"""shared SP00KY protocol and ecdsa helpers.

used by the fixture generator, the organizer solver, and the tests.
"""

import hashlib
import socket

from ecdsa import NIST256p, SigningKey
from ecdsa.util import sigencode_string

N = NIST256p.order
G = NIST256p.generator

OP_HELLO = 0x01
OP_AUTH_START = 0x02
OP_AUTH_CHALLENGE = 0x03
OP_AUTH_PROVE = 0x04
OP_AUTH_RESULT = 0x05
OP_EXEC = 0x06
OP_EXEC_RESULT = 0x07
OP_ERROR = 0x08
OP_LOGOUT = 0x09

AUTH_FAIL = 0x00
AUTH_OK = 0x01

EXEC_OK = 0x00
EXEC_ERR = 0x01
EXEC_DENIED = 0x02
EXEC_CONT = 0x03

ERR_MALFORMED = 0x01
ERR_INVALID = 0x02
ERR_UNAUTH = 0x03
ERR_INTERNAL = 0x04

MAX_PAYLOAD = 1024
VERSION = 0x01


class ProtocolError(Exception):
    def __init__(self, message, opcode=None, payload=b""):
        super().__init__(message)
        self.opcode = opcode
        self.payload = payload


class AuthError(ProtocolError):
    pass


def auth_message(username, challenge):
    user = username.encode("ascii")
    if not 1 <= len(user) <= 255:
        raise ValueError("username length")
    if len(challenge) != 32:
        raise ValueError("challenge length")
    return b"SP00KY-AUTH-v1" + bytes([len(user)]) + user + challenge


def log_message(timestamp_ms, username, event_bytes):
    user = username.encode("ascii")
    if not 1 <= len(user) <= 255:
        raise ValueError("username length")
    if len(event_bytes) > 65535:
        raise ValueError("event length")
    return (
        b"SP00KY-LOG-v1"
        + int(timestamp_ms).to_bytes(8, "big")
        + bytes([len(user)])
        + user
        + len(event_bytes).to_bytes(2, "big")
        + event_bytes
    )


def hash_int(message):
    digest = hashlib.sha256(message).digest()
    return int.from_bytes(digest, "big") % N


def sign_with_nonce(private_d, message, nonce):
    """ecdsa p-256 signature with an explicit nonce. s is not normalized."""
    z = hash_int(message)
    k = int(nonce) % N
    if k == 0:
        raise ValueError("nonce is zero")
    point = k * G
    r = int(point.x()) % N
    if r == 0:
        raise ValueError("signature r is zero")
    s = (pow(k, -1, N) * (z + r * int(private_d))) % N
    if s == 0:
        raise ValueError("signature s is zero")
    return r, s, z


def recover_private(z1, s1, z2, s2, r):
    """recover d from two ecdsa signatures that reused one nonce.

    s = k^-1 (z + r*d) mod n
    k = (z1 - z2) * inverse(s1 - s2) mod n
    d = (s1*k - z1) * inverse(r) mod n
    """
    r = int(r) % N
    s1 = int(s1) % N
    s2 = int(s2) % N
    z1 = int(z1) % N
    z2 = int(z2) % N
    if r == 0 or s1 == s2:
        raise ValueError("unusable signature pair")
    k = ((z1 - z2) % N) * pow((s1 - s2) % N, -1, N) % N
    if k == 0:
        raise ValueError("recovered nonce is zero")
    d = ((s1 * k - z1) % N) * pow(r, -1, N) % N
    if d == 0:
        raise ValueError("recovered key is zero")
    return k, d


def pubkey_uncompressed(private_d):
    point = int(private_d) * G
    return (
        b"\x04"
        + int(point.x()).to_bytes(32, "big")
        + int(point.y()).to_bytes(32, "big")
    )


def parse_auth_log(text):
    rows = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = {}
        for part in line.split():
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            fields[key] = value
        needed = {"timestamp_ms", "username", "event_hex", "public_key", "r", "s"}
        if needed <= fields.keys():
            rows.append(fields)
    return rows


def find_reused_nonce(rows):
    groups = {}
    for row in rows:
        groups.setdefault((row["public_key"].lower(), row["r"].lower()), []).append(row)
    hits = [group for group in groups.values() if len(group) >= 2]
    if len(hits) != 1:
        raise ValueError(f"expected one repeated nonce, found {len(hits)}")
    if len(hits[0]) != 2:
        raise ValueError("repeated nonce group does not contain exactly two signatures")
    return hits[0]


def recover_from_rows(pair):
    def z_of(row):
        message = log_message(
            int(row["timestamp_ms"]),
            row["username"],
            bytes.fromhex(row["event_hex"]),
        )
        return hash_int(message)

    z1 = z_of(pair[0])
    z2 = z_of(pair[1])
    s1 = int(pair[0]["s"], 16)
    s2 = int(pair[1]["s"], 16)
    r = int(pair[0]["r"], 16)
    _k, d = recover_private(z1, s1, z2, s2, r)
    return d


def pem_signer(path):
    with open(path, "rb") as handle:
        key = SigningKey.from_pem(handle.read())

    def signer(username, challenge):
        message = auth_message(username, challenge)
        return key.sign(message, hashfunc=hashlib.sha256, sigencode=sigencode_string)

    return signer


def key_signer(private_d):
    key = SigningKey.from_secret_exponent(int(private_d), curve=NIST256p, hashfunc=hashlib.sha256)

    def signer(username, challenge):
        message = auth_message(username, challenge)
        return key.sign(message, hashfunc=hashlib.sha256, sigencode=sigencode_string)

    return signer


def write_msg(sock, opcode, payload=b""):
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    header = bytes([VERSION, opcode]) + len(payload).to_bytes(2, "big")
    sock.sendall(header + payload)


def recvall(sock, size):
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf


def read_msg(sock):
    header = recvall(sock, 4)
    version = header[0]
    opcode = header[1]
    length = int.from_bytes(header[2:4], "big")
    if version != VERSION:
        raise ProtocolError(f"unsupported version {version}", opcode)
    if length > MAX_PAYLOAD:
        raise ProtocolError(f"payload too large ({length})", opcode)
    payload = recvall(sock, length) if length else b""
    return opcode, payload


class Client:
    def __init__(self, host, port, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def hello(self):
        write_msg(self.sock, OP_HELLO, b"")
        opcode, payload = read_msg(self.sock)
        if opcode != OP_HELLO:
            raise ProtocolError("expected HELLO", opcode, payload)
        return payload

    def auth_start(self, username):
        user = username.encode("ascii")
        write_msg(self.sock, OP_AUTH_START, bytes([len(user)]) + user)
        return read_msg(self.sock)

    def auth_prove(self, signature):
        if len(signature) != 64:
            raise ValueError("signature must be 64 bytes")
        write_msg(self.sock, OP_AUTH_PROVE, signature)
        return read_msg(self.sock)

    def login(self, username, signer):
        banner = self.hello()
        opcode, payload = self.auth_start(username)
        if opcode != OP_AUTH_CHALLENGE or len(payload) != 32:
            raise AuthError("expected challenge", opcode, payload)
        signature = signer(username, payload)
        opcode, payload = self.auth_prove(signature)
        if opcode != OP_AUTH_RESULT or payload != bytes([AUTH_OK]):
            raise AuthError("authentication failed", opcode, payload)
        return banner

    def exec(self, command):
        data = command.encode("utf-8")
        if len(data) > 256:
            raise ValueError("command too long")
        write_msg(self.sock, OP_EXEC, data)
        chunks = []
        status = None
        while True:
            opcode, payload = read_msg(self.sock)
            if opcode == OP_ERROR:
                raise ProtocolError("server error during exec", opcode, payload)
            if opcode != OP_EXEC_RESULT or len(payload) < 1:
                raise ProtocolError("expected EXEC_RESULT", opcode, payload)
            status = payload[0]
            chunks.append(payload[1:])
            if status != EXEC_CONT:
                return status, b"".join(chunks)

    def logout(self):
        write_msg(self.sock, OP_LOGOUT, b"")
