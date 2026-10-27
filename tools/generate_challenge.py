#!/usr/bin/env python3
"""create a fresh SP00KY instance.

the historical administrator signatures intentionally reuse one ecdsa nonce.
the running server never signs with that nonce. the administrator private key
is written only under data/private.
"""

import argparse
import datetime
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ecdsa import NIST256p, SigningKey

import spookylib

N = spookylib.N
G = spookylib.G


def scalar(rng):
    while True:
        value = rng.randrange(1, N)
        if value != 0:
            return value


def allocate_nonce(rng, used_r):
    while True:
        k = scalar(rng)
        point = k * G
        r = int(point.x()) % N
        if r == 0 or r in used_r:
            continue
        used_r.add(r)
        return k, r


def write_pem(path, private_d, private):
    key = SigningKey.from_secret_exponent(int(private_d), curve=NIST256p)
    data = key.to_pem() if private else key.get_verifying_key().to_pem()
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o600 if private else 0o644)


def unique_ts(ts, used):
    while ts in used:
        ts += 1
    used.add(ts)
    return ts


def signed_line(ts, username, event, public_hex, r, s):
    return (
        f"timestamp_ms={ts} username={username} event_hex={event.hex()} "
        f"public_key={public_hex} r={r:064x} s={s:064x}"
    )


def unsigned_line(ts, username, event, result):
    return (
        f"timestamp_ms={ts} username={username} event_hex={event.hex()} result={result}"
    )


def build_logs(rng, admin_d, general_d, admin_pub, general_pub, boot_ms):
    used_r = set()
    used_ts = set()
    records = []
    keys = {
        "admin": (admin_d, admin_pub),
        "general": (general_d, general_pub),
    }
    ips = [f"10.{a}.{b}.{c}" for a in range(1, 6) for b in (0, 4, 8) for c in (10, 14, 22, 40)]

    def add_signed(ts, username, event):
        private_d, public_hex = keys[username]
        k, _r = allocate_nonce(rng, used_r)
        message = spookylib.log_message(ts, username, event)
        r, s, _z = spookylib.sign_with_nonce(private_d, message, k)
        if r in used_r and r != _r:
            raise RuntimeError("unexpected r collision")
        # allocate_nonce already reserved r. sign_with_nonce must reproduce it.
        if r != _r:
            raise RuntimeError("nonce and signature r diverged")
        records.append(signed_line(ts, username, event, public_hex, r, s))

    def add_unsigned(ts, username, event, result):
        records.append(unsigned_line(ts, username, event, result))

    signed_kinds = (
        "accepted signature for {user} from {ip}",
        "session opened for {user} from {ip}",
        "session closed for {user} from {ip}",
        "shell started for {user} from {ip}",
    )
    unsigned_kinds = (
        ("failed signature for {user} from {ip}", "failure"),
        ("unknown user rejected from {ip}", "rejected"),
        ("challenge expired for {user} from {ip}", "expired"),
        ("disconnect before proof from {ip}", "closed"),
    )

    span_start = boot_ms - 10 * 24 * 60 * 60 * 1000
    span_end = boot_ms + 2 * 24 * 60 * 60 * 1000
    window_end = boot_ms + 180000

    for i in range(230):
        ts = unique_ts(rng.randint(span_start, span_end), used_ts)
        # Keep the two vulnerable timestamps free, and leave a few slots inside
        # the fallback window for ordinary signatures added below.
        username = "admin" if rng.randrange(10) < 3 else "general"
        ip = ips[rng.randrange(len(ips))]
        kind = signed_kinds[i % len(signed_kinds)]
        event = kind.format(user=username, ip=ip).encode("ascii")
        add_signed(ts, username, event)

    for i in range(70):
        ts = unique_ts(rng.randint(span_start, span_end), used_ts)
        username = "admin" if i % 4 == 0 else "general"
        ip = ips[rng.randrange(len(ips))]
        kind, result = unsigned_kinds[i % len(unsigned_kinds)]
        event = kind.format(user=username, ip=ip).encode("ascii")
        add_unsigned(ts, username, event, result)

    for i in range(8):
        ts = unique_ts(boot_ms + 4000 + i * 8000, used_ts)
        username = "admin" if i % 2 == 0 else "general"
        event = f"audit checkpoint {i} for {username} during boot".encode("ascii")
        add_signed(ts, username, event)
    for i in range(12):
        ts = unique_ts(boot_ms + 30000 + i * 5000, used_ts)
        username = "general" if i % 3 else "admin"
        ip = ips[i % len(ips)]
        if i % 2 == 0:
            event = f"session note {i} for {username} from {ip}".encode("ascii")
            add_signed(ts, username, event)
        else:
            event = f"failed signature for {username} from {ip}".encode("ascii")
            add_unsigned(ts, username, event, "failure")

    vuln_k, vuln_r = allocate_nonce(rng, used_r)
    vuln_events = (
        (boot_ms + 27000, b"accepted signature for admin from 10.7.0.14"),
        (boot_ms + 96000, b"session opened for admin from 10.7.0.14"),
    )
    vuln_meta = []
    for ts, event in vuln_events:
        ts = unique_ts(ts, used_ts)
        if not (boot_ms < ts < window_end):
            raise RuntimeError("vulnerable signature fell outside the fallback window")
        message = spookylib.log_message(ts, "admin", event)
        r, s, z = spookylib.sign_with_nonce(admin_d, message, vuln_k)
        if r != vuln_r:
            raise RuntimeError("vulnerable r mismatch")
        records.append(signed_line(ts, "admin", event, admin_pub, r, s))
        vuln_meta.append({"timestamp_ms": ts, "r": f"{r:064x}", "s": f"{s:064x}", "z": f"{z:064x}"})

    records.sort(key=lambda line: int(line.split()[0].split("=", 1)[1]))

    rows = spookylib.parse_auth_log("\n".join(records))
    pair = spookylib.find_reused_nonce(rows)
    recovered = spookylib.recover_from_rows(pair)
    if recovered != admin_d:
        raise RuntimeError("nonce reuse did not recover the administrator key")
    if spookylib.pubkey_uncompressed(recovered).hex() != admin_pub:
        raise RuntimeError("recovered key does not match the administrator public key")
    if pair[0]["event_hex"] == pair[1]["event_hex"]:
        raise RuntimeError("vulnerable messages are identical")
    if abs(int(pair[0]["timestamp_ms"]) - int(pair[1]["timestamp_ms"])) < 10000:
        raise RuntimeError("vulnerable signatures are too close together")

    vuln_times = {item["timestamp_ms"] for item in vuln_meta}
    indexes = [i for i, line in enumerate(records) if int(line.split()[0].split("=", 1)[1]) in vuln_times]
    if len(indexes) != 2 or abs(indexes[0] - indexes[1]) < 5:
        raise RuntimeError("vulnerable log lines are adjacent")

    header = [
        "# SP00KY authentication log",
        "# Signed audit records use the canonical SP00KY-LOG-v1 message.",
        f"# account username=general uid=1000 public_key={general_pub}",
        f"# account username=admin uid=0 public_key={admin_pub}",
    ]
    auth_log = "\n".join(header + records) + "\n"

    syslog = build_syslog(rng, boot_ms, window_end)
    return auth_log, syslog, vuln_meta


def iso(ms):
    moment = datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(ms) % 1000:03d}Z"


def build_syslog(rng, boot_ms, window_end):
    lines = []
    noise = [
        "spooky-auth[220]: listening on port 19160",
        "spooky-fs[88]: mounted virtual root",
        "cron[301]: session housekeeping complete",
        "spooky-net[18]: link up eth0",
        "ntpd[77]: clock synchronized",
        "spooky-auth[220]: rotated challenge cache",
        "spooky-fs[88]: log partition within quota",
    ]
    start = boot_ms - 3 * 24 * 60 * 60 * 1000
    for i in range(50):
        ts = start + i * 90 * 60 * 1000 + rng.randint(0, 20000)
        lines.append((ts, f"{iso(ts)} spooky {noise[i % len(noise)]}"))

    clues = [
        (boot_ms, "kernel: spooky-rng: insufficient entropy during initialization"),
        (boot_ms + 1000, "spooky-auth[220]: temporary signing fallback activated"),
        (window_end, "kernel: spooky-rng: normal operation restored"),
        (window_end + 500, "spooky-auth[220]: temporary signing fallback deactivated"),
    ]
    for ts, text in clues:
        lines.append((ts, f"{iso(ts)} spooky {text}"))

    lines.sort(key=lambda item: item[0])
    return "\n".join(item[1] for item in lines) + "\n"


MOTD = """\
SP00KY remote access
Unauthorized use is prohibited.
This system is provided for laboratory account holders.
"""

CONF = """\
# SP00KY service configuration
protocol = SP00KY/1
port = 19160
auth.algorithm = ecdsa-p256-sha256
auth.message = SP00KY-AUTH-v1
log.auth = /var/log/auth.log
log.system = /var/log/syslog
"""

WELCOME = """\
Welcome to the SP00KY remote access service.

This account can inspect shared system files. Authentication history is kept
under /var/log. The administrator home directory is not readable from here.
"""

GENERAL_NOTES = """\
Lab notes, general account

The remote service authenticates with ECDSA P-256 challenge-response signatures.
Each account has its own key. Session and signature audit records are appended
to the authentication log, including the fields needed to rebuild a signed record.

The administrator still has a home directory on this host. The matching private
key was never checked into the general account.
"""

ADMIN_NOTES = """\
Lab notes, administrator

12 Jan 2024 boot was noisy. The authentication log still contains the signed
audit records from that morning. Account keys were not rotated afterward.
"""

FLAG_PLACEHOLDER = "This file is replaced from SPOOKY_FLAG when the server starts.\n"


def filesystem(auth_log, syslog):
    return [
        ("D", 0o755, 0, "/", None),
        ("D", 0o755, 0, "/etc", None),
        ("F", 0o644, 0, "/etc/motd", MOTD.encode()),
        ("F", 0o644, 0, "/etc/hostname", b"spooky\n"),
        ("F", 0o644, 0, "/etc/spooky.conf", CONF.encode()),
        ("D", 0o755, 0, "/home", None),
        ("D", 0o755, 1000, "/home/general", None),
        ("F", 0o644, 1000, "/home/general/welcome.txt", WELCOME.encode()),
        ("F", 0o644, 1000, "/home/general/notes.txt", GENERAL_NOTES.encode()),
        ("D", 0o700, 0, "/home/admin", None),
        ("F", 0o600, 0, "/home/admin/notes.txt", ADMIN_NOTES.encode()),
        ("F", 0o600, 0, "/home/admin/flag.txt", FLAG_PLACEHOLDER.encode()),
        ("D", 0o755, 0, "/var", None),
        ("D", 0o755, 0, "/var/log", None),
        ("F", 0o644, 0, "/var/log/auth.log", auth_log.encode()),
        ("F", 0o644, 0, "/var/log/syslog", syslog.encode()),
        ("D", 0o755, 0, "/tmp", None),
    ]


def main():
    parser = argparse.ArgumentParser(description="Generate a SP00KY challenge instance")
    parser.add_argument("--out", default="data", help="output directory")
    parser.add_argument("--flag", default="spooky{reused_k_no_nons3nse_89f3ae32316e}")
    parser.add_argument("--seed", type=int, default=None, help="deterministic development seed")
    args = parser.parse_args()

    rng = random.Random(args.seed) if args.seed is not None else random.SystemRandom()
    admin_d = scalar(rng)
    general_d = scalar(rng)
    if admin_d == general_d:
        raise SystemExit("key collision")

    admin_pub = spookylib.pubkey_uncompressed(admin_d).hex()
    general_pub = spookylib.pubkey_uncompressed(general_d).hex()

    boot_ms = int(
        datetime.datetime(2024, 1, 12, 3, 14, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000
    )
    auth_log, syslog, vuln_meta = build_logs(rng, admin_d, general_d, admin_pub, general_pub, boot_ms)

    out = os.path.abspath(args.out)
    public = os.path.join(out, "public")
    runtime = os.path.join(out, "runtime")
    private = os.path.join(out, "private")
    root = os.path.join(runtime, "root")
    for directory in (public, runtime, private, root):
        os.makedirs(directory, exist_ok=True)

    write_pem(os.path.join(public, "general.pem"), general_d, private=True)
    write_pem(os.path.join(private, "admin.pem"), admin_d, private=True)
    write_pem(os.path.join(runtime, "general.pub.pem"), general_d, private=False)
    write_pem(os.path.join(runtime, "admin.pub.pem"), admin_d, private=False)

    manifest = []
    for kind, mode, uid, path, data in filesystem(auth_log, syslog):
        manifest.append(f"{kind} {mode:04o} {uid} {path}")
        if kind == "F":
            host_path = os.path.join(root, path.lstrip("/"))
            os.makedirs(os.path.dirname(host_path), exist_ok=True)
            with open(host_path, "wb") as handle:
                handle.write(data)

    with open(os.path.join(runtime, "manifest.txt"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(manifest) + "\n")
    with open(os.path.join(runtime, "users.txt"), "w", encoding="utf-8") as handle:
        handle.write("general 1000 /home/general general.pub.pem\n")
        handle.write("admin 0 /home/admin admin.pub.pem\n")

    with open(os.path.join(public, "README.txt"), "w", encoding="utf-8") as handle:
        handle.write(
            "general.pem is the ordinary account key for the SP00KY service.\n"
            "Use it with spooky-client --user general.\n"
        )
    with open(os.path.join(private, "README.txt"), "w", encoding="utf-8") as handle:
        handle.write(
            "Organizer only. Do not copy this directory into participant files\n"
            "or the runtime container.\n"
        )
    with open(os.path.join(private, "flag.txt"), "w", encoding="utf-8") as handle:
        handle.write(args.flag + "\n")
    instance = {
        "seed": args.seed,
        "admin_public_key": admin_pub,
        "general_public_key": general_pub,
        "vulnerable": vuln_meta,
        "recovery_verified": True,
    }
    with open(os.path.join(private, "instance.json"), "w", encoding="utf-8") as handle:
        json.dump(instance, handle, indent=2)
        handle.write("\n")

    # The runtime tree must not contain a private key.
    for dirpath, _dirnames, filenames in os.walk(runtime):
        for name in filenames:
            path = os.path.join(dirpath, name)
            with open(path, "rb") as handle:
                blob = handle.read()
            if b"PRIVATE" in blob:
                raise SystemExit(f"private material leaked into runtime: {path}")

    print(f"wrote instance under {out}")
    print(f"auth log lines: {auth_log.count(chr(10))}")
    print("administrator key recovery: verified")
    print(f"vulnerable timestamps: {vuln_meta[0]['timestamp_ms']} {vuln_meta[1]['timestamp_ms']}")


if __name__ == "__main__":
    main()
