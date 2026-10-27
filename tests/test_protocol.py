import time

from support import ServerCase

import spookylib


def read_exec(sock):
    chunks = []
    status = None
    while True:
        opcode, payload = spookylib.read_msg(sock)
        if opcode != spookylib.OP_EXEC_RESULT or len(payload) < 1:
            raise AssertionError(f"unexpected message {opcode} {payload!r}")
        status = payload[0]
        chunks.append(payload[1:])
        if status != spookylib.EXEC_CONT:
            return status, b"".join(chunks)


class ProtocolTests(ServerCase):
    def test_hello_banner(self):
        client = self.connect()
        try:
            self.assertEqual(client.hello(), b"SP00KY/1 - Remote Access Service")
        finally:
            client.close()

    def test_zero_length_payload(self):
        client = self.connect()
        try:
            spookylib.write_msg(client.sock, spookylib.OP_HELLO, b"")
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_HELLO)
            self.assertGreater(len(payload), 0)
        finally:
            client.close()

    def test_maximum_payload_is_framed(self):
        client = self.connect()
        try:
            spookylib.write_msg(client.sock, spookylib.OP_HELLO, b"A" * spookylib.MAX_PAYLOAD)
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_ERROR)
            self.assertEqual(payload[0], spookylib.ERR_MALFORMED)
            self.assertNotIn(b"too large", payload)
        finally:
            client.close()

    def test_oversized_payload_rejected(self):
        client = self.connect()
        try:
            header = bytes([spookylib.VERSION, spookylib.OP_HELLO]) + (1025).to_bytes(2, "big")
            client.sock.sendall(header)
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_ERROR)
            self.assertEqual(payload[0], spookylib.ERR_MALFORMED)
            self.assertIn(b"too large", payload)
        finally:
            client.close()

    def test_unknown_version(self):
        client = self.connect()
        try:
            client.sock.sendall(bytes([0x09, spookylib.OP_HELLO, 0, 0]))
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_ERROR)
            self.assertIn(b"version", payload)
        finally:
            client.close()

    def test_unknown_opcode(self):
        client = self.connect()
        try:
            spookylib.write_msg(client.sock, 0x7F, b"")
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_ERROR)
            self.assertEqual(payload[0], spookylib.ERR_INVALID)
        finally:
            client.close()

    def test_partial_header(self):
        client = self.connect()
        try:
            frame = bytes([spookylib.VERSION, spookylib.OP_HELLO, 0, 0])
            client.sock.sendall(frame[:2])
            time.sleep(0.2)
            client.sock.sendall(frame[2:])
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_HELLO)
            self.assertIn(b"SP00KY", payload)
        finally:
            client.close()

    def test_partial_payload(self):
        client = self.connect()
        try:
            client.hello()
            body = bytes([len(b"general")]) + b"general"
            frame = bytes([spookylib.VERSION, spookylib.OP_AUTH_START]) + len(body).to_bytes(2, "big") + body
            client.sock.sendall(frame[:6])
            time.sleep(0.2)
            client.sock.sendall(frame[6:])
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_AUTH_CHALLENGE)
            self.assertEqual(len(payload), 32)
        finally:
            client.close()

    def test_multiple_packets_in_one_write(self):
        client = self.connect()
        try:
            body = bytes([len(b"general")]) + b"general"
            blob = bytes([spookylib.VERSION, spookylib.OP_HELLO, 0, 0])
            blob += bytes([spookylib.VERSION, spookylib.OP_AUTH_START]) + len(body).to_bytes(2, "big") + body
            client.sock.sendall(blob)
            opcode, _payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_HELLO)
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_AUTH_CHALLENGE)
            self.assertEqual(len(payload), 32)
        finally:
            client.close()

    def test_malformed_auth_start(self):
        client = self.connect()
        try:
            client.hello()
            spookylib.write_msg(client.sock, spookylib.OP_AUTH_START, b"")
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_ERROR)
            self.assertEqual(payload[0], spookylib.ERR_MALFORMED)
        finally:
            client.close()

    def test_unexpected_opcode_during_authentication(self):
        client = self.connect()
        try:
            client.hello()
            opcode, payload = client.auth_start("general")
            self.assertEqual(opcode, spookylib.OP_AUTH_CHALLENGE)
            spookylib.write_msg(client.sock, spookylib.OP_EXEC, b"whoami")
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_ERROR)
            self.assertEqual(payload[0], spookylib.ERR_INVALID)
        finally:
            client.close()

    def test_unauthenticated_exec(self):
        client = self.connect()
        try:
            client.hello()
            spookylib.write_msg(client.sock, spookylib.OP_EXEC, b"whoami")
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_ERROR)
            self.assertEqual(payload[0], spookylib.ERR_UNAUTH)
        finally:
            client.close()

    def test_embedded_nul_is_not_a_host_command(self):
        client = self.login()
        try:
            spookylib.write_msg(client.sock, spookylib.OP_EXEC, b"cat\x00/etc/hostname")
            status, data = read_exec(client.sock)
            self.assertNotEqual(status, spookylib.EXEC_OK)
            self.assertNotIn(b"spooky", data)
        finally:
            client.close()

    def test_large_output_uses_continuation(self):
        client = self.login()
        try:
            spookylib.write_msg(client.sock, spookylib.OP_EXEC, b"cat /var/log/auth.log")
            opcode, payload = spookylib.read_msg(client.sock)
            self.assertEqual(opcode, spookylib.OP_EXEC_RESULT)
            self.assertEqual(payload[0], spookylib.EXEC_CONT)
            status = payload[0]
            chunks = [payload[1:]]
            while status == spookylib.EXEC_CONT:
                _opcode, payload = spookylib.read_msg(client.sock)
                status = payload[0]
                chunks.append(payload[1:])
            data = b"".join(chunks)
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertIn(b"timestamp_ms=", data)
            self.assertGreater(len(data), 1023)
        finally:
            client.close()
