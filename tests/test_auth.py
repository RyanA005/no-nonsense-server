import subprocess

from support import ADMIN_KEY, CLIENT, DEV_FLAG, GENERAL_KEY, ServerCase

import spookylib


class AuthTests(ServerCase):
    def test_general_login(self):
        client = self.login()
        try:
            status, data = client.exec("whoami")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertEqual(data, b"general\n")
        finally:
            client.close()

    def test_incorrect_signature(self):
        client = self.connect()
        try:
            client.hello()
            opcode, challenge = client.auth_start("general")
            self.assertEqual(opcode, spookylib.OP_AUTH_CHALLENGE)
            signature = spookylib.pem_signer(GENERAL_KEY)("general", challenge)
            signature = bytes([signature[0] ^ 0x01]) + signature[1:]
            opcode, payload = client.auth_prove(signature)
            self.assertEqual(opcode, spookylib.OP_AUTH_RESULT)
            self.assertEqual(payload, bytes([spookylib.AUTH_FAIL]))
        finally:
            client.close()

    def test_zero_signature_uses_full_length(self):
        client = self.connect()
        try:
            client.hello()
            client.auth_start("general")
            opcode, payload = client.auth_prove(b"\x00" * 64)
            self.assertEqual(opcode, spookylib.OP_AUTH_RESULT)
            self.assertEqual(payload, bytes([spookylib.AUTH_FAIL]))
        finally:
            client.close()

    def test_unknown_user(self):
        client = self.connect()
        try:
            client.hello()
            opcode, payload = client.auth_start("root")
            self.assertEqual(opcode, spookylib.OP_ERROR)
            self.assertIn(b"unknown user", payload)
        finally:
            client.close()

    def test_replay_and_challenge_reuse(self):
        first = self.connect()
        second = self.connect()
        try:
            first.hello()
            opcode, challenge = first.auth_start("general")
            self.assertEqual(len(challenge), 32)
            signature = spookylib.pem_signer(GENERAL_KEY)("general", challenge)

            second.hello()
            opcode, other = second.auth_start("general")
            self.assertNotEqual(challenge, other)
            opcode, payload = second.auth_prove(signature)
            self.assertEqual(opcode, spookylib.OP_AUTH_RESULT)
            self.assertEqual(payload, bytes([spookylib.AUTH_FAIL]))

            opcode, payload = first.auth_prove(signature)
            self.assertEqual(payload, bytes([spookylib.AUTH_OK]))
            spookylib.write_msg(first.sock, spookylib.OP_AUTH_PROVE, signature)
            opcode, payload = spookylib.read_msg(first.sock)
            self.assertEqual(opcode, spookylib.OP_ERROR)
            self.assertEqual(payload[0], spookylib.ERR_INVALID)
        finally:
            first.close()
            second.close()

    def test_signature_is_bound_to_username(self):
        client = self.connect()
        try:
            client.hello()
            opcode, challenge = client.auth_start("admin")
            self.assertEqual(opcode, spookylib.OP_AUTH_CHALLENGE)
            signature = spookylib.pem_signer(GENERAL_KEY)("admin", challenge)
            opcode, payload = client.auth_prove(signature)
            self.assertEqual(opcode, spookylib.OP_AUTH_RESULT)
            self.assertEqual(payload, bytes([spookylib.AUTH_FAIL]))
        finally:
            client.close()

    def test_fresh_admin_signature(self):
        client = self.login("admin", ADMIN_KEY)
        try:
            status, data = client.exec("cat /home/admin/flag.txt")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertEqual(data.decode().strip(), DEV_FLAG)
        finally:
            client.close()

    def test_challenges_are_fresh(self):
        seen = set()
        for _ in range(4):
            client = self.connect()
            try:
                client.hello()
                _opcode, challenge = client.auth_start("general")
                self.assertEqual(len(challenge), 32)
                seen.add(challenge)
            finally:
                client.close()
        self.assertEqual(len(seen), 4)

    def test_reference_client(self):
        proc = subprocess.run(
            [
                CLIENT,
                "--host",
                "127.0.0.1",
                "--port",
                str(self.server.port),
                "--user",
                "general",
                "--key",
                GENERAL_KEY,
            ],
            input="whoami\ncat /etc/hostname\nexit\n",
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("general", proc.stdout)
        self.assertIn("spooky", proc.stdout)
        self.assertIn("general@spooky:~$", proc.stdout)
