import hashlib
import os
import subprocess
import sys

from ecdsa import SigningKey

from support import ADMIN_KEY, DEV_FLAG, GENERAL_KEY, ROOT, RUNTIME, ServerCase

import spookylib


def canonical_log_message(timestamp_ms, username, event):
    user = username.encode("ascii")
    return (
        b"SP00KY-LOG-v1"
        + int(timestamp_ms).to_bytes(8, "big")
        + bytes([len(user)])
        + user
        + len(event).to_bytes(2, "big")
        + event
    )


class SolutionTests(ServerCase):
    def test_runtime_has_no_private_keys(self):
        for dirpath, _dirnames, filenames in os.walk(RUNTIME):
            for name in filenames:
                path = os.path.join(dirpath, name)
                with open(path, "rb") as handle:
                    blob = handle.read()
                self.assertNotIn(b"PRIVATE", blob, path)

    def test_solver_source_does_not_embed_the_admin_key(self):
        with open(os.path.join(ROOT, "tools", "solve.py"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn("admin.pem", text)
        self.assertNotIn("instance.json", text)
        self.assertNotIn("spooky{", text)

    def test_repeated_nonce_recovers_admin_key(self):
        with open(os.path.join(RUNTIME, "root", "var", "log", "auth.log"), encoding="utf-8") as handle:
            rows = spookylib.parse_auth_log(handle.read())
        pair = spookylib.find_reused_nonce(rows)
        self.assertEqual(pair[0]["r"].lower(), pair[1]["r"].lower())
        self.assertNotEqual(pair[0]["s"].lower(), pair[1]["s"].lower())
        self.assertNotEqual(pair[0]["event_hex"], pair[1]["event_hex"])
        self.assertEqual(pair[0]["public_key"].lower(), pair[1]["public_key"].lower())

        for row in pair:
            event = bytes.fromhex(row["event_hex"])
            message = canonical_log_message(int(row["timestamp_ms"]), row["username"], event)
            library = spookylib.log_message(int(row["timestamp_ms"]), row["username"], event)
            self.assertEqual(message, library)
            self.assertEqual(hashlib.sha256(message).digest(), hashlib.sha256(library).digest())

        private_d = spookylib.recover_from_rows(pair)
        self.assertEqual(
            spookylib.pubkey_uncompressed(private_d),
            bytes.fromhex(pair[0]["public_key"]),
        )
        with open(ADMIN_KEY, "rb") as handle:
            stored = SigningKey.from_pem(handle.read())
        self.assertEqual(int(stored.privkey.secret_multiplier), int(private_d))

    def test_general_cannot_read_flag(self):
        client = self.login()
        try:
            status, data = client.exec("cat /home/admin/flag.txt")
            self.assertEqual(status, spookylib.EXEC_DENIED)
            self.assertNotIn(DEV_FLAG.encode(), data)
        finally:
            client.close()

    def test_solver_reads_flag_from_live_service(self):
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(ROOT, "tools", "solve.py"),
                "--host",
                "127.0.0.1",
                "--port",
                str(self.server.port),
                "--key",
                GENERAL_KEY,
                "--expect",
                DEV_FLAG,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertEqual(proc.stdout.strip(), DEV_FLAG)
