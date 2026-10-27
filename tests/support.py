import os
import subprocess
import sys
import threading
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import spookylib

GENERAL_KEY = os.path.join(ROOT, "data", "public", "general.pem")
ADMIN_KEY = os.path.join(ROOT, "data", "private", "admin.pem")
RUNTIME = os.path.join(ROOT, "data", "runtime")
SERVER = os.path.join(ROOT, "spooky-server")
CLIENT = os.path.join(ROOT, "spooky-client")
DEV_FLAG = "spooky{reused_k_no_nons3nse_89f3ae32316e}"


class Server:
    def __init__(self, flag=DEV_FLAG):
        env = os.environ.copy()
        env["SPOOKY_FLAG"] = flag
        self.stderr_lines = []
        self.proc = subprocess.Popen(
            [SERVER, "--host", "127.0.0.1", "--port", "0", "--data", RUNTIME],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()
        line = self.proc.stdout.readline()
        if not line.startswith("LISTENING "):
            err = ""
            if self.proc.stderr is not None:
                err = self.proc.stderr.read()
            raise RuntimeError(f"server failed to start: {line!r} {err}")
        self.port = int(line.split()[1])

    def _drain_stderr(self):
        if self.proc.stderr is None:
            return
        for line in self.proc.stderr:
            self.stderr_lines.append(line)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        self._stderr_thread.join(timeout=3)
        if self.proc.stdout is not None:
            self.proc.stdout.close()
        if self.proc.stderr is not None:
            self.proc.stderr.close()
        self.stderr = "".join(self.stderr_lines)


class ServerCase(unittest.TestCase):
    flag = DEV_FLAG

    @classmethod
    def setUpClass(cls):
        cls.server = Server(flag=cls.flag)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def connect(self):
        return spookylib.Client("127.0.0.1", self.server.port)

    def login(self, user="general", key=None):
        path = key if key is not None else GENERAL_KEY
        client = self.connect()
        client.login(user, spookylib.pem_signer(path))
        return client
