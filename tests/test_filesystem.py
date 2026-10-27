import os

from support import DEV_FLAG, ServerCase

import spookylib


class FilesystemTests(ServerCase):
    def test_general_reads_own_files_and_logs(self):
        client = self.login()
        try:
            status, data = client.exec("cat /home/general/welcome.txt")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertIn(b"SP00KY", data)
            status, data = client.exec("cat /var/log/auth.log")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertIn(b"public_key=", data)
            status, data = client.exec("cat /var/log/syslog")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertIn(b"insufficient entropy", data)
            self.assertIn(b"temporary signing fallback activated", data)
            self.assertIn(b"normal operation restored", data)
        finally:
            client.close()

    def test_general_cannot_read_or_list_admin_home(self):
        client = self.login()
        try:
            status, data = client.exec("cat /home/admin/flag.txt")
            self.assertEqual(status, spookylib.EXEC_DENIED)
            self.assertNotIn(DEV_FLAG.encode(), data)
            status, data = client.exec("ls /home/admin")
            self.assertEqual(status, spookylib.EXEC_DENIED)
            status, data = client.exec("cd /home/admin")
            self.assertEqual(status, spookylib.EXEC_DENIED)
            status, _data = client.exec("pwd")
            self.assertEqual(_data.strip(), b"/home/general")
        finally:
            client.close()

    def test_admin_reads_flag(self):
        from support import ADMIN_KEY

        client = self.login("admin", ADMIN_KEY)
        try:
            status, data = client.exec("cat /home/admin/flag.txt")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertEqual(data.decode().strip(), DEV_FLAG)
            status, data = client.exec("id")
            self.assertIn(b"uid=0(admin)", data)
        finally:
            client.close()

    def test_relative_paths_and_dotdot(self):
        client = self.login()
        try:
            status, _data = client.exec("cd /var")
            self.assertEqual(status, spookylib.EXEC_OK)
            status, data = client.exec("pwd")
            self.assertEqual(data.strip(), b"/var")
            status, data = client.exec("cat log/syslog")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertIn(b"spooky-rng", data)

            status, _data = client.exec("cd /home/general")
            self.assertEqual(status, spookylib.EXEC_OK)
            status, data = client.exec("cat ../../home/admin/flag.txt")
            self.assertEqual(status, spookylib.EXEC_DENIED)
            self.assertNotIn(DEV_FLAG.encode(), data)
            status, data = client.exec("ls ../admin")
            self.assertEqual(status, spookylib.EXEC_DENIED)
            status, data = client.exec("cat ../../etc/motd")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertIn(b"laboratory", data)

            status, _data = client.exec("cd /")
            status, _data = client.exec("cd ..")
            status, data = client.exec("pwd")
            self.assertEqual(data.strip(), b"/")
            status, data = client.exec("ls")
            self.assertEqual(status, spookylib.EXEC_OK)
            for name in (b"etc/", b"home/", b"tmp/", b"var/"):
                self.assertIn(name, data)
        finally:
            client.close()

    def test_long_path_is_rejected(self):
        client = self.login()
        try:
            status, data = client.exec("cat " + ("a/" * 40) + "b")
            self.assertEqual(status, spookylib.EXEC_ERR)
            self.assertNotIn(b"Permission denied", data)
            status, data = client.exec("pwd")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertEqual(data.strip(), b"/home/general")
        finally:
            client.close()

    def test_unknown_commands_stay_inside_the_simulator(self):
        client = self.login()
        try:
            status, data = client.exec("uname")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertIn(b"SP00KY", data)
            self.assertNotIn(os.uname().release.encode(), data)

            status, data = client.exec("cat /etc/passwd")
            self.assertEqual(status, spookylib.EXEC_ERR)
            self.assertNotIn(b"root:x:", data)

            status, data = client.exec("/bin/sh -c id")
            self.assertEqual(status, spookylib.EXEC_ERR)
            self.assertIn(b"command not found", data)

            status, data = client.exec("date")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertIn(b"2026", data)
        finally:
            client.close()

    def test_stat_and_empty_tmp(self):
        client = self.login()
        try:
            status, data = client.exec("stat /home/admin")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertIn(b"0700", data)
            self.assertIn(b"directory", data)
            status, data = client.exec("ls /tmp")
            self.assertEqual(status, spookylib.EXEC_OK)
            self.assertEqual(data, b"")
        finally:
            client.close()
