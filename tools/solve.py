#!/usr/bin/env python3
"""organizer-only end-to-end solver.

recovers the administrator ecdsa key from the remotely readable authentication
log, then authenticates and reads the flag. the private key is not hardcoded.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import spookylib


def main():
    parser = argparse.ArgumentParser(description="Solve a live SP00KY instance")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--key", required=True, help="general user private key PEM")
    parser.add_argument("--expect", required=True, help="expected flag text")
    args = parser.parse_args()

    general = spookylib.Client(args.host, args.port)
    try:
        general.login("general", spookylib.pem_signer(args.key))
        status, data = general.exec("cat /var/log/auth.log")
    finally:
        general.close()

    if status != spookylib.EXEC_OK:
        raise SystemExit(f"failed to read auth log: {data!r}")

    rows = spookylib.parse_auth_log(data.decode("utf-8", "replace"))
    pair = spookylib.find_reused_nonce(rows)
    private_d = spookylib.recover_from_rows(pair)
    expected_pub = bytes.fromhex(pair[0]["public_key"])
    if spookylib.pubkey_uncompressed(private_d) != expected_pub:
        raise SystemExit("recovered key does not match the log public key")

    admin = spookylib.Client(args.host, args.port)
    try:
        admin.login("admin", spookylib.key_signer(private_d))
        status, data = admin.exec("cat /home/admin/flag.txt")
    finally:
        admin.close()

    if status != spookylib.EXEC_OK:
        raise SystemExit(f"failed to read flag: {data!r}")
    flag = data.decode("utf-8", "replace").strip()
    if flag != args.expect.strip():
        raise SystemExit(f"flag mismatch: {flag!r}")
    print(flag)


if __name__ == "__main__":
    main()
