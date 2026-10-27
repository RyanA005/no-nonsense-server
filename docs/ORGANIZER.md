# organizer notes

this challenge is a simulated remote linux server. participants get the `general` key, the protocol spec, and a reference client. the flag is `/home/admin/flag.txt` and is readable only after a normal ecdsa login as `admin`.

the weakness is hidden in the logs, administrator audit records were signed with the same ecdsa nonce. (in reality i generated these intentially this ay with openssl).

# how it works

- `spooky-server` accepts tcp connections and serves the SP00KY binary protocol detailed in `docs/PROTOCOL.md`.
- connections carry an authentication state and working directory. a simple `poll` loop handles up to 32 connections. idle connections close after 180 seconds.
- login uses ecdsa p-256 over sha-256. the server stores public keys.
- a subset of bash shell commands are interpreted manually by the server.
- the virtual filesystem is in memory. the flag string is copied from `--flag` or `SPOOKY_FLAG` into `/home/admin/flag.txt`.

# authentication

```text
ASCII("SP00KY-AUTH-v1") || uint8(username_length) || username || challenge[32]
```

the signature is raw `r || s` (32 byes each = 64 total).

# planted nonce reuse

ecdsa:

```text
s = k^-1 (z + r*d) mod n
```

`k` is the nonce, `z` is the sha-256 of the signed bytes modulo the p-256 order `n`. `r` and `s` are the signature, `d` is the private key.

different messages signed with the same `k` produce the same `r` but different `s`:

```text
k = (z1 - z2) * inverse(s1 - s2, n) mod n
d = (s1*k - z1) * inverse(r, n) mod n
```

`tools/generate_challenge.py` builds both keys, writes 300 authentication records, and signs two different administrator events with one identical nonzero nonce. the generator then runs the recovery above and refuses to emit an instance if `d` does not match the administrator key.

we also leave the following hint in `/var/log/syslog`:

```text
spooky-rng: insufficient entropy during initialization
spooky-auth: temporary signing fallback activated
spooky-rng: normal operation restored
```

the signed historical message is:

```text
ASCII("SP00KY-LOG-v1")
|| uint64(timestamp_ms)
|| uint8(username_length)
|| username
|| uint16(event_length)
|| event_bytes
```

# solution

1. log in as `general`, discover and read `/var/log/auth.log` / `/var/log/syslog`.
2. find the admin signatures that share `r`.
3. rebuild both `SP00KY-LOG-v1` messages and hash them with SHA-256.
4. solve for `d` with the formulas above, check that `d*G` matches logged public key.
5. open a new connection as `admin` with `d`.
6. read `/home/admin/flag.txt`.


# generate instance

development:

```bash
make generate
```

uses seed `20261013` and the placeholder flag `spooky{reused_k_no_nons3nse_89f3ae32316e}`.

a random instance:

```bash
make generate-prod
```

instance with explicit flag:

```bash
.venv/bin/python tools/generate_challenge.py --out data --flag 'spooky{reused_k_no_nons3nse_89f3ae32316e}'
```

outputs:

 - `data/public/general.pem` -> participant general user key
 - `data/runtime/` -> server container with public keys, virtual files
 - `data/private/admin.pem` -> organizers admin user key
 - `data/private/instance.json` ->  vulnerable timestamp record

# run

```bash
make
make generate
SPOOKY_FLAG='spooky{reused_k_no_nons3nse_89f3ae32316e}' ./spooky-server --port 19160 --data data/runtime
./spooky-client --host 127.0.0.1 --port 19160 --user general --key data/public/general.pem
```

validate:

```bash
make test
.venv/bin/python tools/solve.py \
    --host 127.0.0.1 --port 19160 \
    --key data/public/general.pem \
    --expect 'spooky{reused_k_no_nons3nse_89f3ae32316e}'
```

`make test` starts a server and runs the solver. the suite should recover the key from the log and read the flag through an admin session.

participant handout:

```bash
make participant-dist
```

`dist/participant/` contains the client, protocol docs, and `general.pem`.

# deploy

generate the instance first so `data/runtime` exists.

```bash
SPOOKY_FLAG='spooky{reused_k_no_nons3nse_89f3ae32316e}' docker compose -f deploy/compose.yaml up --build
```

this builds server, copies `data/runtime`, and runs as uid 10001. 
the compose file drops all capabilities, sets `no-new-privileges`, uses a read only root filesystem, and limits cpu, memory, and process count.
publish on port 19160.
also update participant docs to disclose the actual server host.

# checks

- `make test` passes.
- `data/runtime` contains no `private` pem.
- the container environment flag is the production flag.
