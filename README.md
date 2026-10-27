# no nonsense on this server

simulated remote-access service for a cryptography ctf challenge. client and server speak the small binary SP00KY protocol, sign in with ecdsa p-256, and explore a simulated filesystem.

participant info: [docs/PARTICIPANT.md](docs/PARTICIPANT.md)

organizer info: [docs/ORGANIZER.md](docs/ORGANIZER.md)

SP00KY protocol: [docs/PROTOCOL.md](docs/PROTOCOL.md)

## build

dependencies: gcc, openssl3, python3.

```bash
make
make generate
make test
```

`make generate` generates a development instance under `data/`. admin private key lives in `data/private`.

```bash
./spooky-server --port 19160 --data data/runtime
./spooky-client --host 0.0.0.0 --port 19160 --user general --key data/public/general.pem
```

development flag is `spooky{reused_k_no_nons3nse_89f3ae32316e}`. override it with `SPOOKY_FLAG` or `--flag`.
