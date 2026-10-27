# SP00KY protocol

SP00KY is a binary tcp protocol. a reference client is given as `spooky-client`.

default port: `19160`.

# framing

every message has a 4-byte header followed by a payload.

| offset | size | field |
|---:|---:|---|
| 0 | 1 | protocol version |
| 1 | 1 | opcode |
| 2 | 2 | payload length |
| 4 | n | payload |

protocol version: `0x01`.

maximum payload size: 1024 bytes.

payloads are binary and may contain zero bytes.

multi-byte integers are big-endian.

## Opcodes

| opcode | name | direction |
|---|---|---|
| `0x01` | HELLO | client to server, and the server reply |
| `0x02` | AUTH_START | client to server |
| `0x03` | AUTH_CHALLENGE | server to client |
| `0x04` | AUTH_PROVE | client to server |
| `0x05` | AUTH_RESULT | server to client |
| `0x06` | EXEC | client to server |
| `0x07` | EXEC_RESULT | server to client |
| `0x08` | ERROR | server to client |
| `0x09` | LOGOUT | client to server |

# HELLO

client payload: empty.

server payload: `SP00KY/1 - Remote Access Service`.

# AUTH_START

payload:

- 1 byte username length
- username bytes

server replies with AUTH_CHALLENGE. the challenge is 32 bytes from a cryptographic rng and is single-use.

# AUTH_PROVE

payload: 64 bytes

- bytes 0 through 31: ecdsa `r`, unsigned big-endian
- bytes 32 through 63: ecdsa `s`, unsigned big-endian

sign this message with ecdsa over nist p-256 and sha-256:

```text
ASCII("SP00KY-AUTH-v1")
|| uint8(username_length)
|| ASCII(username)
|| challenge[32]
```

the server checks the signature against that user's registered public key.

# AUTH_RESULT

payload: 1 byte.

- `0x00` failed
- `0x01` succeeded

# EXEC

payload: utf-8 command bytes. maximum command length is 256 bytes.

# EXEC_RESULT

payload:

- 1 byte status
- command output

status codes:

- `0x00` success
- `0x01` command error
- `0x02` permission denied
- `0x03` continuation

# ERROR

payload:

- 1 byte error code
- the remaining bytes are a utf-8 description

Error codes:

- `0x01` malformed packet
- `0x02` invalid operation
- `0x03` unauthenticated
- `0x04` internal failure

# LOGOUT

empty payload. the server closes the connection.

# authentication log records

`/var/log/auth.log` contains historical audit lines. lines that include `r` and `s` are ecdsa signatures over a canonical record:

```text
ASCII("SP00KY-LOG-v1")
|| uint64(timestamp_ms, big-endian)
|| uint8(username_length)
|| ASCII(username)
|| uint16(event_length, big-endian)
|| event_bytes
```
