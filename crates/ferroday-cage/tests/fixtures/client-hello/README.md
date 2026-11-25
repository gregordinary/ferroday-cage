# ClientHello fixtures

The first bytes six TLS clients sent, committed so the network stack's reader
of a TCP flow's first bytes is tested against what clients actually send
rather than against bytes this crate wrote.

Each was captured on 2026-11-18 by a listener on `127.0.0.1`, which recorded
everything a client sent until it fell silent, with the client connecting to
the server name `example.com`. Each file is one ClientHello in one TLS record.

| File | Client | Bytes | Key shares |
| --- | --- | --- | --- |
| `git-2.43-gnutls-3.8.bin` | git 2.43.0, GnuTLS 3.8.3 | 396 | P-256, X25519 |
| `curl-8.5-openssl-3.0.bin` | curl 8.5.0, OpenSSL 3.0.13 | 517 | X25519 |
| `python-3.12-openssl-3.0.bin` | Python 3.12, OpenSSL 3.0.13 | 517 | X25519 |
| `go-1.27.bin` | Go 1.27 `crypto/tls` | 1,515 | X25519MLKEM768, X25519 |
| `openssl-3.6.4.bin` | `openssl s_client` 3.6.4 | 1,542 | X25519MLKEM768, X25519 |
| `node-24.18.bin` | Node 24.18 | 1,588 | X25519MLKEM768, X25519 |

The last three are longer than the 1,460 bytes of one segment under the stack's
default MTU, so a guest sends each in two. The tests split them there.
