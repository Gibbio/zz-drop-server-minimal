# Security policy — zz-drop-server-minimal

> **This is a reference implementation, not a production server.**
> If you expose this binary to the public internet you take on a
> long list of operator responsibilities (TLS, backups, monitoring,
> rate limiting, abuse handling, security updates, database
> hardening, legal compliance) that are explicitly **out of scope**
> for this codebase. See the README's "Warning" section.

## Reporting a vulnerability

Please use **GitHub Security Advisories** (the "Security" tab of
this repository) to file a private vulnerability report. Do not
open public issues, pull requests, or discussion threads for
security problems, and please don't disclose details on social
media or chat platforms before the maintainers have responded.

Acknowledgement target: **7 days**. Fix-or-workaround target for
high-severity issues: **30 days** when the vulnerability touches
the *protocol* (the `/api/v1/...` surface itself); for
deployment-only issues we may close as "out of scope, see README".
Reporters are credited in the release notes unless they ask
otherwise.

## Scope of this server's security claims

What this binary **does** guarantee:

- it stores **only** what the API v1 contract says it stores —
  email, Argon2id-hashed account password, alias, encrypted blob,
  size, version, timestamps; (if 2FA is on) Argon2id-hashed
  recovery codes and an XChaCha20-Poly1305-encrypted-at-rest TOTP
  shared seed
- account passwords are hashed with Argon2id (64 MiB / 3 iter /
  1 lane, ~150 ms target) before storage
- session tokens are 32 random bytes; only the SHA-256 digest is
  stored; the plaintext is returned to the client and never
  written to logs
- the TOTP master key (used to encrypt seeds at rest) is loaded
  from `ZZDROP_TOTP_KEY`; if unset, the server generates a
  random key in memory and prints a stderr warning that
  enrollments will not survive a restart
- TOTP rate-limiting is **ephemeral** (in-memory `HashMap`); no
  IP/user-agent capture
- the wire is plaintext HTTP by default; **TLS termination is
  the operator's responsibility** (e.g. behind a reverse proxy)
- bind defaults to `127.0.0.1:8080` — exposing publicly is an
  explicit operator decision

What this binary **does not** offer:

- a TLS server (no `rustls` listener; bring your own reverse
  proxy)
- backup or replication
- HTTP-level abuse handling (header sniffing, geoip blocks,
  WAF rules)
- application-level metrics or audit log
- production-grade logging policy — `tracing` writes structured
  records to stderr; you choose where they go and for how long
- a stable upgrade path between schema versions (the migrations
  directory is renumbered freely until v1.0)

## Operator responsibilities

If you self-host this server, you are responsible for at least:

- TLS (terminate in front of the binary)
- Backups of the SQLite file and the `ZZDROP_TOTP_KEY` (lose the
  key, lose every TOTP enrollment)
- A reverse proxy that does **not** persist application-level
  IP/user-agent logs associated with profiles, in line with the
  project's privacy stance
- Rate-limiting at the edge (the in-process TOTP rate-limit
  defends against credential stuffing for one specific endpoint;
  it is not a substitute for an edge limiter)
- Patching the OS, the Rust toolchain, and the dependency tree
  (`cargo audit` is the project's reference, run periodically;
  `cargo deny` is suggested for licence + duplicate-version drift
  on top)
- Legal compliance with whatever jurisdiction you operate in

## What the server cannot decrypt

The server stores `profile.zz` blobs as opaque ciphertext. It
**cannot**:

- decrypt the profile
- learn the profile-decrypt passphrase
- learn the cloud provider URL, username, app password, OAuth
  token, or remote folder

That property is enforced upstream: the encryption happens
client-side in `zz-drop-tui` (now `tui/` in the zz-drop monorepo) / `zz-drop` using primitives from
`zz-drop-core` (now `core/` in the zz-drop monorepo). This server is intentionally on the wrong side of
the trust boundary for those secrets.

## Cross-references

- [`README.md`](README.md) — quickstart, configuration, status
- [`https://github.com/zz-drop/zz-drop/blob/main/SECURITY.md`](https://github.com/zz-drop/zz-drop/blob/main/SECURITY.md) —
  project-wide security policy
- [`https://github.com/zz-drop/zz-drop/blob/main/core/docs/security-model.md`](https://github.com/zz-drop/zz-drop/blob/main/core/docs/security-model.md)
  — canonical model: what the server stores / does not store, TOTP
  scope, logging rules, honest non-claims
- [`https://github.com/zz-drop/zz-drop/blob/main/core/docs/api/openapi.yaml`](https://github.com/zz-drop/zz-drop/blob/main/core/docs/api/openapi.yaml)
  — public HTTP API v1 contract
