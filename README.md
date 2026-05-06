# zz-drop-server-minimal

Minimal reference implementation of the zz-drop API v1.

This is **not** the production server used by `zz-drop.net`.

It is intended for:

- local development
- testing
- self-hosting experiments
- API compatibility validation

## Status

Pre-alpha reference implementation. `/api/v1/info` answers,
SQLite via sqlx-migrate is wired, the binary serves over TCP.
Auth endpoints (`/auth/register`, `/auth/login`, two-step
TOTP login + enroll/verify/disable) and profile endpoints
(`/profiles`, `/profiles/{alias}/blob`) are implemented; see
the endpoint list below for the current surface.

## Quickstart

```bash
# default: bind 127.0.0.1:8080, in-memory SQLite
cargo run

# pick a port and a persistent SQLite file
ZZDROP_BIND=127.0.0.1:9000 \
DATABASE_URL=sqlite:./state.db \
    cargo run

# hit the discovery endpoint
curl http://127.0.0.1:8080/api/v1/info
# → {"api_version":"1","implementation":"zz-drop-server-minimal v…",…}
```

## Local test

For a fast end-to-end check of the full HTTP surface:

```bash
./scripts/smoke.sh
```

The script builds the binary, spawns it on `127.0.0.1:18080` with an
in-memory SQLite, and walks register → login → list → create →
put_blob → get_blob → version_conflict → delete. Each step prints
`✓` on success.

To exercise the **TUI push sub-flow** end-to-end against this
server, follow the walkthrough in
[`docs/local-test.md`](docs/local-test.md).

For a small binary suitable for distribution use the `dist` profile:

```bash
cargo build --profile dist
```

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `ZZDROP_BIND` | `127.0.0.1:8080` | TCP bind address |
| `DATABASE_URL` | `sqlite::memory:` | sqlx connection URL (SQLite only) |
| `ZZDROP_TOTP_KEY` | _(generated in memory)_ | Base64 of 32 random bytes; the key used to encrypt TOTP shared seeds at rest. If unset, generated at startup — TOTP enrollments do not survive a restart and a stderr warning is printed. |
| `ZZDROP_MAX_ALIASES_FREE` | `5` | Maximum profile aliases per Free account. |
| `ZZDROP_BLOB_MAX_BYTES` | `1048576` (1 MiB) | Hard cap on the size of an uploaded encrypted blob (per blob). |
| `RUST_LOG` | `zz_drop_server_minimal=info,tower_http=info` | tracing filter |

The default bind is loopback. Exposing the server to a public network
is an explicit operator decision and pulls in everything in the
"Warning" section below.

## Warning

This project is intentionally minimal.

Do not assume it is production-ready.

If you expose it to the public internet, you are responsible for:

- TLS
- backups
- monitoring
- rate limiting
- abuse handling
- security updates
- database hardening
- legal compliance

Use at your own risk.

## Included (v1 surface, target)

- API v1 compatibility
- account login/register
- profile alias create/list/delete
- encrypted `profile.zz` upload/download
- `expected_version` conflict handling

Currently implemented:

- `GET  /api/v1/info`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login` (two-step when TOTP is on)
- `POST /api/v1/auth/totp/enroll` (requires Bearer token)
- `POST /api/v1/auth/totp/verify` (activates pending enrollment)
- `POST /api/v1/auth/totp/login` (step 2 of two-step login)
- `POST /api/v1/auth/totp/disable` (requires password + code)
- `GET    /api/v1/profiles` (list aliases)
- `POST   /api/v1/profiles` (create alias; quota-checked)
- `GET    /api/v1/profiles/{alias}/blob` (download encrypted blob)
- `PUT    /api/v1/profiles/{alias}/blob?expected_version=N` (atomic upload)
- `DELETE /api/v1/profiles/{alias}` (remove alias + blob)
- `GET    /api/v1/account/email-preferences` (returns the three flags)
- `PUT    /api/v1/account/email-preferences` (partial body; `security_events` is non-disableable at both the API contract and the DB `CHECK` constraint)

The server now covers **14/14 endpoints** of the API v1 contract.
Operationally it is still "minimal reference": no TLS, no edge
rate-limit, no backups, no production guarantees — see `SECURITY.md`.

## Not included

- billing
- Pro plan
- email flows
- polished dashboard
- production hardening
- advanced abuse protection
- operational monitoring
