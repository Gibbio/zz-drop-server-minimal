# Local end-to-end test

Two ways to exercise `zz-drop-server-minimal` against the rest of the
project on one machine.

| What | Command | What it covers |
|---|---|---|
| Automated smoke | `./scripts/smoke.sh` | full happy-path of `/api/v1/...` (register → login → list → create → put_blob → get_blob → version_conflict → delete) |
| Manual TUI flow | walkthrough below | `zz-tui` push sub-flow against the local server, including TOTP if you enable it |

## 1. Automated smoke

```bash
# from this repo's root
./scripts/smoke.sh
```

The script:

1. builds `zz-drop-server-minimal` (cached after the first run)
2. spawns it on `127.0.0.1:18080` with an in-memory SQLite and a
   random TOTP master key
3. walks through 9 checks; each prints `✓` on success or `✗ …` on
   failure
4. kills the server and removes the temp workspace on exit

To hit a server you already have running (e.g. on `:8080`):

```bash
./scripts/smoke.sh http://127.0.0.1:8080
```

The script never persists state. Use it as a regression check for the
HTTP surface; for stateful debugging, follow the TUI walkthrough
below with the **persistent** server config.

## 2. Manual TUI walkthrough

End-to-end verification of the TUI's push sub-flow against a local
server. Three terminal windows.

### Configure your local-test secrets once

Put your local-only credentials in `local-test.env` at the repo root.
This file is **gitignored** — your real email and TOTP master key
never end up in source control:

```bash
cd zz-drop-server-minimal

# write the file once
cat > local-test.env <<'EOF'
TEST_EMAIL=tester@local.test
TEST_PASSWORD=1234567890abcdef
ZZDROP_TOTP_KEY=__GENERATED_BELOW__
EOF

# fill ZZDROP_TOTP_KEY with a fresh 32-byte base64 value
sed -i.bak "s|__GENERATED_BELOW__|$(head -c 32 /dev/urandom | base64)|" \
    local-test.env && rm -f local-test.env.bak
```

Replace `tester@local.test` with whatever email you want for personal
testing — `local-test.env` is yours and won't be committed. The
example above keeps a non-routable `local.test` placeholder so a
clean clone of the repo still works without editing.

The chosen password (`1234567890abcdef`) is exactly 16 characters,
which is the server's `MIN_PASSWORD_LEN`. Anything shorter is
rejected by `POST /auth/register` with HTTP 400.

### Terminal A — server with persistent state

```bash
cd zz-drop-server-minimal

# build it once
cargo build --bin zz-drop-server-minimal

# load local-test.env, then run with persistent SQLite
set -a && source ./local-test.env && set +a

ZZDROP_BIND=127.0.0.1:8080 \
DATABASE_URL=sqlite:./local-test.db \
RUST_LOG=zz_drop_server_minimal=info,tower_http=info \
    ./target/debug/zz-drop-server-minimal
```

The server prints a stderr banner reminding you it is not
production-ready, then logs `INFO listening bind=127.0.0.1:8080`.
Leave it running.

To start over from scratch:

```bash
rm -f local-test.db local-test.db-journal
# keep local-test.env unless you want a fresh TOTP master key
```

### Terminal B — pre-register your test account

The TUI push sub-flow logs in but does **not** register. Create the
account once via the API:

```bash
set -a && source ./local-test.env && set +a

curl -sS -X POST http://127.0.0.1:8080/api/v1/auth/register \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}" \
    -w 'HTTP %{http_code}\n'
# → HTTP 201
```

You can re-use these credentials across `zz-tui` invocations as long
as `local-test.db` survives.

### Terminal C — run zz-tui pointing at the local server

```bash
cd zz-drop-tui
cargo build --bin zz-tui

ZZDROP_API_BASE=http://127.0.0.1:8080 \
    ./target/debug/zz-tui
```

Walk the wizard:

1. **Welcome** → `Configure new profile` (Enter)
2. **Provider** → Nextcloud (Enter)
3. **Nextcloud server** → URL of any test Nextcloud (e.g. a Docker
   instance on `http://localhost:8081`); Enter
4. **Auth** → app password or Login Flow; complete
5. **Folder** → e.g. `/zz-drop-test` (Enter)
6. **Collision** → leave on Rename (Enter)
7. **Probe** → press Enter to run; it tries PROPFIND/MKCOL/PUT
   against the cloud you configured. Skip / reconfigure if your
   Nextcloud isn't ready.
8. **Profile passphrase** → type something with 16+ characters,
   confirm, Enter (or `y` past the weak warning)
9. **Done** → ✓ profile saved at `~/.config/zz-drop/profile.zz`
   (or your platform's equivalent)

Now press **`p`** on the Done screen:

10. **Account login** → email + password from terminal B (Tab to
    switch fields, Enter to send)
11. If TOTP is enabled on the account → **Two-factor** screen;
    enter the 6-digit code or one of the recovery codes
12. **Push profile** → `↑↓` to pick an existing alias if any, or
    type a new one (e.g. `local-test`); Enter
13. ✓ green `pushed to zz-drop.net` (the message text doesn't change
    when you point at a local server) with `alias / size / ver`

### Verify from terminal B

```bash
# Login again to grab a token
TOKEN=$(curl -sS -X POST http://127.0.0.1:8080/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

# List your aliases
curl -sS -H "Authorization: Bearer $TOKEN" \
    http://127.0.0.1:8080/api/v1/profiles | python3 -m json.tool
# → {"profiles":[{"alias":"local-test","blob_size":N,"blob_version":1, …}]}

# Pull the encrypted blob and check size matches the local profile.zz
curl -sS -H "Authorization: Bearer $TOKEN" \
    -o /tmp/local-test.zz \
    http://127.0.0.1:8080/api/v1/profiles/local-test/blob
ls -l /tmp/local-test.zz   # should match `wc -c` of your local profile.zz
```

To verify the round-trip is perfect, compare bytes:

```bash
diff -q /tmp/local-test.zz "$HOME/.config/zz-drop/profile.zz"
# (no output → identical)
```

That last check is the "the server stored it as opaque ciphertext"
guarantee made concrete: bytes in, bytes out.

### Optional — TOTP path

To exercise the two-step login on the same account:

```bash
# Enroll TOTP (terminal B — uses the token from above)
curl -sS -X POST http://127.0.0.1:8080/api/v1/auth/totp/enroll \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d '{}' | python3 -m json.tool
# → JSON with otpauth_uri, secret_base32, recovery_codes[]
```

Scan the QR (`otpauth_uri`) into an authenticator app, then verify
to activate:

```bash
CODE=123456   # whatever the app shows
curl -sS -X POST http://127.0.0.1:8080/api/v1/auth/totp/verify \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"code\":\"$CODE\"}" -w 'HTTP %{http_code}\n'
# → HTTP 204
```

Now log in from `zz-tui` again — pressing Enter on the Account
screen returns a `totp_required` and the TUI advances to the
**Two-factor** screen automatically.

## Cleanup

When you're done:

```bash
# stop the server (Ctrl-C in terminal A) and clean its state
rm -f zz-drop-server-minimal/local-test.{db,env}

# (optional) wipe the local zz-drop config dir
rm -rf "$HOME/.config/zz-drop"
```

## Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| smoke aborts with "server did not bind" | another process on `:18080`. Set `PORT=19090 ./scripts/smoke.sh` or stop the conflict. |
| `zz-tui` push fails with `network error` | server not running, or `ZZDROP_API_BASE` points elsewhere. Confirm with `curl http://127.0.0.1:8080/api/v1/info`. |
| `zz-tui` push fails with `wrong credentials` | account not registered on this DB instance. Re-run terminal B's `register` curl. |
| Probe step fails | the TUI probe hits your cloud provider, not this server. Reconfigure provider URL/auth or skip. |
| TOTP enrollments disappeared after server restart | `ZZDROP_TOTP_KEY` was unset → server generated a fresh in-memory key. Always source `local-test.env` before launching. |
