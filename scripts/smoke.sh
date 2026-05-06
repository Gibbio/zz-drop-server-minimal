#!/usr/bin/env bash
# Smoke test for `zz-drop-server-minimal`.
#
# Walks the full happy path of the API v1: register → login → list →
# create alias → put_blob → get_blob → version_conflict → delete.
# Each step asserts the HTTP status and prints one line per step.
# Exits 0 if every step passes, 1 otherwise.
#
# Usage:
#
#   ./scripts/smoke.sh                          # auto-spawn server on 127.0.0.1:18080
#   ./scripts/smoke.sh http://localhost:8080    # hit an existing running server
#
# Requires: bash, curl. No `jq`; we grep the JSON.

set -euo pipefail

# ── config ─────────────────────────────────────────────────────────────
PORT=${PORT:-18080}
HOST=${HOST:-127.0.0.1}
BASE=${1:-http://${HOST}:${PORT}}
EXTERNAL_BASE=${1:-}

EMAIL="smoke+$(date +%s)@local.test"
PASSWORD="1234567890abcdef"
ALIAS="smoke-$(date +%s | tail -c 5)"
BLOB_PAYLOAD="opaque-encrypted-blob-from-smoke"

# Workspace + spawned-server PID file.
TMPDIR_=$(mktemp -d -t zz-drop-smoke-XXXXXX)
SERVER_PID=""
trap cleanup EXIT INT TERM

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR_"
}

# ── helpers ────────────────────────────────────────────────────────────
say()   { printf '  %s\n' "$*"; }
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail()  { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }
hr()    { printf '%s\n' '────────────────────────────────────────'; }

assert_status() {
    local expected="$1" got="$2" what="$3"
    if [[ "$got" != "$expected" ]]; then
        fail "$what: expected HTTP $expected, got $got"
        printf 'response body:\n' >&2
        cat "$TMPDIR_/last_body" >&2 || true
        exit 1
    fi
}

curl_status() {
    # POST/GET/PUT/DELETE wrapper. Captures body to $TMPDIR_/last_body
    # and prints just the status code.
    curl -sS -o "$TMPDIR_/last_body" -w '%{http_code}' "$@"
}

wait_tcp() {
    local host="$1" port="$2" deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if (echo > "/dev/tcp/${host}/${port}") 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# ── 1. start (or attach to) server ─────────────────────────────────────

if [[ -z "$EXTERNAL_BASE" ]]; then
    hr
    say "building server (cargo build)"
    cargo build --quiet --bin zz-drop-server-minimal >"$TMPDIR_/build.log" 2>&1 ||
        { cat "$TMPDIR_/build.log" >&2; fail "cargo build failed"; }
    BIN="$(cargo metadata --format-version=1 --no-deps 2>/dev/null \
        | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/debug/zz-drop-server-minimal"
    [[ -x "$BIN" ]] || fail "binary not found at $BIN"

    say "starting server on ${HOST}:${PORT}"
    TOTP_KEY=$(head -c 32 /dev/urandom | base64)
    ZZDROP_BIND="${HOST}:${PORT}" \
    ZZDROP_TOTP_KEY="$TOTP_KEY" \
    DATABASE_URL="sqlite::memory:" \
    RUST_LOG="warn" \
        "$BIN" >"$TMPDIR_/server.log" 2>&1 &
    SERVER_PID=$!
    if ! wait_tcp "$HOST" "$PORT"; then
        cat "$TMPDIR_/server.log" >&2
        fail "server did not bind ${HOST}:${PORT} within 10 s"
    fi
    ok "server listening (pid $SERVER_PID)"
else
    hr
    say "using external server at $BASE"
fi

# ── 2. /info ────────────────────────────────────────────────────────────
hr
say "GET ${BASE}/api/v1/info"
status=$(curl_status "${BASE}/api/v1/info")
assert_status 200 "$status" "/info"
grep -q '"api_version":"1"' "$TMPDIR_/last_body" || fail "/info missing api_version"
ok "info OK"

# ── 3. register ─────────────────────────────────────────────────────────
hr
say "POST /auth/register  (email=$EMAIL)"
status=$(curl_status -X POST "${BASE}/api/v1/auth/register" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
assert_status 201 "$status" "/auth/register"
ok "registered"

# ── 4. login ────────────────────────────────────────────────────────────
hr
say "POST /auth/login"
status=$(curl_status -X POST "${BASE}/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
assert_status 200 "$status" "/auth/login"
TOKEN=$(grep -oE '"token":"[^"]+"' "$TMPDIR_/last_body" | head -n1 | cut -d'"' -f4)
[[ -n "$TOKEN" ]] || fail "no token in /auth/login response"
ok "logged in, token captured"

# ── 5. list profiles (empty) ───────────────────────────────────────────
hr
say "GET /profiles  (expect empty)"
status=$(curl_status -H "Authorization: Bearer $TOKEN" "${BASE}/api/v1/profiles")
assert_status 200 "$status" "/profiles"
grep -q '"profiles":\[\]' "$TMPDIR_/last_body" || fail "/profiles not empty"
ok "list empty"

# ── 6. create alias ─────────────────────────────────────────────────────
hr
say "POST /profiles  (alias=$ALIAS)"
status=$(curl_status -X POST "${BASE}/api/v1/profiles" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"alias\":\"$ALIAS\"}")
assert_status 201 "$status" "/profiles (create)"
grep -q "\"alias\":\"$ALIAS\"" "$TMPDIR_/last_body" || fail "create did not echo alias"
ok "alias created"

# ── 7. put_blob (expected_version=0) ───────────────────────────────────
hr
say "PUT /profiles/$ALIAS/blob?expected_version=0"
status=$(curl_status -X PUT "${BASE}/api/v1/profiles/${ALIAS}/blob?expected_version=0" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "$BLOB_PAYLOAD")
assert_status 200 "$status" "/blob (initial PUT)"
grep -q '"blob_version":1' "$TMPDIR_/last_body" || fail "blob_version did not bump to 1"
ok "blob uploaded, version=1"

# ── 8. get_blob ─────────────────────────────────────────────────────────
hr
say "GET /profiles/$ALIAS/blob"
status=$(curl_status -H "Authorization: Bearer $TOKEN" "${BASE}/api/v1/profiles/${ALIAS}/blob")
assert_status 200 "$status" "/blob (GET)"
got=$(cat "$TMPDIR_/last_body")
[[ "$got" == "$BLOB_PAYLOAD" ]] || fail "blob payload mismatch: got '$got'"
ok "blob round-trip OK"

# ── 9. stale expected_version → 409 ────────────────────────────────────
hr
say "PUT /profiles/$ALIAS/blob?expected_version=0  (stale, expect 409)"
status=$(curl_status -X PUT "${BASE}/api/v1/profiles/${ALIAS}/blob?expected_version=0" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary 'stale')
assert_status 409 "$status" "/blob stale PUT"
ok "stale PUT correctly rejected with 409"

# ── 10. delete ──────────────────────────────────────────────────────────
hr
say "DELETE /profiles/$ALIAS"
status=$(curl_status -X DELETE "${BASE}/api/v1/profiles/${ALIAS}" \
    -H "Authorization: Bearer $TOKEN")
assert_status 200 "$status" "/profiles (DELETE)"
ok "alias deleted"

hr
ok "smoke OK — all 9 checks passed against $BASE"
exit 0
