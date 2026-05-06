# AGENTS.md — zz-drop-server-minimal

This repository is part of the **zz-drop** project.

zz-drop is a minimalist CLI-first tool to quickly put files into — and
get files from — a configured safe cloud destination.

```bash
zz file.md      # upload
zz d file.md    # download
```

The project is not a sync tool, not a mount tool, and not a generic
cloud file manager.

## Required reading before editing

Before modifying anything in this repository, read:

- `README.md`
- `SECURITY.md` if present
- `CONTRIBUTING.md` if present
- relevant files under `docs/` if present
- this `AGENTS.md`

If the maintainer has provided additional project context for the
session, follow it. If unsure, stop and ask the maintainer before
editing — do not proceed on partial context.

## This repository's role

This repository is the **minimal reference implementation of the
zz-drop API v1**. It is not the production hosted server.

It contains:

- API v1 compatibility surface
- account login/register
- profile alias create/list/delete
- encrypted `profile.zz` upload/download
- `expected_version` conflict handling
- minimal database

It must clearly state in `README.md`:

- not production-ready
- use at your own risk
- no complete hardening
- no billing
- no polished dashboard
- no advanced abuse handling
- no monitoring/backups/compliance guarantees

It must **not** add features outside the API v1 reference surface
(no billing, no dashboard polish, no Pro plan, no email flows beyond
what the API v1 contract requires).

API DTOs and the OpenAPI contract are defined upstream in the shared
crate; do not duplicate them here.

## Mandatory project-wide rule

Do **not** make isolated changes.

Every change must consider:

- API v1 compatibility (this is the canonical reference)
- profile alias model (charset, length, lowercase, global uniqueness)
- blob size limits
- security/privacy/logging
- README warnings (not production)
- tests
- cross-repository duplication

A change is incomplete if it changes behavior without updating the
relevant docs/spec/tests in the same patch.

## Security rules

Never log:

- account passwords
- password hashes in plaintext form
- session tokens
- Authorization headers
- profile decrypt passphrases (the server must never receive them)
- decrypted profile data (the server must never receive it)
- provider credentials (the server must never receive them)
- persistent IP/user-agent logs associated with profiles or sessions

The server stores **only**:

- account credentials hashed with Argon2id
- session token hashes
- profile alias metadata
- the encrypted `profile.zz` blob (opaque, server cannot decrypt)

The server must never see or store decrypted profile data, provider
metadata, or provider credentials.

Errors must not leak excessive information (e.g. distinguish
"account exists" vs "wrong password" only where the threat model
allows).

## Documentation rule

If behavior changes, update docs in the same change.

- API changes → update the OpenAPI contract in the shared crate; this
  repository must remain compatible
- security behavior changes → update `SECURITY.md` and `README.md`
  warning section
- migration changes → document migration steps

## Definition of done

A change is not complete unless:

- code builds
- tests pass or are updated
- docs are updated if needed
- API compatibility with v1 is preserved
- security impact has been considered
- the "not production" warning in `README.md` is intact
- no scope creep was introduced
