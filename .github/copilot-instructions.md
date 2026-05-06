This repository is the minimal reference implementation of the zz-drop API v1.

Follow `AGENTS.md` as the source of truth.

When generating code:

- preserve API v1 compatibility
- do not invent new features (no billing, no Pro plan, no dashboard polish)
- do not duplicate DTOs or types defined in the shared crate
- never log secrets (passphrases, session tokens, Authorization headers, decrypted profile data)
- the server must never see or store decrypted profile data, provider credentials or provider metadata
- update docs/tests when behavior changes
- keep the "not production" warning in `README.md` intact
