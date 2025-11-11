## Project Snapshot

- **Name**: `jwtview` – terminal utility to inspect JSON Web Tokens.
- **Language/Tooling**: Rust 2024 edition with Cargo.
- **Key Dependencies**:
  - `clap` for CLI parsing.
  - `anyhow` for error handling.
  - `serde`/`serde_json` for JSON decoding.
  - `base64` for segment decoding.
  - `colored` for themed terminal output.
  - `chrono` for human-readable timestamp rendering.
  - `reqwest` (blocking, rustls) for JWKS HTTP fetches.
  - `ring` for JOSE signature verification (RSA/ECDSA/EdDSA).
  - `pem` for parsing PEM public keys.

## Current Behavior

1. Reads tokens via positional arg, `--file <path>`, or `--file -` (stdin).
2. Splits JWT, decodes header/payload JSON, and displays them with sorted keys, object/array recursion, and colored values.
3. Annotates `exp`, `iat`, `nbf` claims with RFC3339 timestamps in dim text.
4. Shows signature segment (base64url + byte length).
5. Verification modes:
   - `--jwks-url`: fetch JWKS, locate matching `kid`, verify signatures using the header-selected algorithm (RS*/PS*, ES256/384, EdDSA).
   - `--key`: load PEM-encoded RSA/ECDSA/Ed25519 public key (SPKI) and verify locally.
   - Both flags are mutually exclusive; when neither is passed, verification is skipped.
   - Prints verification status: `verified` (kid + alg), `FAILED <reason>`, or `skipped` if no source.

## Notes for Future Agents

- Networking requires approval/escalation in restricted environments; tests that fetch JWKS must account for that.
- Only RS256 is implemented; extend `verify_with_key` to support other `alg`/`kty` combinations.
- JWKS fetch currently downloads on every run; consider caching if performance is needed.
- Output uses `colored`; avoid non-ASCII to keep terminals happy.
- Maintain contrast rules (dim white instead of bright black) to keep muted text legible on dark backgrounds.
