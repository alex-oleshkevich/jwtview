# jwtview

`jwtview` is a Rust-powered CLI utility for peeking inside JSON Web Tokens without decrypting or mutating them. It splits a token into header, payload, and signature, pretty-prints the claims with colorized values, and (optionally) verifies RS256 signatures against a JWKS endpoint.

## Features

- Accepts tokens via positional argument, `--file <path>`, or stdin with `--file -`.
- Base64url decodes header/payload and prints them with sorted keys, nested object/array support, and human-friendly timestamps for `exp`, `iat`, and `nbf`.
- Shows the raw signature segment plus its byte length.
- When `--jwks-url` is provided, fetches the JWKS, selects the matching `kid`, and verifies RS256 signatures using `ring`.
- Alternatively, pass `--key <pem>` to verify against a local RSA public key (PEM). `--key` and `--jwks-url` are mutually exclusive.

## Usage

```bash
cargo run -- <token>
cargo run -- --file token.jwt --jwks-url https://example.com/.well-known/jwks.json
cargo run -- --key path/to/key.pem <token>
cargo run -- --file - < token.txt
```

### CLI Options

| Flag | Description |
| ---- | ----------- |
| `--file <path>` | Read the token from a file (`-` to read from stdin). |
| `<token>` | Positional argument for the raw JWT when `--file` is omitted. |
| `--jwks-url <url>` | Optional JWKS endpoint; if set, RS256 signature verification runs automatically. |
| `--key <path>` | Optional path to a PEM-encoded RSA public key (SubjectPublicKeyInfo). Cannot be combined with `--jwks-url`. |

## Building

```bash
cargo build
```

## Disclaimer

This tool was vibe coded with Codex. The author doesn't give a fuck if it breaks anything and never inspected the code. Use at your own risk.
