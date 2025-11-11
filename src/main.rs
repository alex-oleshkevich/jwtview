use std::fs;
use std::io::{self, Read};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use clap::Parser;
use colored::*;
use pem::Pem;
use reqwest::blocking::Client;
use ring::signature::{RsaPublicKeyComponents, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use serde::Deserialize;
use serde_json::{Map, Value};

fn main() {
    if let Err(err) = run() {
        eprintln!("{} {}", "error:".red().bold(), err);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let token_source = resolve_token_source(&cli)?;
    let token = token_source.trim().to_string();

    if cli.jwks_url.is_some() && cli.key.is_some() {
        bail!("--jwks-url and --key cannot be used together");
    }

    let parts = TokenParts::parse(&token)?;
    let verification_status = if let Some(key_path) = cli.key.as_deref() {
        match verify_with_key_file(&parts, key_path) {
            Ok(report) => VerificationStatus::Verified(report),
            Err(err) => VerificationStatus::Failed(format!("{err:#}")),
        }
    } else if let Some(url) = cli.jwks_url.as_deref() {
        match verify_with_jwks(&parts, url) {
            Ok(report) => VerificationStatus::Verified(report),
            Err(err) => VerificationStatus::Failed(format!("{err:#}")),
        }
    } else {
        VerificationStatus::Skipped
    };

    println!("{}", "JWT Breakdown".bold());
    println!();

    print_section("Header", &parts.header);
    println!();
    print_section("Payload", &parts.payload);
    println!();
    print_signature(&parts.signature_raw, parts.signature_bytes.len());
    println!();
    print_summary(
        cli.jwks_url.as_deref(),
        cli.key.as_deref(),
        &verification_status,
    );

    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "jwtview", about = "Friendly JWT token inspector")]
struct Cli {
    /// Path to a file that contains the JWT (use '-' for stdin)
    #[arg(long, value_name = "PATH")]
    file: Option<String>,
    /// Raw JWT token when not using --file
    #[arg(value_name = "TOKEN")]
    token_text: Option<String>,
    /// JWKS endpoint the token would be verified against
    #[arg(long = "jwks-url", value_name = "URL")]
    jwks_url: Option<String>,
    /// Path to an RSA public key (PEM). Mutually exclusive with --jwks-url
    #[arg(long = "key", value_name = "PATH")]
    key: Option<String>,
}

fn resolve_token_source(cli: &Cli) -> Result<String> {
    if let Some(path) = &cli.file {
        if path == "-" {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("failed to read token from stdin")?;
            Ok(buf)
        } else {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read token file at {}", path))
        }
    } else {
        cli.token_text
            .clone()
            .context("provide a token via positional argument or --file/--file -")
    }
}

struct TokenParts {
    header: Value,
    payload: Value,
    signature_bytes: Vec<u8>,
    signature_raw: String,
    signing_input: String,
}

impl TokenParts {
    fn parse(token: &str) -> Result<Self> {
        let segments: Vec<&str> = token.split('.').collect();
        if segments.len() != 3 {
            bail!("expected token with three segments, found {}", segments.len());
        }

        let header = decode_json_segment(segments[0]).context("invalid header segment")?;
        let payload = decode_json_segment(segments[1]).context("invalid payload segment")?;
        let signature_bytes =
            decode_segment(segments[2]).context("invalid signature segment encoding")?;

        Ok(Self {
            header,
            payload,
            signature_bytes,
            signature_raw: segments[2].to_string(),
            signing_input: format!("{}.{}", segments[0], segments[1]),
        })
    }
}

fn decode_segment(segment: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .or_else(|_| URL_SAFE.decode(segment))
        .with_context(|| "failed to base64url-decode segment")
}

fn decode_json_segment(segment: &str) -> Result<Value> {
    let bytes = decode_segment(segment)?;
    serde_json::from_slice(&bytes).context("segment is not valid JSON")
}

fn print_section(title: &str, value: &Value) {
    println!("{}", title.bold());
    match value {
        Value::Object(map) => print_object(map, 1),
        _ => println!("  {}", format_value(value, None)),
    }
}

fn print_object(map: &Map<String, Value>, indent: usize) {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for key in keys {
        let val = map.get(key).expect("key must exist");
        let label = format!("{key}:").bright_cyan();
        let padding = "  ".repeat(indent);
        match val {
            Value::Object(obj) => {
                println!("{padding}{label}");
                print_object(obj, indent + 1);
            }
            Value::Array(items) => {
                println!("{padding}{label}");
                print_array(items, indent + 1);
            }
            _ => {
                let formatted = format_value(val, Some(key));
                println!("{padding}{label} {formatted}");
            }
        }
    }
}

fn print_array(items: &[Value], indent: usize) {
    for (idx, item) in items.iter().enumerate() {
        let padding = "  ".repeat(indent);
        let bullet = format!("[{idx}]").bright_white().dimmed();
        match item {
            Value::Object(map) => {
                println!("{padding}{bullet}");
                print_object(map, indent + 1);
            }
            Value::Array(inner) => {
                println!("{padding}{bullet}");
                print_array(inner, indent + 1);
            }
            _ => {
                let formatted = format_value(item, None);
                println!("{padding}{bullet} {formatted}");
            }
        }
    }
}

fn format_value(value: &Value, key_hint: Option<&str>) -> String {
    match value {
        Value::String(s) => format!("{:?}", s).green().to_string(),
        Value::Number(num) => {
            let base = num.to_string().blue().to_string();
            if let Some(key) = key_hint {
                if let Some(extra) = describe_timestamp_claim(key, num) {
                    return format!("{base} {extra}");
                }
            }
            base
        }
        Value::Bool(b) => {
            if *b {
                "true".magenta().to_string()
            } else {
                "false".magenta().to_string()
            }
        }
        Value::Null => "null".bright_white().dimmed().to_string(),
        Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(|v| format_value(v, None)).collect();
            format!("[{}]", rendered.join(", ")).yellow().to_string()
        }
        Value::Object(_) => "{ ... }".yellow().to_string(),
    }
}

fn describe_timestamp_claim(key: &str, num: &serde_json::Number) -> Option<String> {
    let ts = num.as_i64()?;
    match key {
        "exp" | "iat" | "nbf" => {
            let label = match key {
                "exp" => "expires",
                "iat" => "issued",
                "nbf" => "valid from",
                _ => unreachable!(),
            };
            humanize_timestamp(ts).map(|readable| {
                format!(
                    "{}",
                    format!("({label}: {readable})")
                        .bright_white()
                        .dimmed()
                )
            })
        }
        _ => None,
    }
}

fn humanize_timestamp(ts: i64) -> Option<String> {
    let dt: DateTime<Utc> = DateTime::<Utc>::from_timestamp(ts, 0)?;
    Some(dt.to_rfc3339())
}

fn print_signature(raw: &str, byte_len: usize) {
    println!("{}", "Signature".bold());
    println!("  {} {}", "Base64url:".bright_cyan(), raw.yellow());
    println!(
        "  {} {}",
        "Length:".bright_cyan(),
        format!("{byte_len} bytes").bright_white().dimmed()
    );
}

fn print_summary(
    jwks_url: Option<&str>,
    key_path: Option<&str>,
    status: &VerificationStatus,
) {
    println!("{}", "Signature Verification".bold());
    match status {
        VerificationStatus::Skipped => println!(
            "  {} {}",
            "Status:".bright_cyan(),
            "skipped (no verification source provided)".yellow()
        ),
        VerificationStatus::Verified(report) => println!(
            "  {} {}",
            "Status:".bright_cyan(),
            format!(
                "verified (kid: {}, alg: {})",
                report.kid,
                report.alg
            )
            .green()
        ),
        VerificationStatus::Failed(err) => println!(
            "  {} {}",
            "Status:".bright_cyan(),
            format!("FAILED: {err}").red()
        ),
    }
    if let Some(url) = jwks_url {
        println!("  {} {}", "JWKS URL:".bright_cyan(), url);
    }
    if let Some(path) = key_path {
        println!("  {} {}", "Key File:".bright_cyan(), path);
    }
    if jwks_url.is_none() && key_path.is_none() {
        println!(
            "  {} {}",
            "Source:".bright_cyan(),
            "not provided".bright_white().dimmed()
        );
    }
}

#[derive(Debug)]
enum VerificationStatus {
    Skipped,
    Verified(VerificationReport),
    Failed(String),
}

#[derive(Debug)]
struct VerificationReport {
    kid: String,
    alg: String,
}

fn verify_with_jwks(parts: &TokenParts, url: &str) -> Result<VerificationReport> {
    let kid = header_kid(parts)?;
    let alg = ensure_rs256(parts)?;

    let jwks = fetch_jwks(url)?;
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.kid.as_deref() == Some(kid))
        .with_context(|| format!("no JWKS key with kid '{kid}'"))?;

    verify_with_key(parts, jwk)?;

    Ok(VerificationReport {
        kid: kid.to_string(),
        alg: jwk
            .alg
            .clone()
            .unwrap_or_else(|| alg.to_string()),
    })
}

fn verify_with_key_file(parts: &TokenParts, key_path: &str) -> Result<VerificationReport> {
    let alg = ensure_rs256(parts)?;
    let pem_data = fs::read_to_string(key_path)
        .with_context(|| format!("failed to read key file at {key_path}"))?;
    let pem_block: Pem = pem::parse(pem_data).context("failed to parse PEM key")?;

    let verifier =
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pem_block.contents());
    verifier
        .verify(parts.signing_input.as_bytes(), &parts.signature_bytes)
        .map_err(|_| anyhow!("signature verification failed"))?;

    let kid = parts
        .header
        .get("kid")
        .and_then(Value::as_str)
        .unwrap_or("<none>");

    Ok(VerificationReport {
        kid: kid.to_string(),
        alg: alg.to_string(),
    })
}

fn verify_with_key(parts: &TokenParts, jwk: &Jwk) -> Result<()> {
    if jwk.kty != "RSA" {
        bail!("unsupported JWK kty '{}'", jwk.kty);
    }

    let modulus_b64 = jwk.n.as_deref().context("JWK missing modulus 'n'")?;
    let exponent_b64 = jwk.e.as_deref().context("JWK missing exponent 'e'")?;

    let modulus =
        decode_segment(modulus_b64).context("failed to decode JWK modulus 'n' as base64url")?;
    let exponent =
        decode_segment(exponent_b64).context("failed to decode JWK exponent 'e' as base64url")?;

    let public_key = RsaPublicKeyComponents {
        n: modulus.as_slice(),
        e: exponent.as_slice(),
    };

    public_key
        .verify(
            &RSA_PKCS1_2048_8192_SHA256,
            parts.signing_input.as_bytes(),
            &parts.signature_bytes,
        )
        .map_err(|_| anyhow!("signature verification failed"))?;

    Ok(())
}

fn fetch_jwks(url: &str) -> Result<Jwks> {
    let client = Client::builder()
        .build()
        .context("failed to build HTTP client")?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("failed to fetch JWKS from {url}"))?
        .error_for_status()
        .with_context(|| format!("received error response from {url}"))?;

    response.json().context("failed to parse JWKS response")
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

fn header_kid(parts: &TokenParts) -> Result<&str> {
    parts
        .header
        .get("kid")
        .and_then(Value::as_str)
        .context("JWT header missing 'kid'")
}

fn ensure_rs256<'a>(parts: &'a TokenParts) -> Result<&'a str> {
    let alg = parts
        .header
        .get("alg")
        .and_then(Value::as_str)
        .context("JWT header missing 'alg'")?;
    if alg != "RS256" {
        bail!("unsupported alg '{alg}', only RS256 is currently supported");
    }
    Ok(alg)
}
