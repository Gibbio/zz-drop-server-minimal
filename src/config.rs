use std::env;
use std::net::SocketAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use thiserror::Error;

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_DB_URL: &str = "sqlite::memory:";
const TOTP_KEY_BYTES: usize = 32;
const DEFAULT_MAX_ALIASES_FREE: u32 = 5;
const DEFAULT_BLOB_MAX_BYTES: u64 = 1 * 1024 * 1024; // 1 MiB

#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Address the server binds to. From `ZZDROP_BIND`, default
    /// `127.0.0.1:8080`. Bind to `127.0.0.1` only by default — exposing
    /// to the public internet is an explicit operator decision and is
    /// gated by SECURITY.md warnings.
    pub bind: SocketAddr,

    /// SQLx connection URL. From `DATABASE_URL`, default
    /// `sqlite::memory:`. Production deployments should set this to a
    /// file path (`sqlite:/var/lib/zz-drop/state.db`) — the in-memory
    /// default exists so `cargo run` Just Works without setup.
    pub database_url: String,

    /// 32-byte master key used to encrypt TOTP shared seeds at rest.
    /// From `ZZDROP_TOTP_KEY` (base64). If unset, generated at startup
    /// — TOTP enrollments then do not survive a restart and a stderr
    /// warning is printed by `main`.
    pub totp_master_key: [u8; 32],

    /// Maximum number of profile aliases per Free account. From
    /// `ZZDROP_MAX_ALIASES_FREE`, default 5.
    pub max_aliases_free: u32,

    /// Hard cap on the size of an uploaded encrypted blob (per blob).
    /// From `ZZDROP_BLOB_MAX_BYTES`, default 1 MiB. The hosted
    /// `zz-drop.net` will likely raise this; the minimal reference
    /// keeps it tight to discourage misuse.
    pub blob_max_bytes: u64,

    /// Free-form `implementation` field returned by `/api/v1/info`.
    /// Defaults to the crate name + version.
    pub implementation: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("ZZDROP_BIND `{value}`: {source}")]
    BadBind {
        value: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("ZZDROP_TOTP_KEY: {0}")]
    BadTotpKey(String),
    #[error("ZZDROP_MAX_ALIASES_FREE: {0}")]
    BadMaxAliases(String),
    #[error("ZZDROP_BLOB_MAX_BYTES: {0}")]
    BadBlobMax(String),
    #[error("rng failure")]
    Rng,
}

impl ServerConfig {
    /// Build a config from environment variables, falling back to safe
    /// development defaults. The caller can ask `totp_master_key_was_random()`
    /// to know whether a stderr warning should be printed.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = match env::var("ZZDROP_BIND") {
            Ok(s) => s
                .parse()
                .map_err(|source| ConfigError::BadBind { value: s, source })?,
            Err(_) => DEFAULT_BIND
                .parse()
                .expect("DEFAULT_BIND is a valid SocketAddr"),
        };
        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DB_URL.to_string());
        let totp_master_key = read_or_generate_totp_key()?;
        let max_aliases_free = match env::var("ZZDROP_MAX_ALIASES_FREE") {
            Ok(s) => s
                .parse::<u32>()
                .map_err(|e| ConfigError::BadMaxAliases(e.to_string()))?,
            Err(_) => DEFAULT_MAX_ALIASES_FREE,
        };
        let blob_max_bytes = match env::var("ZZDROP_BLOB_MAX_BYTES") {
            Ok(s) => s
                .parse::<u64>()
                .map_err(|e| ConfigError::BadBlobMax(e.to_string()))?,
            Err(_) => DEFAULT_BLOB_MAX_BYTES,
        };
        let implementation = format!(
            "{name} v{version}",
            name = env!("CARGO_PKG_NAME"),
            version = env!("CARGO_PKG_VERSION")
        );
        Ok(Self {
            bind,
            database_url,
            totp_master_key,
            max_aliases_free,
            blob_max_bytes,
            implementation,
        })
    }

    /// `true` when `ZZDROP_TOTP_KEY` was unset at startup and we
    /// generated a random key in memory — TOTP enrollments will not
    /// survive a process restart.
    pub fn totp_master_key_was_random(&self) -> bool {
        env::var_os("ZZDROP_TOTP_KEY")
            .filter(|v| !v.is_empty())
            .is_none()
    }
}

fn read_or_generate_totp_key() -> Result<[u8; TOTP_KEY_BYTES], ConfigError> {
    if let Ok(s) = env::var("ZZDROP_TOTP_KEY") {
        let bytes = B64
            .decode(s.as_bytes())
            .map_err(|e| ConfigError::BadTotpKey(format!("base64: {e}")))?;
        if bytes.len() != TOTP_KEY_BYTES {
            return Err(ConfigError::BadTotpKey(format!(
                "expected {TOTP_KEY_BYTES} bytes, got {}",
                bytes.len()
            )));
        }
        let mut k = [0u8; TOTP_KEY_BYTES];
        k.copy_from_slice(&bytes);
        return Ok(k);
    }
    let mut k = [0u8; TOTP_KEY_BYTES];
    getrandom::getrandom(&mut k).map_err(|_| ConfigError::Rng)?;
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bind_parses() {
        let _: SocketAddr = DEFAULT_BIND
            .parse()
            .expect("DEFAULT_BIND is a SocketAddr");
    }

    #[test]
    fn implementation_string_is_non_empty() {
        // We can't fully mutate process env in parallel tests; just
        // assert the constant build-time format produces something.
        let imp = format!(
            "{name} v{version}",
            name = env!("CARGO_PKG_NAME"),
            version = env!("CARGO_PKG_VERSION")
        );
        assert!(imp.starts_with("zz-drop-server-minimal v"));
    }
}
