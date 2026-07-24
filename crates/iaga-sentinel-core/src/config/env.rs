use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEnv {
    Development,
    Test,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMode {
    Sidecar,
    Gateway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Compact,
    Json,
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogFormat::Pretty => write!(f, "pretty"),
            LogFormat::Compact => write!(f, "compact"),
            LogFormat::Json => write!(f, "json"),
        }
    }
}

impl std::fmt::Display for ServiceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceMode::Sidecar => write!(f, "sidecar"),
            ServiceMode::Gateway => write!(f, "gateway"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppEnv {
    pub port: u16,
    /// Interface the HTTP server binds to (`IAGA_SENTINEL_HOST`).
    /// Defaults to `0.0.0.0` (all interfaces), the pre-1.5.2 behavior.
    pub host: String,
    pub node_env: NodeEnv,
    pub default_mode: ServiceMode,
    /// Allowed CORS origins (`IAGA_SENTINEL_CORS_ORIGINS`, comma-separated).
    /// `None` keeps the permissive `Any` origin of previous releases.
    pub cors_origins: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct LoggingEnv {
    pub format: LogFormat,
    pub filter_directive: String,
}

/// Parse an env var into `T`, falling back to `default` when the var is
/// unset, empty, or unparseable. Tunables read through this helper keep
/// their pre-1.5.2 hardcoded values as defaults.
pub fn env_parse<T: std::str::FromStr>(name: &str, default: T) -> T {
    parse_or(env::var(name).ok(), default)
}

fn parse_or<T: std::str::FromStr>(raw: Option<String>, default: T) -> T {
    raw.as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_origin_list(raw: Option<String>) -> Option<Vec<String>> {
    let list: Vec<String> = raw?
        .split(',')
        .map(str::trim)
        .filter(|o| !o.is_empty())
        .map(str::to_string)
        .collect();
    if list.is_empty() {
        None
    } else {
        Some(list)
    }
}

/// Resolve `IAGA_SENTINEL_DEFAULT_MODE` into a [`ServiceMode`]. Defaults to
/// `Sidecar`: IAGA Sentinel is an advisory governance + evidence sidecar, not a
/// network gateway (see positioning / ARCHITECTURE). Reporting `gateway` on
/// `/health` by default mislabeled the product; opt into gateway framing
/// explicitly with `IAGA_SENTINEL_DEFAULT_MODE=gateway`.
fn parse_service_mode(raw: Option<String>) -> ServiceMode {
    match raw.as_deref().map(str::trim) {
        Some("gateway") => ServiceMode::Gateway,
        _ => ServiceMode::Sidecar,
    }
}

pub fn load_env() -> AppEnv {
    let port = env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4010);

    let host = env::var("IAGA_SENTINEL_HOST")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "0.0.0.0".to_string());

    let node_env = match env::var("NODE_ENV").unwrap_or_default().as_str() {
        "production" => NodeEnv::Production,
        "test" => NodeEnv::Test,
        _ => NodeEnv::Development,
    };

    let default_mode = parse_service_mode(env::var("IAGA_SENTINEL_DEFAULT_MODE").ok());

    let cors_origins = parse_origin_list(env::var("IAGA_SENTINEL_CORS_ORIGINS").ok());

    AppEnv {
        port,
        host,
        node_env,
        default_mode,
        cors_origins,
    }
}

pub fn load_logging_env(node_env: NodeEnv) -> LoggingEnv {
    let format = match env::var("IAGA_SENTINEL_LOG_FORMAT")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "json" => LogFormat::Json,
        "compact" => LogFormat::Compact,
        "pretty" => LogFormat::Pretty,
        _ => {
            if node_env == NodeEnv::Production {
                LogFormat::Json
            } else {
                LogFormat::Pretty
            }
        }
    };

    let filter_directive = env::var("RUST_LOG")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            env::var("IAGA_SENTINEL_LOG_LEVEL")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .unwrap_or_else(|| "info".to_string());

    LoggingEnv {
        format,
        filter_directive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_or_falls_back_on_unset_empty_or_garbage() {
        assert_eq!(parse_or::<u64>(None, 42), 42);
        assert_eq!(parse_or::<u64>(Some("".into()), 42), 42);
        assert_eq!(parse_or::<u64>(Some("  ".into()), 42), 42);
        assert_eq!(parse_or::<u64>(Some("nope".into()), 42), 42);
        assert_eq!(parse_or::<u64>(Some("7".into()), 42), 7);
        assert_eq!(parse_or::<u64>(Some(" 7 ".into()), 42), 7);
    }

    #[test]
    fn service_mode_defaults_to_sidecar() {
        // Unset / empty / unknown all default to Sidecar (not Gateway).
        assert_eq!(parse_service_mode(None), ServiceMode::Sidecar);
        assert_eq!(parse_service_mode(Some("".into())), ServiceMode::Sidecar);
        assert_eq!(parse_service_mode(Some("proxy".into())), ServiceMode::Sidecar);
        assert_eq!(parse_service_mode(Some("sidecar".into())), ServiceMode::Sidecar);
        // Only the explicit opt-in selects Gateway.
        assert_eq!(parse_service_mode(Some("gateway".into())), ServiceMode::Gateway);
        assert_eq!(
            parse_service_mode(Some("  gateway  ".into())),
            ServiceMode::Gateway
        );
    }

    #[test]
    fn origin_list_parses_and_normalizes() {
        assert_eq!(parse_origin_list(None), None);
        assert_eq!(parse_origin_list(Some("".into())), None);
        assert_eq!(parse_origin_list(Some(" , ,".into())), None);
        assert_eq!(
            parse_origin_list(Some("https://a.example, https://b.example ,".into())),
            Some(vec![
                "https://a.example".to_string(),
                "https://b.example".to_string()
            ])
        );
    }
}
