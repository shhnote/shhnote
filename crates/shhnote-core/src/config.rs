use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

const MIN_SECRET_LEN: usize = 32;
const MIB: u64 = 1024 * 1024;
// Bigger files in the database slow it down, so this limit can be lowered but never raised.
const MAX_INLINE_BYTES: u64 = 3 * MIB / 2;
const DEFAULT_LOCAL_MAX_BYTES: u64 = 10 * MIB;
const DEFAULT_S3_MAX_BYTES: u64 = 25 * MIB;

#[derive(Debug)]
pub struct Config {
    pub env: AppEnv,
    pub debug: bool,
    pub url: String,
    pub api_routing: ApiRouting,
    pub api_url: String,
    pub secret_key: Secret,
    pub encryption_key: Secret,
    pub bind_addr: SocketAddr,
    pub log_level: LogLevel,
    pub trusted_proxies: Vec<IpAddr>,
    pub database: Database,
    pub storage: Storage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnv {
    Local,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiRouting {
    // The API lives under `/api` on the main domain.
    Path,
    // The API lives on its own subdomain, at `host`.
    Subdomain { host: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug)]
pub enum Database {
    Sqlite {
        path: PathBuf,
    },
    Postgres {
        host: String,
        port: u16,
        database: String,
        username: String,
        password: Secret,
    },
}

#[derive(Debug)]
pub struct Storage {
    // Files up to this size are stored in the database itself.
    pub inline_max_bytes: u64,
    // Where larger files go. `None` means only inline files are allowed.
    pub external: Option<ExternalStorage>,
}

#[derive(Debug)]
pub enum ExternalStorage {
    Local {
        path: PathBuf,
        max_bytes: u64,
    },
    S3 {
        bucket: String,
        region: String,
        endpoint: Option<String>,
        access_key_id: String,
        secret_access_key: Secret,
        max_bytes: u64,
    },
}

impl Storage {
    pub fn max_upload_bytes(&self) -> u64 {
        self.external
            .as_ref()
            .map_or(self.inline_max_bytes, ExternalStorage::max_bytes)
    }
}

impl ExternalStorage {
    pub fn max_bytes(&self) -> u64 {
        match self {
            Self::Local { max_bytes, .. } | Self::S3 { max_bytes, .. } => *max_bytes,
        }
    }
}

// Wraps sensitive values so they never show up in logs or error messages by accident.
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Debug)]
pub enum ConfigError {
    DotEnv(String),
    Missing(&'static str),
    Invalid { name: &'static str, reason: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DotEnv(reason) => write!(f, "could not read .env: {reason}"),
            Self::Missing(name) => write!(f, "{name} is required but not set"),
            Self::Invalid { name, reason } => write!(f, "{name} is invalid: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let mut vars = read_dotenv()?;
        // Real environment variables win over .env, so a deployment can override any value.
        vars.extend(
            std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))),
        );
        Self::from_vars(&vars)
    }

    pub fn from_vars(vars: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let vars = Vars(vars);

        // Defaults to production so a missing value never turns on development behaviour.
        let env = vars.parse_or("APP_ENV", AppEnv::Production)?;
        let debug = vars.parse_or("APP_DEBUG", false)?;
        if env == AppEnv::Production && debug {
            return Err(invalid(
                "APP_DEBUG",
                "must be false when APP_ENV is production",
            ));
        }

        let url = vars.required("APP_URL")?.trim_end_matches('/').to_string();
        let Some((scheme, authority)) = url.split_once("://") else {
            return Err(invalid("APP_URL", "must start with http:// or https://"));
        };
        if !matches!(scheme, "http" | "https") {
            return Err(invalid("APP_URL", "must start with http:// or https://"));
        }
        if authority.is_empty() || authority.contains(['/', '@', '?', '#']) {
            return Err(invalid(
                "APP_URL",
                "must be just a scheme and host, like https://example.com",
            ));
        }

        let (api_routing, api_url) = match vars.get("API_ROUTING").unwrap_or("path") {
            // Local development always uses path routing, so no extra DNS setup is needed.
            "path" | "subdomain" if env == AppEnv::Local => {
                (ApiRouting::Path, format!("{url}/api"))
            }
            "path" => (ApiRouting::Path, format!("{url}/api")),
            "subdomain" => {
                let host = authority
                    .rsplit_once(':')
                    .map_or(authority, |(host, _port)| host);
                if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
                    return Err(invalid(
                        "API_ROUTING",
                        "subdomain needs APP_URL to use a domain name, not an IP address",
                    ));
                }
                let api_url = format!("{scheme}://api.{}", authority.to_ascii_lowercase());
                (
                    ApiRouting::Subdomain {
                        host: format!("api.{}", host.to_ascii_lowercase()),
                    },
                    api_url,
                )
            }
            _ => return Err(invalid("API_ROUTING", "must be path or subdomain")),
        };

        let host = vars.parse_or("SERVER_HOST", IpAddr::V4(Ipv4Addr::LOCALHOST))?;
        let port = vars.parse_or("SERVER_PORT", 3000)?;

        let trusted_proxies = match vars.get("TRUSTED_PROXIES") {
            None => Vec::new(),
            Some(list) => list
                .split(',')
                .map(|ip| ip.trim().parse())
                .collect::<Result<_, _>>()
                .map_err(|e| invalid("TRUSTED_PROXIES", e))?,
        };

        Ok(Self {
            env,
            debug,
            url,
            api_routing,
            api_url,
            secret_key: vars.key("APP_SECRET_KEY")?,
            encryption_key: vars.key("APP_ENCRYPTION_KEY")?,
            bind_addr: SocketAddr::new(host, port),
            log_level: vars.parse_or("LOG_LEVEL", LogLevel::Info)?,
            trusted_proxies,
            database: Database::from_vars(&vars)?,
            storage: Storage::from_vars(&vars)?,
        })
    }
}

impl Database {
    fn from_vars(vars: &Vars) -> Result<Self, ConfigError> {
        match vars.required("DB_CONNECTION")? {
            "sqlite" => Ok(Self::Sqlite {
                path: vars
                    .get("SQLITE_PATH")
                    .unwrap_or("storage/shhnote.db")
                    .into(),
            }),
            "postgres" => Ok(Self::Postgres {
                host: vars.required("PG_HOST")?.to_string(),
                port: vars.parse_or("PG_PORT", 5432)?,
                database: vars.required("PG_DATABASE")?.to_string(),
                username: vars.required("PG_USERNAME")?.to_string(),
                // Local setups often have no password, so an empty one is allowed.
                password: Secret(vars.get("PG_PASSWORD").unwrap_or_default().to_string()),
            }),
            _ => Err(invalid("DB_CONNECTION", "must be sqlite or postgres")),
        }
    }
}

impl Storage {
    fn from_vars(vars: &Vars) -> Result<Self, ConfigError> {
        let inline_max_bytes = vars.parse_or("UPLOAD_MAX_INLINE_BYTES", MAX_INLINE_BYTES)?;
        if inline_max_bytes == 0 || inline_max_bytes > MAX_INLINE_BYTES {
            return Err(invalid(
                "UPLOAD_MAX_INLINE_BYTES",
                format!("must be between 1 and {MAX_INLINE_BYTES}"),
            ));
        }

        let external = match vars.get("STORAGE_DRIVER").unwrap_or("inline") {
            "inline" => None,
            "local" => Some(ExternalStorage::Local {
                path: vars
                    .get("STORAGE_LOCAL_PATH")
                    .unwrap_or("storage/uploads")
                    .into(),
                max_bytes: external_max_bytes(
                    vars,
                    "UPLOAD_MAX_LOCAL_BYTES",
                    DEFAULT_LOCAL_MAX_BYTES,
                    inline_max_bytes,
                )?,
            }),
            "s3" => Some(ExternalStorage::S3 {
                bucket: vars.required("S3_BUCKET")?.to_string(),
                region: vars.required("S3_REGION")?.to_string(),
                endpoint: vars.get("S3_ENDPOINT").map(str::to_string),
                access_key_id: vars.required("S3_ACCESS_KEY_ID")?.to_string(),
                secret_access_key: Secret(vars.required("S3_SECRET_ACCESS_KEY")?.to_string()),
                max_bytes: external_max_bytes(
                    vars,
                    "UPLOAD_MAX_S3_BYTES",
                    DEFAULT_S3_MAX_BYTES,
                    inline_max_bytes,
                )?,
            }),
            _ => return Err(invalid("STORAGE_DRIVER", "must be inline, local or s3")),
        };

        Ok(Self {
            inline_max_bytes,
            external,
        })
    }
}

fn external_max_bytes(
    vars: &Vars,
    name: &'static str,
    default: u64,
    inline_max_bytes: u64,
) -> Result<u64, ConfigError> {
    let max_bytes = vars.parse_or(name, default)?;
    // Files up to the inline limit always go in the database, so a lower limit here makes no sense.
    if max_bytes < inline_max_bytes {
        return Err(invalid(name, "must be at least UPLOAD_MAX_INLINE_BYTES"));
    }
    Ok(max_bytes)
}

impl FromStr for AppEnv {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            _ => Err("must be local or production"),
        }
    }
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err("must be error, warn, info, debug or trace"),
        }
    }
}

fn read_dotenv() -> Result<HashMap<String, String>, ConfigError> {
    let lines = match dotenvy::dotenv_iter() {
        Ok(lines) => lines,
        // No .env file is normal in production, where real environment variables are used.
        Err(e) if e.not_found() => return Ok(HashMap::new()),
        Err(e) => return Err(dotenv_error(e)),
    };
    lines.collect::<Result<_, _>>().map_err(dotenv_error)
}

fn dotenv_error(e: dotenvy::Error) -> ConfigError {
    match e {
        // The default message includes the whole line, which could contain a secret.
        dotenvy::Error::LineParse(_, index) => {
            ConfigError::DotEnv(format!("syntax error at character {index} of a line"))
        }
        other => ConfigError::DotEnv(other.to_string()),
    }
}

fn invalid(name: &'static str, reason: impl fmt::Display) -> ConfigError {
    ConfigError::Invalid {
        name,
        reason: reason.to_string(),
    }
}

struct Vars<'a>(&'a HashMap<String, String>);

impl Vars<'_> {
    // Empty values count as unset, so `KEY=` behaves the same as leaving the line out.
    fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(|v| v.trim()).filter(|v| !v.is_empty())
    }

    fn required(&self, name: &'static str) -> Result<&str, ConfigError> {
        self.get(name).ok_or(ConfigError::Missing(name))
    }

    fn parse_or<T>(&self, name: &'static str, default: T) -> Result<T, ConfigError>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        match self.get(name) {
            None => Ok(default),
            Some(value) => value.parse().map_err(|e| invalid(name, e)),
        }
    }

    // The length check catches placeholders like "changeme" before they reach production.
    fn key(&self, name: &'static str) -> Result<Secret, ConfigError> {
        let value = self.required(name)?;
        if value.len() < MIN_SECRET_LEN {
            return Err(invalid(
                name,
                format!("must be at least {MIN_SECRET_LEN} characters"),
            ));
        }
        Ok(Secret(value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_vars() -> HashMap<String, String> {
        [
            ("APP_ENV", "local"),
            ("APP_URL", "http://localhost:3000/"),
            ("APP_SECRET_KEY", "s".repeat(44).as_str()),
            ("APP_ENCRYPTION_KEY", "e".repeat(44).as_str()),
            ("DB_CONNECTION", "sqlite"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn with(changes: &[(&str, &str)]) -> HashMap<String, String> {
        let mut vars = valid_vars();
        for (k, v) in changes {
            vars.insert(k.to_string(), v.to_string());
        }
        vars
    }

    #[test]
    fn applies_defaults() {
        let config = Config::from_vars(&valid_vars()).unwrap();
        assert_eq!(config.url, "http://localhost:3000");
        assert_eq!(config.bind_addr, "127.0.0.1:3000".parse().unwrap());
        assert_eq!(config.log_level, LogLevel::Info);
        assert!(config.trusted_proxies.is_empty());
        assert_eq!(config.storage.inline_max_bytes, MAX_INLINE_BYTES);
        assert!(config.storage.external.is_none());
        assert_eq!(config.storage.max_upload_bytes(), MAX_INLINE_BYTES);
    }

    #[test]
    fn api_uses_path_routing_by_default() {
        let config = Config::from_vars(&valid_vars()).unwrap();
        assert_eq!(config.api_routing, ApiRouting::Path);
        assert_eq!(config.api_url, "http://localhost:3000/api");
    }

    #[test]
    fn api_subdomain_routing() {
        let vars = with(&[
            ("APP_ENV", "production"),
            ("APP_URL", "https://Example.com:8443"),
            ("API_ROUTING", "subdomain"),
        ]);
        let config = Config::from_vars(&vars).unwrap();
        assert_eq!(
            config.api_routing,
            ApiRouting::Subdomain {
                host: "api.example.com".into()
            }
        );
        assert_eq!(config.api_url, "https://api.example.com:8443");
    }

    #[test]
    fn local_always_uses_api_path_routing() {
        let vars = with(&[("API_ROUTING", "subdomain")]);
        assert_eq!(
            Config::from_vars(&vars).unwrap().api_routing,
            ApiRouting::Path
        );
    }

    #[test]
    fn api_subdomain_needs_a_domain_name() {
        let vars = with(&[
            ("APP_ENV", "production"),
            ("APP_URL", "http://127.0.0.1:3000"),
            ("API_ROUTING", "subdomain"),
        ]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Invalid {
                name: "API_ROUTING",
                ..
            })
        ));
    }

    #[test]
    fn rejects_app_url_with_path() {
        let vars = with(&[("APP_URL", "https://example.com/app")]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Invalid {
                name: "APP_URL",
                ..
            })
        ));
    }

    #[test]
    fn defaults_to_production() {
        let mut vars = valid_vars();
        vars.remove("APP_ENV");
        assert_eq!(Config::from_vars(&vars).unwrap().env, AppEnv::Production);
    }

    #[test]
    fn rejects_debug_in_production() {
        let vars = with(&[("APP_ENV", "production"), ("APP_DEBUG", "true")]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Invalid {
                name: "APP_DEBUG",
                ..
            })
        ));
    }

    #[test]
    fn rejects_missing_or_short_secrets() {
        let vars = with(&[("APP_SECRET_KEY", "")]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Missing("APP_SECRET_KEY"))
        ));

        let vars = with(&[("APP_ENCRYPTION_KEY", "changeme")]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Invalid {
                name: "APP_ENCRYPTION_KEY",
                ..
            })
        ));
    }

    #[test]
    fn postgres_requires_connection_details() {
        let vars = with(&[("DB_CONNECTION", "postgres"), ("PG_HOST", "127.0.0.1")]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Missing("PG_DATABASE"))
        ));
    }

    #[test]
    fn inline_limit_can_only_be_lowered() {
        let vars = with(&[("UPLOAD_MAX_INLINE_BYTES", "1000000")]);
        let config = Config::from_vars(&vars).unwrap();
        assert_eq!(config.storage.inline_max_bytes, 1_000_000);

        let vars = with(&[("UPLOAD_MAX_INLINE_BYTES", "2000000")]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Invalid {
                name: "UPLOAD_MAX_INLINE_BYTES",
                ..
            })
        ));
    }

    #[test]
    fn external_storage_defaults() {
        let config = Config::from_vars(&with(&[("STORAGE_DRIVER", "local")])).unwrap();
        assert_eq!(config.storage.max_upload_bytes(), DEFAULT_LOCAL_MAX_BYTES);

        let vars = with(&[
            ("STORAGE_DRIVER", "s3"),
            ("S3_BUCKET", "shhnote"),
            ("S3_REGION", "us-east-1"),
            ("S3_ACCESS_KEY_ID", "id"),
            ("S3_SECRET_ACCESS_KEY", "secret"),
        ]);
        let config = Config::from_vars(&vars).unwrap();
        assert_eq!(config.storage.max_upload_bytes(), DEFAULT_S3_MAX_BYTES);
    }

    #[test]
    fn external_limit_must_cover_inline_limit() {
        let vars = with(&[
            ("STORAGE_DRIVER", "local"),
            ("UPLOAD_MAX_LOCAL_BYTES", "1000"),
        ]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Invalid {
                name: "UPLOAD_MAX_LOCAL_BYTES",
                ..
            })
        ));
    }

    #[test]
    fn s3_requires_bucket() {
        let vars = with(&[("STORAGE_DRIVER", "s3")]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Missing("S3_BUCKET"))
        ));
    }

    #[test]
    fn parses_trusted_proxies() {
        let vars = with(&[("TRUSTED_PROXIES", "10.0.0.1, ::1")]);
        assert_eq!(Config::from_vars(&vars).unwrap().trusted_proxies.len(), 2);

        let vars = with(&[("TRUSTED_PROXIES", "10.0.0.1,nope")]);
        assert!(Config::from_vars(&vars).is_err());
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let config = Config::from_vars(&valid_vars()).unwrap();
        let output = format!("{config:?}");
        assert!(!output.contains(&"s".repeat(44)));
        assert!(output.contains("[redacted]"));
    }
}
