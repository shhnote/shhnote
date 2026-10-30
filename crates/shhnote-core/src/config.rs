use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

const PREFIX: &str = "SHH_";
const MIN_SECRET_LEN: usize = 32;
const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
// Nothing smaller than the padding minimum can ever be stored, so inline must hold at least that.
const MIN_INLINE_MAX: u64 = 64 * KIB;
const DEFAULT_INLINE_MAX: u64 = 2 * MIB;
const DEFAULT_EXTERNAL_MAX_OBJECT: u64 = 64 * MIB;

// Every variable the server understands. Anything else with the prefix fails startup,
// so a typo never silently falls back to a default.
const KNOWN: &[&str] = &[
    "SHH_ENV",
    "SHH_DEBUG",
    "SHH_URL",
    "SHH_API_ROUTING",
    "SHH_SECRET_KEY",
    "SHH_HOST",
    "SHH_PORT",
    "SHH_LOG_LEVEL",
    "SHH_LOCALES",
    "SHH_DEFAULT_LOCALE",
    "SHH_TRUSTED_PROXIES",
    "SHH_DB",
    "SHH_SQLITE_PATH",
    "SHH_PG_HOST",
    "SHH_PG_PORT",
    "SHH_PG_DATABASE",
    "SHH_PG_USERNAME",
    "SHH_PG_PASSWORD",
    "SHH_STORAGE",
    "SHH_INLINE_MAX",
    "SHH_EXTERNAL_MAX_OBJECT",
    "SHH_LOCAL_PATH",
    "SHH_LOCAL_MAX_TOTAL_BYTES",
    "SHH_S3_BUCKET",
    "SHH_S3_REGION",
    "SHH_S3_ENDPOINT",
    "SHH_S3_ACCESS_KEY_ID",
    "SHH_S3_SECRET_ACCESS_KEY",
    "SHH_S3_MAX_TOTAL_BYTES",
    "SHH_ADMIN_TOKEN",
];
const LOCAL_VARS: &[&str] = &["SHH_LOCAL_PATH", "SHH_LOCAL_MAX_TOTAL_BYTES"];
const S3_VARS: &[&str] = &[
    "SHH_S3_BUCKET",
    "SHH_S3_REGION",
    "SHH_S3_ENDPOINT",
    "SHH_S3_ACCESS_KEY_ID",
    "SHH_S3_SECRET_ACCESS_KEY",
    "SHH_S3_MAX_TOTAL_BYTES",
];

#[derive(Debug)]
pub struct Config {
    pub env: AppEnv,
    pub debug: bool,
    pub url: String,
    pub api_routing: ApiRouting,
    pub api_url: String,
    pub secret_key: Secret,
    pub bind_addr: SocketAddr,
    pub log_level: LogLevel,
    // UI languages to offer. Empty: all built in.
    pub locales: Vec<String>,
    // Where visitors land whose browser asks for none of them; `None` means the first offered.
    pub default_locale: Option<String>,
    pub trusted_proxies: Vec<IpAddr>,
    pub database: Database,
    pub storage: Storage,
    // Only valid until the first admin API key exists (SPEC §8).
    pub admin_token: Option<Secret>,
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
    // Padded blobs up to this size live in the database.
    pub inline_max: u64,
    // Where larger blobs go. `None` means they are refused.
    pub external: Option<ExternalStorage>,
    // Largest padded blob the external tier accepts.
    pub external_max_object: u64,
}

#[derive(Debug)]
pub enum ExternalStorage {
    Local {
        path: PathBuf,
        max_total_bytes: u64,
    },
    S3 {
        bucket: String,
        region: String,
        endpoint: Option<String>,
        access_key_id: String,
        secret_access_key: Secret,
        max_total_bytes: u64,
    },
}

impl Storage {
    pub fn max_blob_bytes(&self) -> u64 {
        if self.external.is_some() {
            self.external_max_object
        } else {
            self.inline_max
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
    Invalid { name: String, reason: String },
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
        vars.reject_unknown()?;

        // Defaults to production so a missing value never turns on development behaviour.
        let env = vars.parse_or("SHH_ENV", AppEnv::Production)?;
        let debug = vars.parse_or("SHH_DEBUG", false)?;
        if env == AppEnv::Production && debug {
            return Err(invalid(
                "SHH_DEBUG",
                "must be false when SHH_ENV is production",
            ));
        }

        let url = vars.required("SHH_URL")?.trim_end_matches('/').to_string();
        let Some((scheme, authority)) = url.split_once("://") else {
            return Err(invalid("SHH_URL", "must start with http:// or https://"));
        };
        if !matches!(scheme, "http" | "https") {
            return Err(invalid("SHH_URL", "must start with http:// or https://"));
        }
        if authority.is_empty() || authority.contains(['/', '@', '?', '#']) {
            return Err(invalid(
                "SHH_URL",
                "must be just a scheme and host, like https://example.com",
            ));
        }

        let (api_routing, api_url) = match vars.get("SHH_API_ROUTING").unwrap_or("path") {
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
                        "SHH_API_ROUTING",
                        "subdomain needs SHH_URL to use a domain name, not an IP address",
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
            _ => return Err(invalid("SHH_API_ROUTING", "must be path or subdomain")),
        };

        let host = vars.parse_or("SHH_HOST", IpAddr::V4(Ipv4Addr::LOCALHOST))?;
        let port = vars.parse_or("SHH_PORT", 3000)?;

        let trusted_proxies: Vec<IpAddr> = match vars.get("SHH_TRUSTED_PROXIES") {
            None => Vec::new(),
            Some(list) => list
                .split(',')
                .map(|ip| ip.trim().parse())
                .collect::<Result<_, _>>()
                .map_err(|e| invalid("SHH_TRUSTED_PROXIES", e))?,
        };
        // Trusting every address would let any client fake its IP and dodge rate limits.
        if trusted_proxies.iter().any(IpAddr::is_unspecified) {
            return Err(invalid(
                "SHH_TRUSTED_PROXIES",
                "must list specific proxy addresses, never 0.0.0.0 or ::",
            ));
        }

        let mut locales: Vec<String> = Vec::new();
        for code in vars.get("SHH_LOCALES").unwrap_or_default().split(',') {
            let code = code.trim().to_ascii_lowercase();
            if !code.is_empty() && !locales.contains(&code) {
                locales.push(code);
            }
        }

        let default_locale = vars
            .get("SHH_DEFAULT_LOCALE")
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty());
        if let Some(code) = &default_locale
            && !locales.is_empty()
            && !locales.contains(code)
        {
            return Err(invalid(
                "SHH_DEFAULT_LOCALE",
                format!("{code} is not in SHH_LOCALES"),
            ));
        }

        let admin_token = match vars.get("SHH_ADMIN_TOKEN") {
            None => None,
            Some(_) => Some(vars.key("SHH_ADMIN_TOKEN")?),
        };

        Ok(Self {
            env,
            debug,
            url,
            api_routing,
            api_url,
            secret_key: vars.key("SHH_SECRET_KEY")?,
            bind_addr: SocketAddr::new(host, port),
            log_level: vars.parse_or("SHH_LOG_LEVEL", LogLevel::Error)?,
            locales,
            default_locale,
            trusted_proxies,
            database: Database::from_vars(&vars)?,
            storage: Storage::from_vars(&vars)?,
            admin_token,
        })
    }
}

impl Database {
    fn from_vars(vars: &Vars) -> Result<Self, ConfigError> {
        match vars.required("SHH_DB")? {
            "sqlite" => Ok(Self::Sqlite {
                path: vars
                    .get("SHH_SQLITE_PATH")
                    .unwrap_or("storage/shhnote.db")
                    .into(),
            }),
            "postgres" => Ok(Self::Postgres {
                host: vars.required("SHH_PG_HOST")?.to_string(),
                port: vars.parse_or("SHH_PG_PORT", 5432)?,
                database: vars.required("SHH_PG_DATABASE")?.to_string(),
                username: vars.required("SHH_PG_USERNAME")?.to_string(),
                // Local setups often have no password, so an empty one is allowed.
                password: Secret(vars.get("SHH_PG_PASSWORD").unwrap_or_default().to_string()),
            }),
            _ => Err(invalid("SHH_DB", "must be sqlite or postgres")),
        }
    }
}

impl Storage {
    fn from_vars(vars: &Vars) -> Result<Self, ConfigError> {
        let inline_max = vars.parse_or("SHH_INLINE_MAX", DEFAULT_INLINE_MAX)?;
        if inline_max < MIN_INLINE_MAX {
            return Err(invalid(
                "SHH_INLINE_MAX",
                format!("must be at least {MIN_INLINE_MAX} bytes"),
            ));
        }

        let driver = vars.get("SHH_STORAGE").unwrap_or("inline");
        let external = match driver {
            "inline" => {
                vars.reject_tier("SHH_STORAGE", LOCAL_VARS)?;
                vars.reject_tier("SHH_STORAGE", S3_VARS)?;
                None
            }
            "local" => {
                vars.reject_tier("SHH_STORAGE", S3_VARS)?;
                Some(ExternalStorage::Local {
                    path: vars.get("SHH_LOCAL_PATH").unwrap_or("storage/blobs").into(),
                    max_total_bytes: vars.positive("SHH_LOCAL_MAX_TOTAL_BYTES")?,
                })
            }
            "s3" => {
                vars.reject_tier("SHH_STORAGE", LOCAL_VARS)?;
                Some(ExternalStorage::S3 {
                    bucket: vars.required("SHH_S3_BUCKET")?.to_string(),
                    region: vars.required("SHH_S3_REGION")?.to_string(),
                    endpoint: vars.get("SHH_S3_ENDPOINT").map(str::to_string),
                    access_key_id: vars.required("SHH_S3_ACCESS_KEY_ID")?.to_string(),
                    secret_access_key: Secret(
                        vars.required("SHH_S3_SECRET_ACCESS_KEY")?.to_string(),
                    ),
                    max_total_bytes: vars.positive("SHH_S3_MAX_TOTAL_BYTES")?,
                })
            }
            _ => return Err(invalid("SHH_STORAGE", "must be inline, local or s3")),
        };

        let external_max_object = match (&external, vars.get("SHH_EXTERNAL_MAX_OBJECT")) {
            (None, Some(_)) => {
                return Err(invalid(
                    "SHH_EXTERNAL_MAX_OBJECT",
                    "only applies when SHH_STORAGE is local or s3",
                ));
            }
            (None, None) => inline_max,
            (Some(_), _) => {
                let max = vars.parse_or("SHH_EXTERNAL_MAX_OBJECT", DEFAULT_EXTERNAL_MAX_OBJECT)?;
                if max < inline_max {
                    return Err(invalid(
                        "SHH_EXTERNAL_MAX_OBJECT",
                        "must be at least SHH_INLINE_MAX",
                    ));
                }
                max
            }
        };

        Ok(Self {
            inline_max,
            external,
            external_max_object,
        })
    }
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

fn invalid(name: impl Into<String>, reason: impl fmt::Display) -> ConfigError {
    ConfigError::Invalid {
        name: name.into(),
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

    fn positive(&self, name: &'static str) -> Result<u64, ConfigError> {
        let value: u64 = self.required(name)?.parse().map_err(|e| invalid(name, e))?;
        if value == 0 {
            return Err(invalid(name, "must be greater than 0"));
        }
        Ok(value)
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

    fn reject_unknown(&self) -> Result<(), ConfigError> {
        let mut unknown: Vec<&str> = self
            .0
            .keys()
            .map(String::as_str)
            .filter(|k| k.starts_with(PREFIX) && !KNOWN.contains(k))
            .collect();
        unknown.sort_unstable();
        match unknown.first() {
            None => Ok(()),
            Some(name) => Err(invalid(*name, "unknown variable (check for a typo)")),
        }
    }

    // A variable for a tier that isn't enabled is almost always a mistake in the deployment.
    fn reject_tier(&self, driver: &str, names: &[&'static str]) -> Result<(), ConfigError> {
        match names.iter().find(|name| self.get(name).is_some()) {
            None => Ok(()),
            Some(name) => Err(invalid(
                *name,
                format!("set, but {driver} does not enable that tier"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_vars() -> HashMap<String, String> {
        [
            ("SHH_ENV", "local"),
            ("SHH_URL", "http://localhost:3000/"),
            ("SHH_SECRET_KEY", "s".repeat(44).as_str()),
            ("SHH_DB", "sqlite"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    #[test]
    fn locales_are_trimmed_lowercased_and_deduplicated() {
        let config = Config::from_vars(&with(&[("SHH_LOCALES", " de, EN ,de")])).unwrap();
        assert_eq!(config.locales, vec!["de", "en"]);
        assert!(Config::from_vars(&with(&[])).unwrap().locales.is_empty());
        let config = Config::from_vars(&with(&[
            ("SHH_LOCALES", "en,de"),
            ("SHH_DEFAULT_LOCALE", "DE"),
        ]))
        .unwrap();
        assert_eq!(config.default_locale.as_deref(), Some("de"));
        assert_eq!(
            invalid_name(Config::from_vars(&with(&[
                ("SHH_LOCALES", "de"),
                ("SHH_DEFAULT_LOCALE", "en")
            ]))),
            "SHH_DEFAULT_LOCALE"
        );
    }

    fn with(changes: &[(&str, &str)]) -> HashMap<String, String> {
        let mut vars = valid_vars();
        for (k, v) in changes {
            vars.insert(k.to_string(), v.to_string());
        }
        vars
    }

    fn s3_vars() -> Vec<(&'static str, &'static str)> {
        vec![
            ("SHH_STORAGE", "s3"),
            ("SHH_S3_BUCKET", "shhnote"),
            ("SHH_S3_REGION", "us-east-1"),
            ("SHH_S3_ACCESS_KEY_ID", "id"),
            ("SHH_S3_SECRET_ACCESS_KEY", "secret"),
            ("SHH_S3_MAX_TOTAL_BYTES", "10000000000"),
        ]
    }

    fn invalid_name(result: Result<Config, ConfigError>) -> String {
        match result {
            Err(ConfigError::Invalid { name, .. }) => name,
            other => panic!("expected an invalid-value error, got {other:?}"),
        }
    }

    #[test]
    fn applies_defaults() {
        let config = Config::from_vars(&valid_vars()).unwrap();
        assert_eq!(config.url, "http://localhost:3000");
        assert_eq!(config.bind_addr, "127.0.0.1:3000".parse().unwrap());
        assert_eq!(config.log_level, LogLevel::Error);
        assert!(config.trusted_proxies.is_empty());
        assert_eq!(config.storage.inline_max, DEFAULT_INLINE_MAX);
        assert!(config.storage.external.is_none());
        assert_eq!(config.storage.max_blob_bytes(), DEFAULT_INLINE_MAX);
        assert!(config.admin_token.is_none());
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
            ("SHH_ENV", "production"),
            ("SHH_URL", "https://Example.com:8443"),
            ("SHH_API_ROUTING", "subdomain"),
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
        let vars = with(&[("SHH_API_ROUTING", "subdomain")]);
        assert_eq!(
            Config::from_vars(&vars).unwrap().api_routing,
            ApiRouting::Path
        );
    }

    #[test]
    fn api_subdomain_needs_a_domain_name() {
        let vars = with(&[
            ("SHH_ENV", "production"),
            ("SHH_URL", "http://127.0.0.1:3000"),
            ("SHH_API_ROUTING", "subdomain"),
        ]);
        assert_eq!(invalid_name(Config::from_vars(&vars)), "SHH_API_ROUTING");
    }

    #[test]
    fn rejects_app_url_with_path() {
        let vars = with(&[("SHH_URL", "https://example.com/app")]);
        assert_eq!(invalid_name(Config::from_vars(&vars)), "SHH_URL");
    }

    #[test]
    fn defaults_to_production() {
        let mut vars = valid_vars();
        vars.remove("SHH_ENV");
        assert_eq!(Config::from_vars(&vars).unwrap().env, AppEnv::Production);
    }

    #[test]
    fn rejects_debug_in_production() {
        let vars = with(&[("SHH_ENV", "production"), ("SHH_DEBUG", "true")]);
        assert_eq!(invalid_name(Config::from_vars(&vars)), "SHH_DEBUG");
    }

    #[test]
    fn rejects_missing_or_short_secrets() {
        let vars = with(&[("SHH_SECRET_KEY", "")]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Missing("SHH_SECRET_KEY"))
        ));

        let vars = with(&[("SHH_ADMIN_TOKEN", "changeme")]);
        assert_eq!(invalid_name(Config::from_vars(&vars)), "SHH_ADMIN_TOKEN");
    }

    #[test]
    fn rejects_unknown_prefixed_variables() {
        let vars = with(&[("SHH_PROT", "3000")]);
        assert_eq!(invalid_name(Config::from_vars(&vars)), "SHH_PROT");

        // Other programs' variables are none of our business.
        let vars = with(&[("PATH", "/usr/bin")]);
        assert!(Config::from_vars(&vars).is_ok());
    }

    #[test]
    fn rejects_variables_for_a_disabled_tier() {
        let vars = with(&[("SHH_S3_BUCKET", "shhnote")]);
        assert_eq!(invalid_name(Config::from_vars(&vars)), "SHH_S3_BUCKET");

        let vars = with(&[("SHH_EXTERNAL_MAX_OBJECT", "1000000")]);
        assert_eq!(
            invalid_name(Config::from_vars(&vars)),
            "SHH_EXTERNAL_MAX_OBJECT"
        );

        let mut changes = s3_vars();
        changes.push(("SHH_LOCAL_PATH", "/tmp"));
        assert_eq!(
            invalid_name(Config::from_vars(&with(&changes))),
            "SHH_LOCAL_PATH"
        );
    }

    #[test]
    fn rejects_trust_all_proxies() {
        let vars = with(&[("SHH_TRUSTED_PROXIES", "10.0.0.1, 0.0.0.0")]);
        assert_eq!(
            invalid_name(Config::from_vars(&vars)),
            "SHH_TRUSTED_PROXIES"
        );

        let vars = with(&[("SHH_TRUSTED_PROXIES", "10.0.0.1, ::1")]);
        assert_eq!(Config::from_vars(&vars).unwrap().trusted_proxies.len(), 2);
    }

    #[test]
    fn postgres_requires_connection_details() {
        let vars = with(&[("SHH_DB", "postgres"), ("SHH_PG_HOST", "127.0.0.1")]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Missing("SHH_PG_DATABASE"))
        ));
    }

    #[test]
    fn external_tiers_need_a_total_ceiling() {
        let vars = with(&[("SHH_STORAGE", "local")]);
        assert!(matches!(
            Config::from_vars(&vars),
            Err(ConfigError::Missing("SHH_LOCAL_MAX_TOTAL_BYTES"))
        ));

        let config = Config::from_vars(&with(&s3_vars())).unwrap();
        assert_eq!(config.storage.max_blob_bytes(), DEFAULT_EXTERNAL_MAX_OBJECT);
    }

    #[test]
    fn external_max_object_must_cover_inline_max() {
        let mut changes = s3_vars();
        changes.push(("SHH_EXTERNAL_MAX_OBJECT", "1000000"));
        assert_eq!(
            invalid_name(Config::from_vars(&with(&changes))),
            "SHH_EXTERNAL_MAX_OBJECT"
        );
    }

    #[test]
    fn inline_max_has_a_floor() {
        let vars = with(&[("SHH_INLINE_MAX", "1000")]);
        assert_eq!(invalid_name(Config::from_vars(&vars)), "SHH_INLINE_MAX");
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let config = Config::from_vars(&valid_vars()).unwrap();
        let output = format!("{config:?}");
        assert!(!output.contains(&"s".repeat(44)));
        assert!(output.contains("[redacted]"));
    }
}
