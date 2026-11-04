use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

use crate::{config::AppEnv, padding::PaddingPolicy};

const DAY: i64 = 86_400;
// Hard ceiling from SPEC D-7; an override above it is refused, not clamped.
pub const MAX_TTL_CEILING: i64 = 14 * DAY;
// Bounds for the numeric settings (SPEC §7.2). A value outside them is refused, so the
// arithmetic that uses it can never overflow and no policy can be switched off by a typo.
const MIN_TTL_FLOOR: i64 = 60;
const CLAIM_WINDOW_RANGE: std::ops::RangeInclusive<i64> = 60..=DAY;
const SALT_ROTATION_RANGE: std::ops::RangeInclusive<i64> = 60..=DAY;
const RETENTION_MAX_DAYS: i64 = 36_500;

// The seconds a duration setting accepts, for forms that offer a choice of durations (the
// admin panel). `None` for settings that are not durations.
pub fn duration_range(key: &str) -> Option<std::ops::RangeInclusive<i64>> {
    match key {
        "min_ttl_secs" | "max_ttl_secs" | "default_ttl_secs" | "ttl_presets" => {
            Some(MIN_TTL_FLOOR..=MAX_TTL_CEILING)
        }
        "claim_window_secs" => Some(CLAIM_WINDOW_RANGE),
        "salt_rotation_secs" => Some(SALT_ROTATION_RANGE),
        _ => None,
    }
}
const TEXT_MAX_RANGE: std::ops::RangeInclusive<u64> = 1..=(1024 * 1024);
const RATE_MAX_PER_HOUR: u32 = 1_000_000;
const MULTIPLIER_RANGE: std::ops::RangeInclusive<u32> = 1..=1000;

// Runtime settings (SPEC §7.2). Every field has a code default; the database stores only
// values an admin changed, as strings keyed by the field name.
// Requests per hour per client for each API operation; 0 disables that limit. `user_multiplier`
// scales them for requests carrying a `user` API key. Best-effort by principle 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    pub create_per_hour: u32,
    pub reveal_per_hour: u32,
    pub confirm_per_hour: u32,
    pub burn_per_hour: u32,
    pub report_per_hour: u32,
    // Admin login attempts.
    pub login_per_hour: u32,
    pub user_multiplier: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            create_per_hour: 30,
            reveal_per_hour: 60,
            confirm_per_hour: 60,
            burn_per_hour: 30,
            report_per_hour: 10,
            login_per_hour: 20,
            user_multiplier: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub site_name: String,
    pub contact_email: String,
    pub security_email: String,
    // Link to the running code, shown in the footer; empty hides it.
    pub source_url: String,
    // The project's own page (a fork's site, say), shown in the footer next to the source
    // link; empty hides it. Content pages fall back to `source_url` for `{{project_url}}`.
    pub project_url: String,
    pub padding: PaddingPolicy,
    // Padmé's floor as last set, kept while the ladder is in use, so switching back to padme
    // restores it instead of silently resetting it (SPEC §6.2).
    pub padding_min: u64,
    // The ladder as last set, kept the same way while Padmé is in use.
    pub padding_ladder: Vec<u64>,
    pub claim_window_secs: i64,
    pub min_ttl_secs: i64,
    pub max_ttl_secs: i64,
    pub default_ttl_secs: i64,
    pub ttl_presets: Vec<i64>,
    pub text_max_bytes: u64,
    pub files_enabled: bool,
    // When false, every blob goes to the external tier; needs `SHH_STORAGE` to enable one.
    pub inline_enabled: bool,
    pub regions: Vec<Region>,
    // Origins other than this site whose frontends may call the API from a browser (D-26):
    // scheme and host, optional port, nothing else. Empty means the site origin only.
    pub allowed_origins: Vec<String>,
    // Days kept at daily resolution before folding into the year; -1 never folds.
    pub daily_retention_days: i64,
    pub rate_limits: RateLimits,
    pub salt_rotation_secs: i64,
    // When true, only requests with a `user` API key may create secrets (private instances).
    pub require_api_key_for_create: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    pub code: String,
    pub name: String,
    pub url: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            // No default: the operator names the site during setup (D-29).
            site_name: String::new(),
            contact_email: String::new(),
            security_email: String::new(),
            source_url: "https://github.com/shhnote/shhnote".into(),
            project_url: String::new(),
            padding: PaddingPolicy::Padme {
                min: PaddingPolicy::DEFAULT_MIN,
            },
            padding_min: PaddingPolicy::DEFAULT_MIN,
            padding_ladder: Vec::new(),
            claim_window_secs: 15 * 60,
            min_ttl_secs: 60,
            max_ttl_secs: MAX_TTL_CEILING,
            default_ttl_secs: DAY,
            ttl_presets: vec![
                15 * 60,
                30 * 60,
                3600,
                6 * 3600,
                12 * 3600,
                DAY,
                3 * DAY,
                7 * DAY,
                14 * DAY,
            ],
            text_max_bytes: 64 * 1024,
            files_enabled: true,
            inline_enabled: true,
            regions: Vec::new(),
            allowed_origins: Vec::new(),
            daily_retention_days: 365,
            rate_limits: RateLimits::default(),
            salt_rotation_secs: 3600,
            require_api_key_for_create: false,
        }
    }
}

impl Settings {
    // Applies database overrides on top of the defaults. An invalid value is reported and
    // skipped rather than failing startup (SPEC §7.2).
    // `env` decides the URL rule: links rendered into pages must be `https://`, except on a
    // local instance, where `http://` is how the pages themselves are served (SPEC §7.2).
    pub fn with_overrides(overrides: &HashMap<String, String>, env: AppEnv) -> (Self, Vec<String>) {
        let allow_http = env == AppEnv::Local;
        let mut s = Self::default();
        let mut warnings = Vec::new();
        let mut padding_mode = "padme".to_string();
        let mut padding_min = PaddingPolicy::DEFAULT_MIN;
        let mut padding_ladder: Vec<u64> = Vec::new();

        for (key, value) in overrides {
            let value = value.trim();
            let result: Result<(), String> = match key.as_str() {
                "site_name" => {
                    s.site_name = value.to_string();
                    Ok(())
                }
                "contact_email" => email(value).map(|v| s.contact_email = v),
                "source_url" => web_url(value, allow_http).map(|v| s.source_url = v),
                "project_url" => web_url(value, allow_http).map(|v| s.project_url = v),
                "security_email" => email(value).map(|v| s.security_email = v),
                "padding_mode" => match value {
                    "padme" | "buckets" => {
                        padding_mode = value.to_string();
                        Ok(())
                    }
                    _ => Err("must be padme or buckets".into()),
                },
                // D-6: 64 KiB is a floor the instance may raise, never lower.
                "padding_min" => parse(value)
                    .and_then(|v: u64| at_least(v, PaddingPolicy::DEFAULT_MIN))
                    .map(|v| padding_min = v),
                "padding_ladder" => parse_list(value)
                    .and_then(ladder)
                    .map(|v| padding_ladder = v),
                "claim_window_secs" => parse(value)
                    .and_then(|v| within(v, CLAIM_WINDOW_RANGE))
                    .map(|v| s.claim_window_secs = v),
                "min_ttl_secs" => parse(value)
                    .and_then(|v: i64| at_least(v, MIN_TTL_FLOOR))
                    .map(|v| s.min_ttl_secs = v),
                "max_ttl_secs" => parse(value)
                    .and_then(|v| within(v, MIN_TTL_FLOOR..=MAX_TTL_CEILING))
                    .map(|v| s.max_ttl_secs = v),
                "default_ttl_secs" => parse(value)
                    .and_then(|v: i64| at_least(v, MIN_TTL_FLOOR))
                    .map(|v| s.default_ttl_secs = v),
                "ttl_presets" => parse_list(value)
                    .and_then(|v: Vec<i64>| {
                        v.iter()
                            .try_for_each(|&p| {
                                within(p, MIN_TTL_FLOOR..=MAX_TTL_CEILING).map(|_| ())
                            })
                            .map(|()| v)
                    })
                    .map(|v| s.ttl_presets = v),
                "text_max_bytes" => parse(value)
                    .and_then(|v| within(v, TEXT_MAX_RANGE))
                    .map(|v| s.text_max_bytes = v),
                "files_enabled" => parse(value).map(|v| s.files_enabled = v),
                "inline_enabled" => parse(value).map(|v| s.inline_enabled = v),
                "daily_retention_days" => parse(value)
                    .and_then(|v: i64| {
                        if v == -1 {
                            Ok(v)
                        } else {
                            within(v, 1..=RETENTION_MAX_DAYS)
                        }
                    })
                    .map(|v| s.daily_retention_days = v),
                "rate_create_per_hour" => rate(value).map(|v| s.rate_limits.create_per_hour = v),
                "rate_reveal_per_hour" => rate(value).map(|v| s.rate_limits.reveal_per_hour = v),
                "rate_confirm_per_hour" => rate(value).map(|v| s.rate_limits.confirm_per_hour = v),
                "rate_burn_per_hour" => rate(value).map(|v| s.rate_limits.burn_per_hour = v),
                "rate_report_per_hour" => rate(value).map(|v| s.rate_limits.report_per_hour = v),
                "rate_login_per_hour" => rate(value).map(|v| s.rate_limits.login_per_hour = v),
                "rate_user_multiplier" => parse(value)
                    .and_then(|v| within(v, MULTIPLIER_RANGE))
                    .map(|v| s.rate_limits.user_multiplier = v),
                "require_api_key_for_create" => {
                    parse(value).map(|v| s.require_api_key_for_create = v)
                }
                "salt_rotation_secs" => parse(value)
                    .and_then(|v| within(v, SALT_ROTATION_RANGE))
                    .map(|v| s.salt_rotation_secs = v),
                "regions" => serde_json::from_str(value)
                    .map_err(|e| e.to_string())
                    .and_then(|v| regions(v, allow_http))
                    .map(|v| s.regions = v),
                "allowed_origins" => origins(value, allow_http).map(|v| s.allowed_origins = v),
                _ => Err("unknown setting".into()),
            };
            if let Err(reason) = result {
                warnings.push(format!("setting {key} ignored: {reason}"));
            }
        }

        s.padding_min = padding_min;
        s.padding_ladder = padding_ladder.clone();
        s.padding = match padding_mode.as_str() {
            "buckets" if !padding_ladder.is_empty() => PaddingPolicy::Buckets {
                ladder: padding_ladder,
            },
            "buckets" => {
                warnings.push("setting padding_mode ignored: buckets needs padding_ladder".into());
                PaddingPolicy::Padme { min: padding_min }
            }
            _ => PaddingPolicy::Padme { min: padding_min },
        };
        if s.min_ttl_secs > s.max_ttl_secs
            || !(s.min_ttl_secs..=s.max_ttl_secs).contains(&s.default_ttl_secs)
        {
            warnings.push("ttl settings inconsistent: using defaults".into());
            let d = Self::default();
            s.min_ttl_secs = d.min_ttl_secs;
            s.max_ttl_secs = d.max_ttl_secs;
            s.default_ttl_secs = d.default_ttl_secs;
        }
        let ttl_range = s.min_ttl_secs..=s.max_ttl_secs;
        if s.ttl_presets.iter().any(|p| !ttl_range.contains(p)) {
            warnings.push("setting ttl_presets ignored: a preset is outside min/max TTL".into());
            s.ttl_presets = Self::default().ttl_presets;
        }
        (s, warnings)
    }
}

impl Settings {
    // Every setting as the string an admin form or the database holds it in. The admin panel
    // stores only entries that differ from `Settings::default().as_strings()`.
    // The address for security reports: the dedicated one, or the contact address while none
    // is set, so one address serves everywhere (D-29).
    pub fn security_email(&self) -> &str {
        if self.security_email.is_empty() {
            &self.contact_email
        } else {
            &self.security_email
        }
    }

    // The padded sizes a policy can produce, the ladder's rungs and `padding_min`, are checked
    // against the largest padded size this instance stores (SPEC §6.2): a bigger one could
    // never be uploaded. The limit comes from the environment and the configured tiers, which
    // the overrides alone do not know, so this runs after them. A value over it falls back,
    // like any invalid value: the minimum to its default, a ladder to Padmé. The reasons are
    // returned, so a save can refuse them and a start can log them.
    pub fn check_blob_limit(&mut self, max_blob_bytes: u64) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.padding_min > max_blob_bytes {
            reasons.push(format!(
                "setting padding_min ignored: {} is above the largest blob this instance stores ({max_blob_bytes} bytes)",
                self.padding_min
            ));
            self.padding_min = PaddingPolicy::DEFAULT_MIN;
            if let PaddingPolicy::Padme { min } = &mut self.padding {
                *min = PaddingPolicy::DEFAULT_MIN;
            }
        }
        if let PaddingPolicy::Buckets { ladder } = &self.padding
            && let Some(largest) = ladder.iter().copied().max()
            && largest > max_blob_bytes
        {
            self.padding = PaddingPolicy::Padme {
                min: self.padding_min,
            };
            reasons.push(format!(
                "setting padding_ladder ignored: {largest} is above the largest blob this instance stores ({max_blob_bytes} bytes)"
            ));
        }
        reasons
    }

    pub fn as_strings(&self) -> BTreeMap<&'static str, String> {
        let sizes = |v: &[u64]| v.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        // The setting that is not in use is written too, so a save never drops it.
        let (padding_mode, padding_min, padding_ladder) = match &self.padding {
            PaddingPolicy::Padme { min } => ("padme", min.to_string(), sizes(&self.padding_ladder)),
            PaddingPolicy::Buckets { ladder } => {
                ("buckets", self.padding_min.to_string(), sizes(ladder))
            }
        };
        let list = |v: &[i64]| v.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
        let r = self.rate_limits;
        BTreeMap::from([
            ("site_name", self.site_name.clone()),
            ("contact_email", self.contact_email.clone()),
            ("security_email", self.security_email.clone()),
            ("source_url", self.source_url.clone()),
            ("project_url", self.project_url.clone()),
            ("padding_mode", padding_mode.to_string()),
            ("padding_min", padding_min),
            ("padding_ladder", padding_ladder),
            ("claim_window_secs", self.claim_window_secs.to_string()),
            ("min_ttl_secs", self.min_ttl_secs.to_string()),
            ("max_ttl_secs", self.max_ttl_secs.to_string()),
            ("default_ttl_secs", self.default_ttl_secs.to_string()),
            ("ttl_presets", list(&self.ttl_presets)),
            ("allowed_origins", self.allowed_origins.join(",")),
            ("text_max_bytes", self.text_max_bytes.to_string()),
            ("files_enabled", self.files_enabled.to_string()),
            ("inline_enabled", self.inline_enabled.to_string()),
            (
                "regions",
                serde_json::to_string(&self.regions).unwrap_or_default(),
            ),
            (
                "daily_retention_days",
                self.daily_retention_days.to_string(),
            ),
            ("rate_create_per_hour", r.create_per_hour.to_string()),
            ("rate_reveal_per_hour", r.reveal_per_hour.to_string()),
            ("rate_confirm_per_hour", r.confirm_per_hour.to_string()),
            ("rate_burn_per_hour", r.burn_per_hour.to_string()),
            ("rate_report_per_hour", r.report_per_hour.to_string()),
            ("rate_login_per_hour", r.login_per_hour.to_string()),
            ("rate_user_multiplier", r.user_multiplier.to_string()),
            ("salt_rotation_secs", self.salt_rotation_secs.to_string()),
            (
                "require_api_key_for_create",
                self.require_api_key_for_create.to_string(),
            ),
        ])
    }
}

// The live settings, swapped atomically when an admin saves. Readers get a cheap `Arc`
// snapshot, so a request never sees a half-updated set.
pub struct SettingsCell(RwLock<Arc<Settings>>);

impl SettingsCell {
    pub fn new(settings: Settings) -> Self {
        Self(RwLock::new(Arc::new(settings)))
    }

    pub fn load(&self) -> Arc<Settings> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn store(&self, settings: Settings) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(settings);
    }
}

fn parse<T: std::str::FromStr>(value: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    value.parse().map_err(|e: T::Err| e.to_string())
}

fn within<T: PartialOrd + std::fmt::Display>(
    value: T,
    range: std::ops::RangeInclusive<T>,
) -> Result<T, String> {
    if range.contains(&value) {
        Ok(value)
    } else {
        Err(format!(
            "must be between {} and {}",
            range.start(),
            range.end()
        ))
    }
}

fn at_least<T: PartialOrd + std::fmt::Display>(value: T, floor: T) -> Result<T, String> {
    if value >= floor {
        Ok(value)
    } else {
        Err(format!("must be at least {floor}"))
    }
}

fn rate(value: &str) -> Result<u32, String> {
    parse(value).and_then(|v| within(v, 0..=RATE_MAX_PER_HOUR))
}

// A ladder is strictly increasing and never below the 64 KiB floor (D-6).
fn ladder(entries: Vec<u64>) -> Result<Vec<u64>, String> {
    let ordered = entries.windows(2).all(|w| w[0] < w[1]);
    let floored = entries
        .first()
        .is_none_or(|&first| first >= PaddingPolicy::DEFAULT_MIN);
    if ordered && floored {
        Ok(entries)
    } else {
        Err(format!(
            "must be strictly increasing, starting at {} or above",
            PaddingPolicy::DEFAULT_MIN
        ))
    }
}

// Links rendered into pages: an https URL or nothing; plain http only on a local instance.
fn web_url(value: &str, allow_http: bool) -> Result<String, String> {
    let value = value.trim();
    let ok = value.is_empty()
        || value.starts_with("https://")
        || (allow_http && value.starts_with("http://"));
    if ok {
        Ok(value.to_string())
    } else if allow_http {
        Err("must be a web URL".into())
    } else {
        Err("must be an https:// URL".into())
    }
}

// Addresses rendered into mailto: links: nothing, or something shaped like an address.
fn email(value: &str) -> Result<String, String> {
    let value = value.trim();
    let shaped = value.contains('@')
        && !value.contains(|c: char| c.is_whitespace() || "\"<>?#/".contains(c));
    if value.is_empty() || shaped {
        Ok(value.to_string())
    } else {
        Err("must be an email address".into())
    }
}

// A comma-separated list of origins, each `scheme://host[:port]` and nothing more: no path,
// query, fragment, userinfo or wildcard. Hosts are lowercased so a browser's `Origin` header
// matches by plain comparison.
fn origins(value: &str, allow_http: bool) -> Result<Vec<String>, String> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|item| {
            let item = item.trim();
            let (scheme, rest) = item
                .split_once("://")
                .ok_or_else(|| format!("{item:?} is not an origin"))?;
            let https = scheme.eq_ignore_ascii_case("https");
            let http = scheme.eq_ignore_ascii_case("http") && allow_http;
            if !(https || http) {
                return Err(format!("{item:?}: origins must be https://"));
            }
            let (host, port) = match rest.rsplit_once(':') {
                Some((host, port)) if !host.contains(']') || host.ends_with(']') => {
                    (host, Some(port))
                }
                _ => (rest, None),
            };
            let host_ok = !host.is_empty()
                && !host.contains(['/', '?', '#', '@', '*', ' ', '\t', '"', '<', '>'])
                && !host.ends_with('.');
            let port_ok =
                port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
            if !host_ok || !port_ok {
                return Err(format!(
                    "{item:?} is not an origin (scheme and host, optional port, nothing else)"
                ));
            }
            let mut origin = format!(
                "{}://{}",
                scheme.to_ascii_lowercase(),
                host.to_ascii_lowercase()
            );
            if let Some(port) = port {
                origin.push(':');
                origin.push_str(port);
            }
            Ok(origin)
        })
        .collect()
}

fn regions(regions: Vec<Region>, allow_http: bool) -> Result<Vec<Region>, String> {
    for region in &regions {
        if region.code.trim().is_empty() || region.name.trim().is_empty() {
            return Err("every region needs a code and a name".into());
        }
        // A region is somewhere to go; an empty link would point the selector at this page.
        if region.url.trim().is_empty() {
            return Err("every region needs a URL".into());
        }
        web_url(&region.url, allow_http).map_err(|e| format!("every region URL {e}"))?;
    }
    Ok(regions)
}

fn parse_list<T: std::str::FromStr>(value: &str) -> Result<Vec<T>, String>
where
    T::Err: std::fmt::Display,
{
    // An empty value is an empty list (the admin form sends "" for an unused ladder).
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value.split(',').map(|v| parse(v.trim())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_apply_and_bad_values_warn() {
        let overrides: HashMap<String, String> = [
            ("site_name", "Example"),
            ("padding_mode", "buckets"),
            ("padding_ladder", "65536, 131072"),
            ("max_ttl_secs", "99999999"),
            ("files_enabled", "maybe"),
            ("nonsense", "1"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let (s, warnings) = Settings::with_overrides(&overrides, AppEnv::Production);
        assert_eq!(s.site_name, "Example");
        assert_eq!(
            s.padding,
            PaddingPolicy::Buckets {
                ladder: vec![65536, 131072]
            }
        );
        // Over the ceiling is refused, not clamped (D-7).
        assert_eq!(s.max_ttl_secs, MAX_TTL_CEILING);
        assert!(s.files_enabled);
        assert_eq!(warnings.len(), 3, "{warnings:?}");
    }

    // Revision 3, C3: `padding_min` survives a switch to the ladder and back, and is still
    // validated while the ladder is in use.
    #[test]
    fn padding_min_is_kept_in_buckets_mode() {
        let pairs = overrides(&[
            ("padding_mode", "buckets"),
            ("padding_ladder", "65536,131072"),
            ("padding_min", "131072"),
        ]);
        let (s, warnings) = Settings::with_overrides(&pairs, AppEnv::Production);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(matches!(s.padding, PaddingPolicy::Buckets { .. }));
        assert_eq!(s.as_strings()["padding_min"], "131072");
        // Saved and loaded again, then switched back: the floor is the one the admin set.
        let mut stored: HashMap<String, String> = s
            .as_strings()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        stored.insert("padding_mode".into(), "padme".into());
        let (back, _) = Settings::with_overrides(&stored, AppEnv::Production);
        assert_eq!(back.padding, PaddingPolicy::Padme { min: 131072 });

        let (low, warnings) = Settings::with_overrides(
            &overrides(&[
                ("padding_mode", "buckets"),
                ("padding_ladder", "65536"),
                ("padding_min", "1024"),
            ]),
            AppEnv::Production,
        );
        assert_eq!(low.padding_min, PaddingPolicy::DEFAULT_MIN);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
    }

    // The same for the ladder: saving with Padmé in use keeps it for the next switch back.
    #[test]
    fn padding_ladder_is_kept_in_padme_mode() {
        let pairs = overrides(&[
            ("padding_mode", "padme"),
            ("padding_ladder", "65536,131072"),
        ]);
        let (s, warnings) = Settings::with_overrides(&pairs, AppEnv::Production);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(s.padding, PaddingPolicy::Padme { min: 65536 });
        assert_eq!(s.as_strings()["padding_ladder"], "65536,131072");
        let mut stored: HashMap<String, String> = s
            .as_strings()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        stored.insert("padding_mode".into(), "buckets".into());
        let (back, _) = Settings::with_overrides(&stored, AppEnv::Production);
        assert_eq!(
            back.padding,
            PaddingPolicy::Buckets {
                ladder: vec![65536, 131072]
            }
        );
    }

    #[test]
    fn region_urls_cannot_be_empty() {
        let regions = r#"[{"code":"eu","name":"EU","url":""}]"#;
        let (s, warnings) =
            Settings::with_overrides(&overrides(&[("regions", regions)]), AppEnv::Local);
        assert!(s.regions.is_empty());
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("needs a URL"), "{warnings:?}");
    }

    #[test]
    fn ladder_sizes_must_fit_the_instance() {
        let pairs = overrides(&[
            ("padding_mode", "buckets"),
            ("padding_ladder", "65536,1048576"),
            ("padding_min", "131072"),
        ]);
        let (mut fits, _) = Settings::with_overrides(&pairs, AppEnv::Production);
        assert!(fits.check_blob_limit(1048576).is_empty());
        assert!(matches!(fits.padding, PaddingPolicy::Buckets { .. }));

        let (mut over, _) = Settings::with_overrides(&pairs, AppEnv::Production);
        let reasons = over.check_blob_limit(1048575);
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(reasons[0].contains("padding_ladder"), "{reasons:?}");
        // Like any invalid value it falls back, here to Padmé with the admin's floor.
        assert_eq!(over.padding, PaddingPolicy::Padme { min: 131072 });

        let mut padme = Settings::default();
        assert!(padme.check_blob_limit(65536).is_empty());
    }

    // Round 2, suspicion 4: a `padding_min` above the largest blob the instance stores would
    // make every create fail; it falls back to the default floor, in either mode.
    #[test]
    fn padding_min_must_fit_the_instance() {
        let (mut padme, _) = Settings::with_overrides(
            &overrides(&[("padding_min", "4294967296")]),
            AppEnv::Production,
        );
        let reasons = padme.check_blob_limit(2 * 1024 * 1024);
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(reasons[0].contains("padding_min"), "{reasons:?}");
        assert_eq!(padme.padding_min, PaddingPolicy::DEFAULT_MIN);
        assert_eq!(
            padme.padding,
            PaddingPolicy::Padme {
                min: PaddingPolicy::DEFAULT_MIN
            }
        );

        // In buckets mode the kept minimum is corrected too, and a ladder that is also over
        // the limit falls back to Padmé with the corrected minimum.
        let (mut buckets, _) = Settings::with_overrides(
            &overrides(&[
                ("padding_mode", "buckets"),
                ("padding_ladder", "65536,4194304"),
                ("padding_min", "4194304"),
            ]),
            AppEnv::Production,
        );
        let reasons = buckets.check_blob_limit(2 * 1024 * 1024);
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert_eq!(buckets.padding_min, PaddingPolicy::DEFAULT_MIN);
        assert_eq!(
            buckets.padding,
            PaddingPolicy::Padme {
                min: PaddingPolicy::DEFAULT_MIN
            }
        );

        let (mut fits, _) = Settings::with_overrides(
            &overrides(&[("padding_min", "2097152")]),
            AppEnv::Production,
        );
        assert!(fits.check_blob_limit(2 * 1024 * 1024).is_empty());
        assert_eq!(fits.padding_min, 2097152);
    }

    #[test]
    fn plain_http_links_only_on_a_local_instance() {
        let region = r#"[{"code":"eu","name":"EU","url":"http://eu.example"}]"#;
        for (key, value) in [
            ("source_url", "http://example.com/src"),
            ("project_url", "http://example.com/"),
            ("regions", region),
        ] {
            let (s, warnings) =
                Settings::with_overrides(&overrides(&[(key, value)]), AppEnv::Production);
            assert_eq!(warnings.len(), 1, "{key}: {warnings:?}");
            assert_eq!(s, Settings::default());
            let (_, warnings) =
                Settings::with_overrides(&overrides(&[(key, value)]), AppEnv::Local);
            assert!(warnings.is_empty(), "{key}: {warnings:?}");
            let https = value.replace("http://", "https://");
            let (_, warnings) =
                Settings::with_overrides(&overrides(&[(key, &https)]), AppEnv::Production);
            assert!(warnings.is_empty(), "{key}: {warnings:?}");
        }
    }

    #[test]
    fn allowed_origins_are_origins_only() {
        let (s, warnings) = Settings::with_overrides(
            &overrides(&[(
                "allowed_origins",
                " https://App.Example , https://app.example:8443",
            )]),
            AppEnv::Production,
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            s.allowed_origins,
            vec!["https://app.example", "https://app.example:8443"]
        );
        assert_eq!(
            s.as_strings()["allowed_origins"],
            "https://app.example,https://app.example:8443"
        );
        for bad in [
            "https://app.example/",
            "https://app.example/path",
            "https://app.example?x",
            "https://*.example",
            "*",
            "app.example",
            "javascript:alert(1)",
            "https://user@app.example",
            "https://app.example:port",
            "http://app.example",
        ] {
            let (s, warnings) = Settings::with_overrides(
                &overrides(&[("allowed_origins", bad)]),
                AppEnv::Production,
            );
            assert_eq!(warnings.len(), 1, "{bad}: {warnings:?}");
            assert!(s.allowed_origins.is_empty(), "{bad}");
        }
        let (s, warnings) = Settings::with_overrides(
            &overrides(&[("allowed_origins", "http://localhost:5173")]),
            AppEnv::Local,
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(s.allowed_origins, vec!["http://localhost:5173"]);
    }

    #[test]
    fn security_email_falls_back_to_contact() {
        let (s, _) = Settings::with_overrides(
            &overrides(&[("contact_email", "ops@example.test")]),
            AppEnv::Production,
        );
        assert_eq!(s.security_email(), "ops@example.test");
        // The stored value stays empty: the fallback is read-time only.
        assert_eq!(s.as_strings()["security_email"], "");
        let (s, _) = Settings::with_overrides(
            &overrides(&[
                ("contact_email", "ops@example.test"),
                ("security_email", "security@example.test"),
            ]),
            AppEnv::Production,
        );
        assert_eq!(s.security_email(), "security@example.test");
        assert_eq!(Settings::default().site_name, "");
    }

    #[test]
    fn out_of_range_values_are_refused() {
        for (key, value) in [
            ("padding_min", "0"),
            ("padding_min", "65535"),
            ("padding_ladder", "0,1,5"),
            ("padding_ladder", "131072,65536"),
            ("claim_window_secs", "-1"),
            ("claim_window_secs", "9223372036854775807"),
            ("min_ttl_secs", "-100"),
            ("max_ttl_secs", "2592000"),
            ("ttl_presets", "-5"),
            ("ttl_presets", "2592000"),
            ("text_max_bytes", "0"),
            ("text_max_bytes", "18446744073709551615"),
            ("rate_user_multiplier", "0"),
            ("rate_user_multiplier", "4294967295"),
            ("rate_create_per_hour", "4294967295"),
            ("salt_rotation_secs", "-1"),
            ("daily_retention_days", "0"),
            ("daily_retention_days", "9223372036854775807"),
            ("source_url", "javascript:alert(1)"),
            ("project_url", "javascript:alert(1)"),
            ("contact_email", "a@b.c\"><x"),
            (
                "regions",
                r#"[{"code":"x","name":"X","url":"javascript:alert(1)"}]"#,
            ),
        ] {
            let (s, warnings) =
                Settings::with_overrides(&overrides(&[(key, value)]), AppEnv::Production);
            assert_eq!(warnings.len(), 1, "{key}={value}: {warnings:?}");
            assert_eq!(s, Settings::default(), "{key}={value} changed something");
        }
        let (s, warnings) = Settings::with_overrides(
            &overrides(&[("ttl_presets", "900,3600")]),
            AppEnv::Production,
        );
        assert!(warnings.is_empty());
        assert_eq!(s.ttl_presets, vec![900, 3600]);
    }

    #[test]
    fn string_form_round_trips() {
        let defaults = Settings::default();
        let strings: HashMap<String, String> = defaults
            .as_strings()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let (back, warnings) = Settings::with_overrides(&strings, AppEnv::Production);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(back, defaults);
    }

    fn overrides(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn retention_accepts_minus_one_only_as_off_switch() {
        let (s, warnings) = Settings::with_overrides(
            &overrides(&[("daily_retention_days", "-1")]),
            AppEnv::Production,
        );
        assert!(warnings.is_empty());
        assert_eq!(s.daily_retention_days, -1);
        for bad in ["0", "-2"] {
            let (s, warnings) = Settings::with_overrides(
                &overrides(&[("daily_retention_days", bad)]),
                AppEnv::Production,
            );
            assert_eq!(warnings.len(), 1, "{bad}");
            assert_eq!(s.daily_retention_days, 365);
        }
    }

    #[test]
    fn empty_overrides_are_the_defaults() {
        let (s, warnings) = Settings::with_overrides(&HashMap::new(), AppEnv::Production);
        assert_eq!(s, Settings::default());
        assert!(warnings.is_empty());
    }
}
