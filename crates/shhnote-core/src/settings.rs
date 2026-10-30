use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

use crate::padding::PaddingPolicy;

const DAY: i64 = 86_400;
// Hard ceiling from SPEC D-7; an override above it is clamped, not honoured.
pub const MAX_TTL_CEILING: i64 = 14 * DAY;

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
    pub padding: PaddingPolicy,
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
            site_name: "shhnote".into(),
            contact_email: String::new(),
            security_email: String::new(),
            padding: PaddingPolicy::Padme {
                min: PaddingPolicy::DEFAULT_MIN,
            },
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
    pub fn with_overrides(overrides: &HashMap<String, String>) -> (Self, Vec<String>) {
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
                "contact_email" => {
                    s.contact_email = value.to_string();
                    Ok(())
                }
                "security_email" => {
                    s.security_email = value.to_string();
                    Ok(())
                }
                "padding_mode" => match value {
                    "padme" | "buckets" => {
                        padding_mode = value.to_string();
                        Ok(())
                    }
                    _ => Err("must be padme or buckets".into()),
                },
                "padding_min" => parse(value).map(|v| padding_min = v),
                "padding_ladder" => parse_list(value).map(|v| padding_ladder = v),
                "claim_window_secs" => parse(value).map(|v| s.claim_window_secs = v),
                "min_ttl_secs" => parse(value).map(|v| s.min_ttl_secs = v),
                "max_ttl_secs" => {
                    parse(value).map(|v: i64| s.max_ttl_secs = v.min(MAX_TTL_CEILING))
                }
                "default_ttl_secs" => parse(value).map(|v| s.default_ttl_secs = v),
                "ttl_presets" => parse_list(value).map(|v| s.ttl_presets = v),
                "text_max_bytes" => parse(value).map(|v| s.text_max_bytes = v),
                "files_enabled" => parse(value).map(|v| s.files_enabled = v),
                "inline_enabled" => parse(value).map(|v| s.inline_enabled = v),
                "daily_retention_days" => parse(value).map(|v| s.daily_retention_days = v),
                "rate_create_per_hour" => parse(value).map(|v| s.rate_limits.create_per_hour = v),
                "rate_reveal_per_hour" => parse(value).map(|v| s.rate_limits.reveal_per_hour = v),
                "rate_confirm_per_hour" => parse(value).map(|v| s.rate_limits.confirm_per_hour = v),
                "rate_burn_per_hour" => parse(value).map(|v| s.rate_limits.burn_per_hour = v),
                "rate_report_per_hour" => parse(value).map(|v| s.rate_limits.report_per_hour = v),
                "rate_login_per_hour" => parse(value).map(|v| s.rate_limits.login_per_hour = v),
                "rate_user_multiplier" => parse(value).map(|v| s.rate_limits.user_multiplier = v),
                "require_api_key_for_create" => {
                    parse(value).map(|v| s.require_api_key_for_create = v)
                }
                "salt_rotation_secs" => parse(value).map(|v| s.salt_rotation_secs = v),
                "regions" => serde_json::from_str(value)
                    .map(|v| s.regions = v)
                    .map_err(|e| e.to_string()),
                _ => Err("unknown setting".into()),
            };
            if let Err(reason) = result {
                warnings.push(format!("setting {key} ignored: {reason}"));
            }
        }

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
        if s.daily_retention_days == 0 || s.daily_retention_days < -1 {
            warnings
                .push("setting daily_retention_days ignored: use a positive number or -1".into());
            s.daily_retention_days = Self::default().daily_retention_days;
        }
        (s, warnings)
    }
}

impl Settings {
    // Every setting as the string an admin form or the database holds it in. The admin panel
    // stores only entries that differ from `Settings::default().as_strings()`.
    pub fn as_strings(&self) -> BTreeMap<&'static str, String> {
        let (padding_mode, padding_min, padding_ladder) = match &self.padding {
            PaddingPolicy::Padme { min } => ("padme", min.to_string(), String::new()),
            PaddingPolicy::Buckets { ladder } => (
                "buckets",
                PaddingPolicy::DEFAULT_MIN.to_string(),
                ladder
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        };
        let list = |v: &[i64]| v.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
        let r = self.rate_limits;
        BTreeMap::from([
            ("site_name", self.site_name.clone()),
            ("contact_email", self.contact_email.clone()),
            ("security_email", self.security_email.clone()),
            ("padding_mode", padding_mode.to_string()),
            ("padding_min", padding_min),
            ("padding_ladder", padding_ladder),
            ("claim_window_secs", self.claim_window_secs.to_string()),
            ("min_ttl_secs", self.min_ttl_secs.to_string()),
            ("max_ttl_secs", self.max_ttl_secs.to_string()),
            ("default_ttl_secs", self.default_ttl_secs.to_string()),
            ("ttl_presets", list(&self.ttl_presets)),
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
            ("padding_ladder", "4096, 16384"),
            ("max_ttl_secs", "99999999"),
            ("files_enabled", "maybe"),
            ("nonsense", "1"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let (s, warnings) = Settings::with_overrides(&overrides);
        assert_eq!(s.site_name, "Example");
        assert_eq!(
            s.padding,
            PaddingPolicy::Buckets {
                ladder: vec![4096, 16384]
            }
        );
        assert_eq!(s.max_ttl_secs, MAX_TTL_CEILING);
        assert!(s.files_enabled);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
    }

    #[test]
    fn string_form_round_trips() {
        let defaults = Settings::default();
        let strings: HashMap<String, String> = defaults
            .as_strings()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let (back, warnings) = Settings::with_overrides(&strings);
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
        let (s, warnings) = Settings::with_overrides(&overrides(&[("daily_retention_days", "-1")]));
        assert!(warnings.is_empty());
        assert_eq!(s.daily_retention_days, -1);
        for bad in ["0", "-2"] {
            let (s, warnings) =
                Settings::with_overrides(&overrides(&[("daily_retention_days", bad)]));
            assert_eq!(warnings.len(), 1, "{bad}");
            assert_eq!(s.daily_retention_days, 365);
        }
    }

    #[test]
    fn empty_overrides_are_the_defaults() {
        let (s, warnings) = Settings::with_overrides(&HashMap::new());
        assert_eq!(s, Settings::default());
        assert!(warnings.is_empty());
    }
}
