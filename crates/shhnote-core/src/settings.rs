use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::padding::PaddingPolicy;

const DAY: i64 = 86_400;
// Hard ceiling from SPEC D-7; an override above it is clamped, not honoured.
pub const MAX_TTL_CEILING: i64 = 14 * DAY;

// Runtime settings (SPEC §7.2). Every field has a code default; the database stores only
// values an admin changed, as strings keyed by the field name.
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
    pub regions: Vec<Region>,
    pub daily_retention_days: i64,
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
            regions: Vec::new(),
            daily_retention_days: 365,
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
                "daily_retention_days" => parse(value).map(|v| s.daily_retention_days = v),
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
        (s, warnings)
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
    fn empty_overrides_are_the_defaults() {
        let (s, warnings) = Settings::with_overrides(&HashMap::new());
        assert_eq!(s, Settings::default());
        assert!(warnings.is_empty());
    }
}
