use std::collections::HashMap;

use fluent_bundle::{FluentArgs, FluentResource, concurrent::FluentBundle};

// Every page is served under one of these prefixes, e.g. `/en/terms`.
pub const LOCALES: &[&str] = &["en", "de"];
pub const DEFAULT_LOCALE: &str = "en";

// Compiled into the binary, so the server needs no files at runtime.
const SOURCES: &[(&str, &str)] = &[
    ("en", include_str!("../locales/en/main.ftl")),
    ("de", include_str!("../locales/de/main.ftl")),
];

pub struct I18n {
    bundles: HashMap<&'static str, FluentBundle<FluentResource>>,
}

impl I18n {
    pub fn load() -> Self {
        let bundles = SOURCES
            .iter()
            .map(|&(locale, source)| {
                // The files are built in, so a broken one is a bug to fix before shipping, not a runtime error.
                let resource =
                    FluentResource::try_new(source.to_string()).unwrap_or_else(|(_, errors)| {
                        panic!("syntax error in locales/{locale}/main.ftl: {errors:?}")
                    });
                let mut bundle = FluentBundle::new_concurrent(vec![
                    locale.parse().expect("locale is a valid language tag"),
                ]);
                // Fluent normally wraps variables in invisible direction marks, which end up as junk in HTML.
                bundle.set_use_isolating(false);
                bundle.add_resource(resource).unwrap_or_else(|e| {
                    panic!("duplicate key in locales/{locale}/main.ftl: {e:?}")
                });
                (locale, bundle)
            })
            .collect();
        Self { bundles }
    }

    // Falls back to English, then to the key itself, so a missing translation never breaks a page.
    pub fn t(&self, locale: &str, key: &str, args: Option<&FluentArgs>) -> String {
        [locale, DEFAULT_LOCALE]
            .iter()
            .find_map(|locale| {
                let bundle = self.bundles.get(locale)?;
                let pattern = bundle.get_message(key)?.value()?;
                let mut errors = Vec::new();
                Some(
                    bundle
                        .format_pattern(pattern, args, &mut errors)
                        .into_owned(),
                )
            })
            .unwrap_or_else(|| key.to_string())
    }
}

// The locales an instance offers (`SHH_LOCALES`), as entries of the built-in list.
pub fn enabled_locales(wanted: &[String]) -> Result<Vec<&'static str>, String> {
    if wanted.is_empty() {
        return Ok(LOCALES.to_vec());
    }
    wanted
        .iter()
        .map(|code| {
            LOCALES
                .iter()
                .copied()
                .find(|l| l.eq_ignore_ascii_case(code))
                .ok_or_else(|| {
                    format!(
                        "SHH_LOCALES: unknown language {code:?}; available: {}",
                        LOCALES.join(", ")
                    )
                })
        })
        .collect()
}

// Picks the best enabled locale from an `Accept-Language` header like `de-CH,de;q=0.9,en;q=0.8`;
// the first enabled locale is the fallback.
pub fn negotiate(accept_language: Option<&str>, enabled: &[&'static str]) -> &'static str {
    let mut best: Option<(&'static str, f32)> = None;
    for part in accept_language.unwrap_or_default().split(',') {
        let mut pieces = part.split(';');
        let tag = pieces.next().unwrap_or_default().trim();
        let quality = pieces
            .find_map(|p| p.trim().strip_prefix("q="))
            .and_then(|q| q.parse().ok())
            .unwrap_or(1.0);
        let language = tag.split('-').next().unwrap_or_default();
        let Some(&locale) = enabled.iter().find(|l| l.eq_ignore_ascii_case(language)) else {
            continue;
        };
        if quality > 0.0 && best.is_none_or(|(_, best_quality)| quality > best_quality) {
            best = Some((locale, quality));
        }
    }
    best.map_or(
        enabled.first().copied().unwrap_or(DEFAULT_LOCALE),
        |(locale, _)| locale,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn keys(source: &str) -> BTreeSet<&str> {
        source
            .lines()
            .filter(|line| line.starts_with(|c: char| c.is_ascii_lowercase() || c == '-'))
            .filter_map(|line| line.split_once('=').map(|(key, _)| key.trim()))
            .collect()
    }

    #[test]
    fn all_locales_have_the_same_keys() {
        let (_, english) = SOURCES[0];
        for &(locale, source) in &SOURCES[1..] {
            assert_eq!(keys(english), keys(source), "keys differ in {locale}");
        }
    }

    #[test]
    fn loads_and_translates() {
        let i18n = I18n::load();
        assert_eq!(i18n.t("de", "language-name", None), "Deutsch");
        assert_eq!(i18n.t("en", "no-such-key", None), "no-such-key");
    }

    #[test]
    fn negotiates_locale() {
        assert_eq!(negotiate(None, LOCALES), "en");
        assert_eq!(negotiate(Some("de-CH,de;q=0.9,en;q=0.8"), LOCALES), "de");
        assert_eq!(negotiate(Some("fr,en;q=0.5,de;q=0.7"), LOCALES), "de");
        assert_eq!(negotiate(Some("fr"), LOCALES), "en");
        assert_eq!(negotiate(Some("de;q=0"), LOCALES), "en");
        // Only enabled locales count, and the first one is the fallback.
        assert_eq!(negotiate(Some("en"), &["de"]), "de");
        assert_eq!(negotiate(None, &["de", "en"]), "de");
        assert_eq!(enabled_locales(&[]).unwrap(), LOCALES);
        assert_eq!(enabled_locales(&["DE".to_string()]).unwrap(), vec!["de"]);
        assert!(enabled_locales(&["fr".to_string()]).is_err());
    }
}
