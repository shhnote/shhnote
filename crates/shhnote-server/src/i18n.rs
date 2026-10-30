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

// What an instance offers (`SHH_LOCALES`) and where unmatched visitors land
// (`SHH_DEFAULT_LOCALE`, otherwise the first offered), as entries of the built-in list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offered {
    pub locales: Vec<&'static str>,
    pub default: &'static str,
}

pub fn offered(wanted: &[String], default: Option<&str>) -> Result<Offered, String> {
    let builtin = |code: &str| {
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
    };
    let locales: Vec<&'static str> = if wanted.is_empty() {
        LOCALES.to_vec()
    } else {
        wanted
            .iter()
            .map(|code| builtin(code))
            .collect::<Result<_, _>>()?
    };
    let default = match default {
        Some(code) => builtin(code)?,
        None => locales[0],
    };
    if !locales.contains(&default) {
        return Err(format!("SHH_DEFAULT_LOCALE: {default} is not offered"));
    }
    Ok(Offered { locales, default })
}

// Picks the best offered locale from an `Accept-Language` header like `de-CH,de;q=0.9,en;q=0.8`.
pub fn negotiate(accept_language: Option<&str>, offered: &Offered) -> &'static str {
    let mut best: Option<(&'static str, f32)> = None;
    for part in accept_language.unwrap_or_default().split(',') {
        let mut pieces = part.split(';');
        let tag = pieces.next().unwrap_or_default().trim();
        let quality = pieces
            .find_map(|p| p.trim().strip_prefix("q="))
            .and_then(|q| q.parse().ok())
            .unwrap_or(1.0);
        let language = tag.split('-').next().unwrap_or_default();
        let Some(&locale) = offered
            .locales
            .iter()
            .find(|l| l.eq_ignore_ascii_case(language))
        else {
            continue;
        };
        if quality > 0.0 && best.is_none_or(|(_, best_quality)| quality > best_quality) {
            best = Some((locale, quality));
        }
    }
    best.map_or(offered.default, |(locale, _)| locale)
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
        let all = offered(&[], None).unwrap();
        assert_eq!(negotiate(None, &all), "en");
        assert_eq!(negotiate(Some("de-CH,de;q=0.9,en;q=0.8"), &all), "de");
        assert_eq!(negotiate(Some("fr,en;q=0.5,de;q=0.7"), &all), "de");
        assert_eq!(negotiate(Some("fr"), &all), "en");
        assert_eq!(negotiate(Some("de;q=0"), &all), "en");
        // Only offered locales count; the default is explicit or the first offered.
        let german = offered(&["DE".to_string()], None).unwrap();
        assert_eq!(negotiate(Some("en"), &german), "de");
        let both = offered(&["en".to_string(), "de".to_string()], Some("de")).unwrap();
        assert_eq!(negotiate(None, &both), "de");
        assert!(offered(&["fr".to_string()], None).is_err());
        assert!(offered(&["de".to_string()], Some("en")).is_err());
    }
}
