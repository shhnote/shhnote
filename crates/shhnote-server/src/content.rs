use std::collections::HashMap;

use pulldown_cmark::{Options, Parser, html};

use crate::i18n::DEFAULT_LOCALE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Doc {
    Terms,
    Privacy,
    Security,
    HowItWorksSimple,
    HowItWorksTechnical,
}

// Compiled into the binary. Only our own files go here: Markdown can contain raw HTML,
// which is passed through to the page unescaped.
const SOURCES: &[(&str, Doc, &str)] = &[
    ("en", Doc::Terms, include_str!("../content/en/terms.md")),
    ("en", Doc::Privacy, include_str!("../content/en/privacy.md")),
    (
        "en",
        Doc::Security,
        include_str!("../content/en/security.md"),
    ),
    (
        "en",
        Doc::HowItWorksSimple,
        include_str!("../content/en/how-it-works-simple.md"),
    ),
    (
        "en",
        Doc::HowItWorksTechnical,
        include_str!("../content/en/how-it-works-technical.md"),
    ),
    ("de", Doc::Terms, include_str!("../content/de/terms.md")),
    ("de", Doc::Privacy, include_str!("../content/de/privacy.md")),
    (
        "de",
        Doc::Security,
        include_str!("../content/de/security.md"),
    ),
    (
        "de",
        Doc::HowItWorksSimple,
        include_str!("../content/de/how-it-works-simple.md"),
    ),
    (
        "de",
        Doc::HowItWorksTechnical,
        include_str!("../content/de/how-it-works-technical.md"),
    ),
];

// Markdown is turned into HTML once at startup rather than on every request.
pub struct Content {
    pages: HashMap<(&'static str, Doc), String>,
}

impl Content {
    pub fn load() -> Self {
        let pages = SOURCES
            .iter()
            .map(|&(locale, doc, markdown)| ((locale, doc), to_html(markdown)))
            .collect();
        Self { pages }
    }

    pub fn get(&self, locale: &'static str, doc: Doc) -> &str {
        self.pages
            .get(&(locale, doc))
            .or_else(|| self.pages.get(&(DEFAULT_LOCALE, doc)))
            .map_or("", String::as_str)
    }
}

fn to_html(markdown: &str) -> String {
    let parser = Parser::new_ext(
        markdown,
        Options::ENABLE_TABLES | Options::ENABLE_SMART_PUNCTUATION,
    );
    let mut out = String::new();
    html::push_html(&mut out, parser);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::LOCALES;

    #[test]
    fn every_locale_has_every_doc() {
        let all = [
            Doc::Terms,
            Doc::Privacy,
            Doc::Security,
            Doc::HowItWorksSimple,
            Doc::HowItWorksTechnical,
        ];
        let content = Content::load();
        for locale in LOCALES {
            for doc in all {
                assert!(
                    content.pages.contains_key(&(*locale, doc)),
                    "{locale} is missing {doc:?}"
                );
            }
        }
    }
}
