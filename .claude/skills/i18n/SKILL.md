---
name: i18n
description: Add or change user-visible text and translations in shhnote using Fluent (.ftl files via fluent-bundle) and per-language Markdown pages. Use when writing any text shown to users in pages, emails, or API messages, or when adding a language.
---

# Translations

Two kinds of translated text, both compiled into the server binary:

- **UI text** (labels, buttons, short paragraphs): Fluent messages in `crates/shhnote-server/locales/<lang>/main.ftl`, loaded by `src/i18n.rs` with `fluent-bundle`. We use `fluent-bundle` directly rather than `fluent-templates`, which pulls in twice as many crates.
- **Long page content** (terms, privacy, security, how it works): Markdown in `crates/shhnote-server/content/<lang>/<page>.md`, turned into HTML once at startup by `src/content.rs`. Start these files at `##`; the page template supplies the `<h1>`.

## Locales

- Locales are plain language codes (`en`, `de`) listed in `LOCALES` in `src/i18n.rs`. `en` is the fallback and the source of truth; every key and page must exist there first.
- Every page lives under a locale prefix: `/en/terms`, `/de/s/<id>`. A path without one, like `/` or `/s/<id>`, gets a temporary redirect to the best match for the browser's `Accept-Language`. Browsers keep the `#` part across the redirect, so secret keys survive it.
- To add a language: add it to `LOCALES` and `SOURCES` in `i18n.rs`, add its `main.ftl`, add every Markdown page to `SOURCES` in `content.rs`, and give it a `language-name` in its own language. The tests fail if any key or page is missing.

## Writing messages

- Keys are lowercase with dashes and grouped by area, for example `form-submit` or `error-404-title`.
- The product name is the `-brand` term. Use `{ -brand }` in messages instead of writing it out.
- Never build sentences by joining strings in Rust or in templates. Word order changes between languages. Use one message with variables instead: `note-count = { $count -> [one] One note *[other] { $count } notes }`.
- Use Fluent's plural selectors for anything with a number in it. Format numbers and sizes for the locale before passing them in (see `format_size` in `web.rs`).
- Keep markup out of messages. Put the HTML in the template and translate the text inside it.
- When adding or renaming a key, update every locale. If you can't translate it, add the English text and mark the line with a `# TODO: translate` comment so it is easy to find.

## Using them

- Page handlers build a `Ctx` with `state.ctx(path)`; templates call `{{ ctx.t("key") }}`. For messages with variables, build the text in the handler with `ctx.t_args`.
- Text that JavaScript shows is passed to it through `data-` attributes rendered from Fluent, never written in the script.
- For API errors, the stable `code` field is never translated; only `message` is.

Run `cargo test` after changing translations: it checks that all locales have the same keys and every page.
