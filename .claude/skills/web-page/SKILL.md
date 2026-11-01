---
name: web-page
description: Add or change a website page in shhnote-server using Askama templates. Use when creating HTML routes, templates, layouts, or forms.
---

# Adding a website page

## Templates

- Templates live in `crates/shhnote-server/templates/`. Pages extend a shared `base.html` layout; reusable pieces go in `templates/partials/`.
- Each page has a struct with `#[derive(askama::Template)]` and `#[template(path = "...")]`, with a `ctx: Ctx` field for translations, links and the language switcher. Pass only what the template needs; build a view struct instead of passing database rows.
- Render with the `render` helper in `web.rs`, which turns a template failure into the 500 error page. Use `error_page` for 404s and other errors, so they are shown in the visitor's language.
- Askama escapes HTML by default. Only use `|safe` for our own Markdown content from `content.rs`, never for anything from a user.
- All user-visible text goes through translations (see the `i18n` skill). No hard-coded English in templates or scripts.
- Build internal links with `ctx.href("/path")` so they keep the current language.

## Routes and forms

- Page routes are added once in `pages()` in `web.rs` and served under every locale prefix (`/en/...`, `/de/...`). Website routes never start with `/api`.
- The reveal (`/s`) and burn (`/burn`) pages are static and identical for every secret: the secret is identified only by the URL fragment, which the script reads. Never put a secret identifier in a path or query string, and never render anything secret-specific on the server. Page handlers can call the same functions as the API, but never call the API over HTTP.
- Forms that change data use POST and redirect after success (POST/redirect/GET), so refreshing doesn't resubmit.
- Every form that changes data must be protected against CSRF.
- On a validation error, show the form again with the user's input and the error messages, with a 422 status.
- Pages should work without JavaScript. The exception is creating and viewing secrets, since encryption happens in the browser: those forms start `hidden`, the script shows them, and a `<noscript>` message explains why.

## Scripts, styles and security headers

- All CSS is in `static/app.css`. Colours come only from the tokens at the top of that file, which are generated for four themes (dark, light, dark-hc, light-hc) plus system matching; never hard-code a colour or a dashed border (use `var(--border-style)`, which becomes solid in the high-contrast themes). The component vocabulary, all defined in `app.css`: `panel`/`vault`, `badge`, `callout`, `readout`, `info-chips`, `flow`, `menu`, `prose`, plus the form classes and the spacing utilities (`mt-8`, `gap-6`/`gap-8`/`gap-12`, `text-center`/`text-left`, `min-h-20`, `w-full`). The stylesheet is deliberately neutral: a reference, not a brand.
- Templates that use the icon or menu macros import them after `extends`; every `{% call %}` needs `{% endcall %}`. Numbered translation keys are built with `ctx.tn("prefix-", i, "-suffix")` inside loops, since `format!` is not available in templates.
- The language and theme switchers are `<details class="menu">` disclosures, present in the header and footer; they work without the script, which only adds close-on-outside-click, Escape, and theme persistence.
- Semantic HTML first: `<nav>` with labels, `<ol>` for steps, `<dl>` for spec lists, `<details>` for FAQs, `role="tablist"` only where the script turns sections into tabs, `aria-live` on status text, `aria-current` on the active nav item. JavaScript is TypeScript in `client/src/ui/`, bundled by `scripts/build-client.sh`; never edit the generated `static/*.js`. No inline `<script>`, `<style>`, `style=` or `on...=` attributes: the Content Security Policy blocks them.
- Text the script shows at runtime goes through Fluent like everything else: add the key to `UI_KEYS` in `web.rs` and to `UiKey` in `client/src/ui/i18n.ts`; the server renders them into the `<script type="application/json" data-i18n>` block and the script reads them with `t("key")`. Variables use a literal `{name}` placeholder (`{ "{hours}" }` in Fluent).
- Pages that react to a URL fragment or a form follow the `[data-state]` pattern: every state is a section in the template, hidden by default, and the script switches with `setState`. Buttons that consume or destroy something only act on trusted events.
- In scripts, insert user-provided text with `textContent`, never `innerHTML`.
- Fonts are Inter, embedded from `static/fonts/` (SIL OFL, licence file alongside) and referenced from `app.css` with a `__V__` placeholder that the server replaces with the asset hash. Nothing is ever loaded from another origin; the CSP allows `font-src 'self'` only.
- Share and burn links shown to users have no locale (`/s#…`, `/burn#…`); the server redirects to the visitor's language and the fragment survives the redirect.
- Admin pages live in `admin.rs`: each handler starts with `authenticate`, every form carries `admin.csrf` (checked by `check_csrf`), templates extend `base.html` and call `nav::admin_nav(ctx, admin)`. Database errors go through `db_error` so they are logged.
- Every page gets the CSP, `Referrer-Policy: no-referrer`, `nosniff` and `X-Frame-Options: DENY` from the `security_headers` layer. Pages showing secret content also send `Cache-Control: no-store`.
- Links to the API come from `config.api_url`, since the API may be on its own subdomain.

## Checking the result

After changing a page, run the server and load it to confirm it renders, including the error and empty states.
