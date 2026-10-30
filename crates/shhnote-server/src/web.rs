use std::{collections::BTreeMap, sync::Arc};

use askama::Template;
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use fluent_bundle::FluentArgs;
use shhnote_core::{
    config::{ApiRouting, AppEnv, Config},
    secret::credential_hash,
    settings::SettingsCell,
};
use shhnote_store::Store;

use crate::{
    admin,
    api::ApiState,
    content::{Content, Doc},
    i18n::{self, I18n, LOCALES},
    ratelimit::RateLimiter,
};

// TODO: settings. Empty hides the source links.
const REPO_URL: &str = "https://github.com/zbcdo/shhnote";

const MIB: u64 = 1024 * 1024;

pub(crate) struct Shared {
    i18n: I18n,
    pub(crate) store: Store,
    pub(crate) settings: Arc<SettingsCell>,
    pub(crate) limiter: Arc<RateLimiter>,
    // Signs admin sessions; comes from SHH_SECRET_KEY.
    pub(crate) secret_key: Vec<u8>,
    pub(crate) secure_cookies: bool,
    pub(crate) admin_token_hash: Option<[u8; 32]>,
    asset_version: String,
    // app.css with the asset hash substituted into its font URLs.
    css: String,
    content: Content,
    api_url: String,
    site_url: String,
    max_blob_bytes: u64,
    csp: HeaderValue,
}

// Each locale gets its own copy of the page routes, so handlers know their language without parsing the URL.
#[derive(Clone)]
pub(crate) struct PageState {
    pub(crate) shared: Arc<Shared>,
    pub(crate) locale: &'static str,
}

pub fn router(config: &Config, api: &ApiState) -> Router {
    let shared = Arc::new(Shared {
        i18n: I18n::load(),
        store: api.store.clone(),
        settings: api.settings.clone(),
        limiter: api.limiter.clone(),
        secret_key: config.secret_key.expose().as_bytes().to_vec(),
        secure_cookies: config.env == AppEnv::Production,
        admin_token_hash: config
            .admin_token
            .as_ref()
            .map(|t| credential_hash(t.expose().as_bytes())),
        asset_version: asset_version(),
        css: APP_CSS.replace("__V__", &asset_version()),
        content: Content::load(),
        api_url: config.api_url.clone(),
        site_url: config.url.clone(),
        max_blob_bytes: config.storage.max_blob_bytes(),
        csp: content_security_policy(config),
    });

    let mut router = Router::new()
        .route("/static/app.css", get(css).with_state(shared.clone()))
        .route("/static/app.js", get(app_js))
        .route("/static/shh.js", get(shh_js))
        .route("/static/argon2.wasm", get(argon2_wasm))
        .route("/static/fonts/inter.woff2", get(font_regular))
        .route("/static/fonts/inter-italic.woff2", get(font_italic));
    for &locale in LOCALES {
        let state = PageState {
            shared: shared.clone(),
            locale,
        };
        router = router.nest(&format!("/{locale}"), pages(state));
    }

    router
        .fallback(redirect_to_locale)
        .layer(middleware::map_response_with_state(
            shared,
            security_headers,
        ))
}

fn pages(state: PageState) -> Router {
    Router::new()
        .route("/", get(home))
        // The secret is identified only by the URL fragment, which never reaches the server,
        // so this page is static and identical for every secret (SPEC §2.2, §11).
        .route("/s", get(view_secret))
        .route("/burn", get(burn))
        .route("/how-it-works", get(how_it_works))
        .route("/about", get(about))
        .route("/contact", get(contact))
        .route("/terms", get(terms))
        .route("/privacy", get(privacy))
        .route("/security", get(security))
        .route("/report", get(report))
        .nest("/admin", admin::routes())
        .fallback(not_found)
        .with_state(state)
}

// What every page template needs: translations and the language switcher.
pub(crate) struct Ctx<'a> {
    pub(crate) shared: &'a Shared,
    pub(crate) locale: &'static str,
    // The page's path without the locale prefix, for marking the current nav item.
    pub(crate) path: String,
    pub(crate) languages: Vec<LanguageLink>,
}

pub(crate) struct LanguageLink {
    pub(crate) code: &'static str,
    pub(crate) name: String,
    pub(crate) href: String,
    pub(crate) current: bool,
}

impl PageState {
    pub(crate) fn href(&self, path: &str) -> String {
        format!("/{}{path}", self.locale)
    }

    // `path` is the page's path without the locale prefix, e.g. `/terms`.
    pub(crate) fn ctx(&self, path: &str) -> Ctx<'_> {
        let languages = LOCALES
            .iter()
            .map(|&code| LanguageLink {
                code,
                name: self.shared.i18n.t(code, "language-name", None),
                href: format!("/{code}{path}"),
                current: code == self.locale,
            })
            .collect();
        Ctx {
            shared: &self.shared,
            locale: self.locale,
            path: path.to_string(),
            languages,
        }
    }
}

impl Ctx<'_> {
    pub(crate) fn t(&self, key: &str) -> String {
        self.shared.i18n.t(self.locale, key, None)
    }

    // Builds keys like `hood-3-label` for templates that loop over numbered items.
    pub(crate) fn tn(&self, prefix: &str, n: &str, suffix: &str) -> String {
        self.t(&format!("{prefix}{n}{suffix}"))
    }

    pub(crate) fn tn2(&self, prefix: &str, a: &str, mid: &str, b: &str) -> String {
        self.t(&format!("{prefix}{a}{mid}{b}"))
    }

    pub(crate) fn t_args(&self, key: &str, args: &FluentArgs) -> String {
        self.shared.i18n.t(self.locale, key, Some(args))
    }

    pub(crate) fn href(&self, path: &str) -> String {
        format!("/{}{path}", self.locale)
    }

    // The configured site name; the Fluent `brand-name` term stays the project name.
    pub(crate) fn site_name(&self) -> String {
        self.shared.settings.load().site_name.clone()
    }

    pub(crate) fn api_url(&self) -> &str {
        &self.shared.api_url
    }

    pub(crate) fn asset_version(&self) -> &str {
        &self.shared.asset_version
    }

    pub(crate) fn repo_url(&self) -> &str {
        REPO_URL
    }

    // The strings the page script needs, as a JSON object. `<` is escaped so a translation can
    // never close the `<script>` block it is embedded in.
    pub(crate) fn ui_json(&self) -> String {
        let map: BTreeMap<&str, String> = UI_KEYS.iter().map(|key| (*key, self.t(key))).collect();
        serde_json::to_string(&map)
            .unwrap_or_default()
            .replace('<', "\\u003c")
    }
}

// Every translation the page script can show. Keep in step with `client/src/ui/i18n.ts`.
const UI_KEYS: &[&str] = &[
    "form-files-remove",
    "result-copied",
    "result-destroyed",
    "result-chip-single",
    "result-chip-multi",
    "result-chip-expires",
    "create-encrypting",
    "create-uploading",
    "create-error-empty",
    "create-error-too-large",
    "create-error-network",
    "create-error-failed",
    "reveal-fetching",
    "reveal-decrypting",
    "reveal-wrong-passphrase",
    "reveal-single-view",
    "reveal-expires-one",
    "reveal-expires-many",
    "reveal-download",
    "reveal-error-network",
    "reveal-error-corrupt",
    "burn-working",
    "report-working",
    "report-error-invalid",
];

#[derive(Template)]
#[template(path = "home.html")]
struct HomePage<'a> {
    ctx: Ctx<'a>,
    upload_hint: String,
    regions: Vec<RegionLink>,
    // The name of this instance's region, if it is in the list.
    region_here: Option<String>,
}

struct RegionLink {
    name: String,
    url: String,
    current: bool,
}

async fn home(State(state): State<PageState>) -> Response {
    let ctx = state.ctx("");
    let mut args = FluentArgs::new();
    args.set(
        "size",
        format_size(state.shared.max_blob_bytes, state.locale),
    );
    let upload_hint = ctx.t_args("form-files-hint", &args);
    let here = state.shared.site_url.trim_end_matches('/');
    let regions: Vec<RegionLink> = state
        .shared
        .settings
        .load()
        .regions
        .iter()
        .map(|r| RegionLink {
            name: r.name.clone(),
            url: r.url.clone(),
            current: r.url.trim_end_matches('/') == here,
        })
        .collect();
    let region_here = regions.iter().find(|r| r.current).map(|r| r.name.clone());
    render(
        &state,
        HomePage {
            ctx,
            upload_hint,
            regions,
            region_here,
        },
    )
}

#[derive(Template)]
#[template(path = "secret.html")]
struct SecretPage<'a> {
    ctx: Ctx<'a>,
}

#[derive(Template)]
#[template(path = "burn.html")]
struct BurnPage<'a> {
    ctx: Ctx<'a>,
}

#[derive(Template)]
#[template(path = "report.html")]
struct ReportPage<'a> {
    ctx: Ctx<'a>,
}

async fn report(State(state): State<PageState>) -> Response {
    render(
        &state,
        ReportPage {
            ctx: state.ctx("/report"),
        },
    )
}

async fn burn(State(state): State<PageState>) -> Response {
    let mut response = render(
        &state,
        BurnPage {
            ctx: state.ctx("/burn"),
        },
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn view_secret(State(state): State<PageState>) -> Response {
    let mut response = render(
        &state,
        SecretPage {
            ctx: state.ctx("/s"),
        },
    );
    // Once the script reveals a secret, nothing on this page may be cached anywhere.
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Template)]
#[template(path = "how_it_works.html")]
struct HowItWorksPage<'a> {
    ctx: Ctx<'a>,
}

async fn how_it_works(State(state): State<PageState>) -> Response {
    render(
        &state,
        HowItWorksPage {
            ctx: state.ctx("/how-it-works"),
        },
    )
}

#[derive(Template)]
#[template(path = "about.html")]
struct AboutPage<'a> {
    ctx: Ctx<'a>,
}

async fn about(State(state): State<PageState>) -> Response {
    render(
        &state,
        AboutPage {
            ctx: state.ctx("/about"),
        },
    )
}

#[derive(Template)]
#[template(path = "contact.html")]
struct ContactPage<'a> {
    ctx: Ctx<'a>,
    contact_email: &'a str,
    security_email: &'a str,
}

async fn contact(State(state): State<PageState>) -> Response {
    let settings = state.shared.settings.load();
    render(
        &state,
        ContactPage {
            ctx: state.ctx("/contact"),
            contact_email: &settings.contact_email,
            security_email: &settings.security_email,
        },
    )
}

#[derive(Template)]
#[template(path = "doc.html")]
struct DocPage<'a> {
    ctx: Ctx<'a>,
    title: String,
    body: &'a str,
}

async fn terms(State(state): State<PageState>) -> Response {
    doc_page(&state, Doc::Terms, "/terms", "page-terms")
}

async fn privacy(State(state): State<PageState>) -> Response {
    doc_page(&state, Doc::Privacy, "/privacy", "page-privacy")
}

async fn security(State(state): State<PageState>) -> Response {
    doc_page(&state, Doc::Security, "/security", "page-security")
}

fn doc_page(state: &PageState, doc: Doc, path: &str, title_key: &str) -> Response {
    let ctx = state.ctx(path);
    let title = ctx.t(title_key);
    render(
        state,
        DocPage {
            ctx,
            title,
            body: state.shared.content.get(state.locale, doc),
        },
    )
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    ctx: Ctx<'a>,
    badge: String,
    title: String,
    message: String,
}

async fn not_found(State(state): State<PageState>) -> Response {
    error_page(&state, StatusCode::NOT_FOUND)
}

pub(crate) fn error_page(state: &PageState, status: StatusCode) -> Response {
    let key = match status {
        StatusCode::NOT_FOUND => "error-404",
        StatusCode::FORBIDDEN => "error-403",
        StatusCode::BAD_REQUEST => "error-400",
        _ => "error-500",
    };
    let ctx = state.ctx("");
    let page = ErrorPage {
        badge: ctx.t("error-badge"),
        title: ctx.t(&format!("{key}-title")),
        message: ctx.t(&format!("{key}-body")),
        ctx,
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        // Don't try to render another page here, or a broken error template would loop.
        Err(e) => {
            eprintln!("template error: {e}");
            status.into_response()
        }
    }
}

// A template error becomes a 500 page instead of crashing the request.
pub(crate) fn render(state: &PageState, page: impl Template) -> Response {
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            eprintln!("template error: {e}");
            error_page(state, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Paths without a locale, like `/` or `/s`, are sent to the same page in the browser's language.
// Browsers keep the `#` part of the link across the redirect, so secret fragments survive it.
async fn redirect_to_locale(req: Request) -> Response {
    let path = req.uri().path();
    if path.starts_with("/static/") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let accept_language = req
        .headers()
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    let locale = i18n::negotiate(accept_language);
    let path = if path == "/" { "" } else { path };
    let location = match req.uri().query() {
        Some(query) => format!("/{locale}{path}?{query}"),
        None => format!("/{locale}{path}"),
    };
    // The target depends on the browser's language, so caches must not reuse it for other people.
    (
        [(header::VARY, "Accept-Language")],
        Redirect::temporary(&location),
    )
        .into_response()
}

fn content_security_policy(config: &Config) -> HeaderValue {
    // When the API is on its own subdomain, the page's scripts need permission to call it.
    let connect = match config.api_routing {
        ApiRouting::Path => "'self'".to_string(),
        ApiRouting::Subdomain { .. } => format!("'self' {}", config.api_url),
    };
    // 'wasm-unsafe-eval' is for the Argon2id module; it allows WebAssembly only, not eval().
    let policy = format!(
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
         font-src 'self'; img-src 'self' data: blob:; connect-src {connect}; \
         form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
    HeaderValue::from_str(&policy).expect("policy is valid header text")
}

async fn security_headers(State(shared): State<Arc<Shared>>, mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, shared.csp.clone());
    // Never tell other sites which page a visitor came from.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

const APP_CSS: &str = include_str!("../static/app.css");
const APP_JS: &[u8] = include_bytes!("../static/app.js");
const SHH_JS: &[u8] = include_bytes!("../static/shh.js");
const ARGON2_WASM: &[u8] = include_bytes!("../static/argon2.wasm");
const FONT_REGULAR: &[u8] = include_bytes!("../static/fonts/inter.woff2");
const FONT_ITALIC: &[u8] = include_bytes!("../static/fonts/inter-italic.woff2");

// Short hash of everything embedded; it goes into asset URLs so a browser never runs a stale copy.
fn asset_version() -> String {
    let mut all = Vec::new();
    for part in [
        APP_CSS.as_bytes(),
        APP_JS,
        SHH_JS,
        ARGON2_WASM,
        FONT_REGULAR,
        FONT_ITALIC,
    ] {
        all.extend_from_slice(part);
    }
    let digest = shhnote_core::kdf::sha256(&all);
    digest[..6].iter().map(|b| format!("{b:02x}")).collect()
}

async fn css(State(shared): State<Arc<Shared>>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        shared.css.clone(),
    )
}

async fn font_regular() -> impl IntoResponse {
    static_asset("font/woff2", FONT_REGULAR)
}

async fn font_italic() -> impl IntoResponse {
    static_asset("font/woff2", FONT_ITALIC)
}

// Generated by scripts/build-client.sh and embedded, so the binary is self-contained.
async fn app_js() -> impl IntoResponse {
    static_asset("text/javascript; charset=utf-8", APP_JS)
}

async fn shh_js() -> impl IntoResponse {
    static_asset("text/javascript; charset=utf-8", SHH_JS)
}

async fn argon2_wasm() -> impl IntoResponse {
    static_asset("application/wasm", ARGON2_WASM)
}

// The URL carries the content hash, so a long immutable cache is safe.
fn static_asset(content_type: &'static str, bytes: &'static [u8]) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        bytes,
    )
}

fn format_size(bytes: u64, locale: &str) -> String {
    let mib = bytes as f64 / MIB as f64;
    let number = if mib.fract() == 0.0 {
        format!("{mib:.0}")
    } else {
        format!("{mib:.1}")
    };
    // German uses a comma as the decimal separator.
    let number = if locale == "de" {
        number.replace('.', ",")
    } else {
        number
    };
    format!("{number} MB")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_sizes() {
        assert_eq!(format_size(64 * MIB, "en"), "64 MB");
        assert_eq!(format_size(3 * MIB / 2, "en"), "1.5 MB");
        assert_eq!(format_size(3 * MIB / 2, "de"), "1,5 MB");
    }
}
