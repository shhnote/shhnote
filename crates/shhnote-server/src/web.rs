use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use askama::Template;
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get},
};
use fluent_bundle::FluentArgs;
use shhnote_core::{
    config::{AdminRouting, ApiRouting, AppEnv, Config, WebMode},
    settings::SettingsCell,
};
use shhnote_store::Store;

use crate::{
    admin,
    api::ApiState,
    content::{Content, Doc},
    i18n::{self, I18n},
    ratelimit::RateLimiter,
};

const MIB: u64 = 1024 * 1024;

pub(crate) struct Shared {
    i18n: I18n,
    // Offered languages in preference order; the first is the redirect fallback.
    offered: i18n::Offered,
    pub(crate) store: Store,
    pub(crate) settings: Arc<SettingsCell>,
    pub(crate) setup: Arc<crate::api::Setup>,
    pub(crate) limiter: Arc<RateLimiter>,
    // Signs admin sessions; comes from SHH_SECRET_KEY.
    pub(crate) secret_key: Vec<u8>,
    pub(crate) secure_cookies: bool,
    pub(crate) env: AppEnv,
    // `/admin` on the main domain, or nothing on the admin domain (D-25).
    admin_prefix: &'static str,
    // The panel's origin when it has its own host, for links rendered on another host.
    admin_origin: Option<String>,
    pub(crate) admin_token_hash: Option<[u8; 32]>,
    asset_version: String,
    // app.css with the asset hash substituted into its font URLs.
    css: String,
    content: Content,
    api_url: String,
    site_url: String,
    pub(crate) max_blob_bytes: u64,
    // Keys minted by the panel, waiting to be shown once on the redirected page (SPEC §8).
    pub(crate) fresh_keys: Mutex<Vec<crate::admin::FreshKey>>,
}

// The SPEC §11 headers, applied to every response by `app::router`.
#[derive(Clone)]
pub(crate) struct SecurityHeaders {
    csp: HeaderValue,
    hsts: bool,
}

impl SecurityHeaders {
    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            csp: content_security_policy(config),
            hsts: config.env == AppEnv::Production,
        }
    }
}

// Each locale gets its own copy of the page routes, so handlers know their language without parsing the URL.
#[derive(Clone)]
pub(crate) struct PageState {
    pub(crate) shared: Arc<Shared>,
    pub(crate) locale: &'static str,
}

// The website, the admin site when the panel has its own host, and the setup page the gate
// shows while setup is unmet (D-29).
pub struct WebRouters {
    pub web: Router,
    pub admin: Option<Router>,
    pub setup: SetupRenderer,
}

#[derive(Clone)]
pub struct SetupRenderer {
    shared: Arc<Shared>,
}

#[derive(Template)]
#[template(path = "setup.html")]
struct SetupPage<'a> {
    ctx: Ctx<'a>,
}

impl SetupRenderer {
    // The page says what is missing and where to log in; never whether a bootstrap token
    // is set. 503 with `no-store`, so nothing caches an instance's setup state.
    pub fn render(&self, accept_language: Option<&str>) -> Response {
        let locale = i18n::negotiate(accept_language, &self.shared.offered);
        let state = PageState {
            shared: self.shared.clone(),
            locale,
        };
        let page = SetupPage {
            ctx: state.ctx("/setup"),
        };
        let mut response = match page.render() {
            Ok(html) => (StatusCode::SERVICE_UNAVAILABLE, Html(html)).into_response(),
            Err(e) => {
                crate::log_error!("template error: {e}");
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
        };
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .append(header::VARY, HeaderValue::from_static("Accept-Language"));
        response
    }
}

pub fn router(config: &Config, api: &ApiState) -> WebRouters {
    let admin_prefix = match config.admin_routing {
        AdminRouting::Path => "/admin",
        AdminRouting::Domain { .. } => "",
    };
    let admin_origin = match &config.admin_routing {
        AdminRouting::Path => None,
        AdminRouting::Domain { url, .. } => Some(url.clone()),
    };
    let shared = Arc::new(Shared {
        i18n: I18n::load(),
        offered: i18n::offered(&config.locales, config.default_locale.as_deref())
            .expect("SHH_LOCALES and SHH_DEFAULT_LOCALE are checked at startup"),
        store: api.store.clone(),
        settings: api.settings.clone(),
        setup: api.setup.clone(),
        limiter: api.limiter.clone(),
        secret_key: config.secret_key.expose().as_bytes().to_vec(),
        secure_cookies: config.env == AppEnv::Production,
        env: config.env,
        admin_prefix,
        admin_origin,
        admin_token_hash: api.admin_token_hash,
        asset_version: asset_version(),
        css: APP_CSS.replace("__V__", &asset_version()),
        content: Content::load(),
        api_url: config.api_url.clone(),
        site_url: config.url.clone(),
        max_blob_bytes: config.storage.max_blob_bytes(),
        fresh_keys: Mutex::new(Vec::new()),
    });

    let own_admin_host = matches!(config.admin_routing, AdminRouting::Domain { .. });
    let offered = shared.offered.clone();
    let mut web = statics(&shared);
    let mut admin = own_admin_host.then(|| statics(&shared));
    for &locale in &offered.locales {
        let state = PageState {
            shared: shared.clone(),
            locale,
        };
        let pages = match (config.web, own_admin_host) {
            (WebMode::Full, false) => pages(state.clone(), true),
            (WebMode::Full, true) => pages(state.clone(), false),
            (WebMode::Api, false) => admin_only(state.clone()),
            // Nothing public and the panel elsewhere: only `/static/*` is left on this host.
            (WebMode::Api, true) => Router::new().fallback(no_page),
        };
        web = web.nest(&format!("/{locale}"), pages);
        if let Some(site) = admin.take() {
            // The panel at `admin.<host>/{locale}/` (D-25).
            let panel = admin::routes().fallback(no_page).with_state(state);
            admin = Some(site.nest(&format!("/{locale}"), panel));
        }
    }

    let web = match config.web {
        WebMode::Full => web.fallback_service(any(redirect_to_locale).with_state(offered.clone())),
        // No public page and no locale redirect: a frontend elsewhere serves those (D-24).
        WebMode::Api => web.fallback(no_page),
    };
    // `/` on the admin host goes to the panel in the browser's language.
    let admin =
        admin.map(|site| site.fallback_service(any(redirect_to_locale).with_state(offered)));
    WebRouters {
        web,
        admin,
        setup: SetupRenderer { shared },
    }
}

// The embedded assets, served on every host the server answers for.
fn statics(shared: &Arc<Shared>) -> Router {
    Router::new()
        .route("/static/app.css", get(css).with_state(shared.clone()))
        .route("/static/app.js", get(app_js))
        .route("/static/shh.js", get(shh_js))
        .route("/static/shh-ui.js", get(shh_ui_js))
        .route("/static/argon2.wasm", get(argon2_wasm))
        .route("/static/fonts/geist.woff2", get(font_regular))
        .route("/static/fonts/geist-italic.woff2", get(font_italic))
        .route("/static/fonts/geist-mono.woff2", get(font_mono))
}

// `SHH_WEB=api`: the admin panel is the only page left under a locale.
fn admin_only(state: PageState) -> Router {
    Router::new()
        .nest("/admin", admin::routes())
        .fallback(no_page)
        .with_state(state)
}

// A bare 404: not the error page, which is itself a public page. The security headers are
// added by the outer layer like everywhere else.
async fn no_page() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

fn pages(state: PageState, with_admin: bool) -> Router {
    let admin = if with_admin {
        admin::routes()
    } else {
        // The panel lives on its own host; the path form answers like any unknown page.
        Router::new()
    };
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
        .route("/acceptable-use", get(acceptable_use))
        .route("/docs", get(docs))
        .route("/report", get(report))
        .nest("/admin", admin)
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
    // `path` is the page's path without the locale prefix, e.g. `/terms`.
    // A link into the admin panel, wherever it is served (D-25).
    pub(crate) fn admin_href(&self, path: &str) -> String {
        format!("/{}{}{path}", self.locale, self.shared.admin_prefix)
    }

    pub(crate) fn ctx(&self, path: &str) -> Ctx<'_> {
        // Admin pages name themselves `/admin/...` whatever host serves them; the language
        // links need the served form.
        let link_path = match path.strip_prefix("/admin") {
            Some(rest) => format!("{}{rest}", self.shared.admin_prefix),
            None => path.to_string(),
        };
        let languages = self
            .shared
            .offered
            .locales
            .iter()
            .map(|&code| LanguageLink {
                code,
                name: self.shared.i18n.t(code, "language-name", None),
                href: format!("/{code}{link_path}"),
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

    // Builds keys like `how-s-2-title` for templates that loop over numbered items.
    pub(crate) fn tn(&self, prefix: &str, n: &str, suffix: &str) -> String {
        self.t(&format!("{prefix}{n}{suffix}"))
    }

    pub(crate) fn t_args(&self, key: &str, args: &FluentArgs) -> String {
        self.shared.i18n.t(self.locale, key, Some(args))
    }

    pub(crate) fn href(&self, path: &str) -> String {
        format!("/{}{path}", self.locale)
    }

    pub(crate) fn admin_href(&self, path: &str) -> String {
        format!("/{}{}{path}", self.locale, self.shared.admin_prefix)
    }

    // A link into the panel from a page that may be served on another host: absolute to the
    // admin host when the panel has one (D-25), the path form otherwise.
    pub(crate) fn admin_url(&self, path: &str) -> String {
        match &self.shared.admin_origin {
            Some(origin) => format!("{origin}/{}{path}", self.locale),
            None => self.admin_href(path),
        }
    }

    // The configured site name; the Fluent `brand-name` term stays the project name.
    // The configured name; the software's name only while setup is not done (D-29), which
    // is when only the admin pages can be seen.
    pub(crate) fn site_name(&self) -> String {
        let name = self.shared.settings.load().site_name.clone();
        if name.is_empty() {
            "shhnote".to_string()
        } else {
            name
        }
    }

    pub(crate) fn api_url(&self) -> &str {
        &self.shared.api_url
    }

    pub(crate) fn asset_version(&self) -> &str {
        &self.shared.asset_version
    }

    // The most bytes a reveal can legitimately return; the page script caps downloads at it.
    pub(crate) fn max_blob_bytes(&self) -> u64 {
        self.shared.max_blob_bytes
    }

    pub(crate) fn repo_url(&self) -> String {
        self.shared.settings.load().source_url.clone()
    }

    pub(crate) fn project_url(&self) -> String {
        self.shared.settings.load().project_url.clone()
    }

    pub(crate) fn server_version(&self) -> &'static str {
        crate::api::SERVER_VERSION
    }

    // The protocol specification in the source repository (`{{spec_url}}`).
    pub(crate) fn spec_url(&self) -> String {
        source_file_url(&self.shared.settings.load().source_url, "SPEC.md")
    }

    // Where the software lives: the project page, or the source link while none is set.
    pub(crate) fn project_or_source_url(&self) -> String {
        let settings = self.shared.settings.load();
        if settings.project_url.is_empty() {
            settings.source_url.clone()
        } else {
            settings.project_url.clone()
        }
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
    "result-destroyed",
    "result-chip-single",
    "result-chip-multi",
    "result-chip-expires",
    "create-encrypting",
    "create-uploading",
    "create-error-empty",
    "create-error-too-large",
    "create-error-text-too-long",
    "create-error-network",
    "create-error-failed",
    "create-error-wasm",
    "reveal-fetching",
    "reveal-decrypting",
    "reveal-wrong-passphrase",
    "reveal-single-view",
    "reveal-single-view-destroyed",
    "reveal-download",
    "reveal-error-network",
    "reveal-error-busy",
    "reveal-error-too-large",
    "reveal-error-corrupt",
    "reveal-error-wasm",
    "burn-working",
    "report-working",
    "report-error-invalid",
    "error-unsupported-protocol",
];

// A file in the source repository, for links from the pages: `<source_url>/blob/main/<file>`
// when the source is a GitHub repository (the default), otherwise the source link itself,
// since other forges lay out file URLs differently. Empty when no source link is set.
fn source_file_url(source_url: &str, file: &str) -> String {
    let base = source_url.trim_end_matches('/');
    let is_repo = base
        .strip_prefix("https://github.com/")
        .is_some_and(|rest| rest.split('/').filter(|part| !part.is_empty()).count() == 2);
    if is_repo {
        format!("{base}/blob/main/{file}")
    } else {
        base.to_string()
    }
}

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
            security_email: settings.security_email(),
        },
    )
}

#[derive(Template)]
#[template(path = "doc.html")]
struct DocPage<'a> {
    ctx: Ctx<'a>,
    title: String,
    body: String,
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

async fn acceptable_use(State(state): State<PageState>) -> Response {
    doc_page(
        &state,
        Doc::AcceptableUse,
        "/acceptable-use",
        "page-acceptable-use",
    )
}

async fn docs(State(state): State<PageState>) -> Response {
    doc_page(&state, Doc::Docs, "/docs", "page-docs")
}

fn doc_page(state: &PageState, doc: Doc, path: &str, title_key: &str) -> Response {
    let ctx = state.ctx(path);
    let title = ctx.t(title_key);
    // Markdown pages may link to this instance by placeholder, since the URLs are deployment
    // settings. Inside link targets the Markdown renderer has percent-encoded the braces.
    let site = format!(
        "{}/{}",
        state.shared.site_url.trim_end_matches('/'),
        state.locale
    );
    // `{{project_url}}` is the project page, or the source link while none is set.
    let settings = state.shared.settings.load();
    let security_email = settings.security_email();
    let project = if settings.project_url.is_empty() {
        settings.source_url.clone()
    } else {
        settings.project_url.clone()
    };
    let spec = source_file_url(&settings.source_url, "SPEC.md");
    let security_policy = source_file_url(&settings.source_url, "SECURITY.md");
    // The placeholders sit in text or in link targets of HTML the renderer has already
    // escaped, so every value goes in escaped too: a setting is text on the page, never
    // markup, whatever an admin typed into it.
    let values = [
        ("site_url", site.as_str()),
        ("api_url", state.shared.api_url.as_str()),
        ("project_url", project.as_str()),
        ("spec_url", spec.as_str()),
        ("security_policy_url", security_policy.as_str()),
        ("version", crate::api::SERVER_VERSION),
        ("site_name", settings.site_name.as_str()),
        ("contact_email", settings.contact_email.as_str()),
        ("security_email", security_email),
    ];
    let mut body = state.shared.content.get(state.locale, doc).to_string();
    for (name, value) in values {
        let escaped = escape_html(value);
        body = body
            .replace(&format!("{{{{{name}}}}}"), &escaped)
            .replace(&format!("%7B%7B{name}%7D%7D"), &escaped);
    }
    render(state, DocPage { ctx, title, body })
}

// The five characters that matter in text and in attribute values.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
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
        badge: format!("{} {}", ctx.t("error-badge"), status.as_u16()),
        title: ctx.t(&format!("{key}-title")),
        message: ctx.t(&format!("{key}-body")),
        ctx,
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        // Don't try to render another page here, or a broken error template would loop.
        Err(e) => {
            crate::log_error!("template error: {e}");
            status.into_response()
        }
    }
}

// A template error becomes a 500 page instead of crashing the request.
pub(crate) fn render(state: &PageState, page: impl Template) -> Response {
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            crate::log_error!("template error: {e}");
            error_page(state, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Paths without a locale, like `/` or `/s`, are sent to the same page in the browser's language.
// Browsers keep the `#` part of the link across the redirect, so secret fragments survive it.
async fn redirect_to_locale(State(offered): State<i18n::Offered>, req: Request) -> Response {
    let path = req.uri().path();
    if path.starts_with("/static/") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let accept_language = req
        .headers()
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    let locale = i18n::negotiate(accept_language, &offered);
    // A link made under a language this instance no longer offers keeps working in another.
    let path = i18n::LOCALES
        .iter()
        .find_map(|known| {
            let rest = path.strip_prefix('/')?.strip_prefix(known)?;
            (rest.is_empty() || rest.starts_with('/')).then_some(rest)
        })
        .unwrap_or(path);
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
    // When the API is on its own domain, the page's scripts need permission to call it.
    let connect = match config.api_routing {
        ApiRouting::Path => "'self'".to_string(),
        ApiRouting::Domain { .. } => format!("'self' {}", config.api_url),
    };
    // 'wasm-unsafe-eval' is for the Argon2id module; it allows WebAssembly only, not eval().
    let policy = format!(
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
         font-src 'self'; img-src 'self' data: blob:; connect-src {connect}; \
         form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
    HeaderValue::from_str(&policy).expect("policy is valid header text")
}

pub(crate) async fn security_headers(
    State(set): State<SecurityHeaders>,
    mut response: Response,
) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, set.csp.clone());
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
    // Nothing on the site uses device features; say so, so an injected script can't either.
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), \
             microphone=(), payment=(), usb=()",
        ),
    );
    if set.hsts {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
    }
    response
}

const APP_CSS: &str = include_str!("../static/app.css");
const APP_JS: &[u8] = include_bytes!("../static/app.js");
const SHH_JS: &[u8] = include_bytes!("../static/shh.js");
// The `/ui` entry of the client package, for frontends without a build step.
const SHH_UI_JS: &[u8] = include_bytes!("../static/shh-ui.js");
const ARGON2_WASM: &[u8] = include_bytes!("../static/argon2.wasm");
const FONT_REGULAR: &[u8] = include_bytes!("../static/fonts/geist.woff2");
const FONT_ITALIC: &[u8] = include_bytes!("../static/fonts/geist-italic.woff2");
const FONT_MONO: &[u8] = include_bytes!("../static/fonts/geist-mono.woff2");

// Short hash of everything embedded; it goes into asset URLs so a browser never runs a stale copy.
fn asset_version() -> String {
    let mut all = Vec::new();
    for part in [
        APP_CSS.as_bytes(),
        APP_JS,
        SHH_JS,
        SHH_UI_JS,
        ARGON2_WASM,
        FONT_REGULAR,
        FONT_ITALIC,
        FONT_MONO,
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

async fn font_mono() -> impl IntoResponse {
    static_asset("font/woff2", FONT_MONO)
}

// Generated by scripts/build-client.sh and embedded, so the binary is self-contained.
async fn app_js() -> impl IntoResponse {
    static_asset("text/javascript; charset=utf-8", APP_JS)
}

async fn shh_js() -> impl IntoResponse {
    static_asset("text/javascript; charset=utf-8", SHH_JS)
}

async fn shh_ui_js() -> impl IntoResponse {
    static_asset("text/javascript; charset=utf-8", SHH_UI_JS)
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

    // Revision 3, C7: spec and security-policy links reach the file on GitHub repositories,
    // and fall back to the source link anywhere else.
    #[test]
    fn source_file_urls() {
        let upstream = "https://github.com/shhnote/shhnote";
        assert_eq!(
            source_file_url(upstream, "SPEC.md"),
            "https://github.com/shhnote/shhnote/blob/main/SPEC.md"
        );
        assert_eq!(
            source_file_url(&format!("{upstream}/"), "SECURITY.md"),
            "https://github.com/shhnote/shhnote/blob/main/SECURITY.md"
        );
        for other in [
            "https://codeberg.org/someone/fork",
            "https://github.com/shhnote",
            "https://github.com/shhnote/shhnote/tree/dev",
            "https://example.com/source",
        ] {
            assert_eq!(source_file_url(other, "SPEC.md"), other);
        }
        assert_eq!(source_file_url("", "SPEC.md"), "");
    }

    #[test]
    fn formats_sizes() {
        assert_eq!(format_size(64 * MIB, "en"), "64 MB");
        assert_eq!(format_size(3 * MIB / 2, "en"), "1.5 MB");
        assert_eq!(format_size(3 * MIB / 2, "de"), "1,5 MB");
    }
}
