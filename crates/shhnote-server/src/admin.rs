use std::collections::HashMap;

use askama::Template;
use axum::{
    Form, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use shhnote_core::{
    config::AppEnv,
    secret::credential_hash,
    settings::{Settings, SettingsCell},
};
use shhnote_store::{ApiKey, Scope, Store};

use crate::{
    clock::{format_date, format_time, now},
    ratelimit::{Endpoint, Peer},
    web::{Ctx, PageState, error_page, render},
};

const COOKIE: &str = "shh_admin";
const SESSION_SECS: i64 = 12 * 3600;
const DAY: i64 = 86_400;
// How long a freshly minted key waits to be shown; a redirect takes well under a second.
const FRESH_KEY_SECS: i64 = 60;

// A key minted by the panel, parked under a one-time nonce until the redirected page shows
// it (SPEC §8): the POST response carries nothing, so a refresh mints nothing and shows
// nothing. Bound to the session that minted it.
pub(crate) struct FreshKey {
    nonce: String,
    session_nonce: [u8; 16],
    key: String,
    expires: i64,
}

pub(crate) fn routes() -> Router<PageState> {
    Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/settings", get(settings_page).post(settings_save))
        .route("/keys", get(keys_page).post(keys_create))
        .route("/keys/delete", post(keys_delete))
        .route("/keys/sessions", post(keys_end_sessions))
        .layer(axum::middleware::map_response(no_store))
}

// Admin responses are never cached (SPEC §8): one of them shows a freshly minted key.
pub(crate) async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// A signed, stateless session: who is logged in and until when. `key_hash` is the admin
// key's hash, or the bootstrap token's hash for a bootstrap session, so both kinds are bound
// to the credential that made them; every request re-checks that credential, and
// `issued_at` is what revocation is measured against (SPEC §8).
#[derive(Clone, Copy)]
struct Session {
    key_hash: [u8; 32],
    bootstrap: bool,
    nonce: [u8; 16],
    issued_at: i64,
    expires: i64,
}

const SESSION_LEN: usize = 1 + 32 + 8 + 8 + 16;

type HmacSha256 = Hmac<Sha256>;

fn mac(secret: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

impl Session {
    fn encode(&self, secret: &[u8]) -> String {
        let mut payload = Vec::with_capacity(SESSION_LEN);
        payload.push(u8::from(self.bootstrap));
        payload.extend_from_slice(&self.key_hash);
        payload.extend_from_slice(&self.issued_at.to_be_bytes());
        payload.extend_from_slice(&self.expires.to_be_bytes());
        payload.extend_from_slice(&self.nonce);
        let tag = mac(secret, &payload);
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(tag)
        )
    }

    fn decode(text: &str, secret: &[u8]) -> Option<Self> {
        let (payload, tag) = text.split_once('.')?;
        let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
        if payload.len() != SESSION_LEN || !constant_time_eq(&mac(secret, &payload), &tag) {
            return None;
        }
        Some(Self {
            bootstrap: payload[0] == 1,
            key_hash: payload[1..33].try_into().ok()?,
            issued_at: i64::from_be_bytes(payload[33..41].try_into().ok()?),
            expires: i64::from_be_bytes(payload[41..49].try_into().ok()?),
            nonce: payload[49..65].try_into().ok()?,
        })
    }

    // Forms carry this; it is bound to the session, so a cross-site page can't forge it.
    fn csrf(&self, secret: &[u8]) -> String {
        let mut data = b"csrf".to_vec();
        data.extend_from_slice(&self.nonce);
        URL_SAFE_NO_PAD.encode(mac(secret, &data))
    }
}

fn cookie_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|pair| {
            pair.strip_prefix(COOKIE)
                .and_then(|rest| rest.strip_prefix('='))
        })
}

// No `Domain` attribute: the cookie belongs to the host that serves the panel, the main
// domain or the admin subdomain, and to nothing else (SPEC §8).
fn set_cookie(state: &PageState, value: &str, max_age: i64) -> HeaderValue {
    let secure = if state.shared.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
    ))
    .expect("cookie text is ASCII")
}

// The logged-in session, or a redirect to the login page.
// Boxed because a Response is large and the error path is rare.
async fn authenticate(state: &PageState, headers: &HeaderMap) -> Result<Session, Box<Response>> {
    let login = Box::new(Redirect::to(&state.admin_href("/login")).into_response());
    let Some(session) =
        cookie_value(headers).and_then(|v| Session::decode(v, &state.shared.secret_key))
    else {
        return Err(login);
    };
    if session.expires <= now() {
        return Err(login);
    }
    // Revocation is strict: a session issued in the same second as a reset or an
    // "end sessions" is dead too, and the operator simply logs in again.
    let valid = if session.bootstrap {
        let bound = matches!(state.shared.admin_token_hash, Some(token) if constant_time_eq(&token, &session.key_hash));
        bound
            && bootstrap_allowed(state).await
            && matches!(state.shared.store.bootstrap_sessions_valid_after().await, Ok(after) if session.issued_at > after)
    } else {
        matches!(state.shared.store.find_api_key(&session.key_hash).await,
            Ok(Some(key)) if key.scope == Scope::Admin && session.issued_at > key.sessions_valid_after)
    };
    if valid { Ok(session) } else { Err(login) }
}

// The bootstrap token works only until the first admin key exists (SPEC §8).
async fn bootstrap_allowed(state: &PageState) -> bool {
    state.shared.admin_token_hash.is_some()
        && matches!(state.shared.store.admin_key_count().await, Ok(0))
}

fn check_csrf(
    session: &Session,
    state: &PageState,
    form: &HashMap<String, String>,
) -> Result<(), Box<Response>> {
    let expected = session.csrf(&state.shared.secret_key);
    match form.get("csrf") {
        Some(given) if constant_time_eq(given.as_bytes(), expected.as_bytes()) => Ok(()),
        _ => Err(Box::new(error_page(state, StatusCode::FORBIDDEN))),
    }
}

// Shared by every admin template: navigation state and the CSRF token for its forms.
struct AdminCtx {
    csrf: String,
    bootstrap: bool,
}

fn admin_ctx(state: &PageState, session: &Session) -> AdminCtx {
    AdminCtx {
        csrf: session.csrf(&state.shared.secret_key),
        bootstrap: session.bootstrap,
    }
}

#[derive(Template)]
#[template(path = "admin/login.html")]
struct LoginPage<'a> {
    ctx: Ctx<'a>,
    error: Option<String>,
    // The first admin key, minted by a bootstrap session that ended with it (SPEC §8).
    new_key: Option<String>,
}

async fn login_page(
    State(state): State<PageState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if authenticate(&state, &headers).await.is_ok() {
        return Redirect::to(&state.admin_href("")).into_response();
    }
    // The cookie of the session that minted the key is still sent, and the parked key is
    // bound to that session's nonce, so the signature alone is enough to hand it over once.
    let new_key = query.get("new").and_then(|nonce| {
        let session =
            cookie_value(&headers).and_then(|v| Session::decode(v, &state.shared.secret_key))?;
        take_fresh_key(&state, &session, nonce)
    });
    render(
        &state,
        LoginPage {
            ctx: state.ctx("/admin/login"),
            error: None,
            new_key,
        },
    )
}

async fn login(
    State(state): State<PageState>,
    Peer(peer): Peer,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let ip = state.shared.limiter.client_ip(peer, &headers);
    let fail = |key: &str, status: StatusCode| {
        let ctx = state.ctx("/admin/login");
        let page = LoginPage {
            error: Some(ctx.t(key)),
            ctx,
            new_key: None,
        };
        let mut response = render(&state, page);
        *response.status_mut() = status;
        response
    };
    if let Err(retry_after) = state.shared.limiter.check(Endpoint::Login, ip) {
        let mut response = fail("admin-login-limited", StatusCode::TOO_MANY_REQUESTS);
        crate::ratelimit::set_retry_after(&mut response, retry_after);
        return response;
    }

    let credential = form.get("credential").map(|c| c.trim()).unwrap_or("");
    let hash = credential_hash(credential.as_bytes());
    let bootstrap = match state.shared.admin_token_hash {
        Some(token_hash) if constant_time_eq(&hash, &token_hash) => bootstrap_allowed(&state).await,
        _ => false,
    };
    let key_ok = !bootstrap
        && matches!(state.shared.store.find_api_key(&hash).await, Ok(Some(key)) if key.scope == Scope::Admin);
    if !bootstrap && !key_ok {
        return fail("admin-login-failed", StatusCode::UNAUTHORIZED);
    }
    if key_ok {
        let _ = state.shared.store.touch_api_key(&hash, now()).await;
    }

    let mut nonce = [0u8; 16];
    if getrandom::fill(&mut nonce).is_err() {
        return error_page(&state, StatusCode::INTERNAL_SERVER_ERROR);
    }
    let issued_at = now();
    let session = Session {
        key_hash: hash,
        bootstrap,
        nonce,
        issued_at,
        expires: issued_at + SESSION_SECS,
    };
    let mut response = Redirect::to(&state.admin_href("")).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        set_cookie(
            &state,
            &session.encode(&state.shared.secret_key),
            SESSION_SECS,
        ),
    );
    response
}

// Logging out needs the CSRF token like every other form (SPEC §8), so a cross-site page
// cannot end an operator's session either.
async fn logout(
    State(state): State<PageState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let session = match authenticate(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(r) = check_csrf(&session, &state, &form) {
        return *r;
    }
    let mut response = Redirect::to(&state.admin_href("/login")).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, set_cookie(&state, "", 0));
    response
}

struct DayRow {
    day: String,
    created: i64,
    viewed: i64,
    burned: i64,
    expired: i64,
    removed: i64,
    reports: i64,
}

#[derive(Template)]
#[template(path = "admin/dashboard.html")]
struct DashboardPage<'a> {
    ctx: Ctx<'a>,
    admin: AdminCtx,
    stats: shhnote_store::Stats,
    days: Vec<DayRow>,
}

async fn dashboard(State(state): State<PageState>, headers: HeaderMap) -> Response {
    let session = match authenticate(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let store = &state.shared.store;
    let stats = match store.stats().await {
        Ok(stats) => stats,
        Err(e) => return db_error(&state, e),
    };
    let daily = match store.daily(now() - 30 * DAY).await {
        Ok(daily) => daily,
        Err(e) => return db_error(&state, e),
    };
    let days = daily
        .into_iter()
        .rev()
        .map(|d| DayRow {
            day: format_date(d.day),
            created: d.created,
            viewed: d.viewed,
            burned: d.burned,
            expired: d.expired,
            removed: d.removed,
            reports: d.reports,
        })
        .collect();
    render(
        &state,
        DashboardPage {
            ctx: state.ctx("/admin"),
            admin: admin_ctx(&state, &session),
            stats,
            days,
        },
    )
}

struct Field {
    key: &'static str,
    value: String,
    default: String,
}

// One tab on the settings page. Order here is the order on screen.
struct Group {
    key: &'static str,
    fields: Vec<Field>,
}

const GROUPS: &[(&str, &[&str])] = &[
    (
        "general",
        &[
            "site_name",
            "contact_email",
            "security_email",
            "source_url",
            "project_url",
            "regions",
            "allowed_origins",
        ],
    ),
    (
        "secrets",
        &[
            "default_ttl_secs",
            "ttl_presets",
            "min_ttl_secs",
            "max_ttl_secs",
            "claim_window_secs",
            "text_max_bytes",
            "files_enabled",
        ],
    ),
    (
        "storage",
        &[
            "padding_mode",
            "padding_min",
            "padding_ladder",
            "inline_enabled",
        ],
    ),
    (
        "limits",
        &[
            "rate_create_per_hour",
            "rate_reveal_per_hour",
            "rate_confirm_per_hour",
            "rate_burn_per_hour",
            "rate_report_per_hour",
            "rate_login_per_hour",
            "rate_user_multiplier",
            "salt_rotation_secs",
            "require_api_key_for_create",
        ],
    ),
    ("stats", &["daily_retention_days"]),
];

#[derive(Template)]
#[template(path = "admin/settings.html")]
struct SettingsPage<'a> {
    ctx: Ctx<'a>,
    admin: AdminCtx,
    groups: Vec<Group>,
    errors: Vec<String>,
    saved: bool,
}

// `shown` overrides what the form displays, so a rejected submission keeps the typed values.
fn groups(current: &Settings, shown: Option<&HashMap<String, String>>) -> Vec<Group> {
    let defaults = Settings::default().as_strings();
    let values = current.as_strings();
    let mut groups: Vec<Group> = GROUPS
        .iter()
        .map(|(key, members)| Group {
            key,
            fields: members
                .iter()
                .map(|member| Field {
                    key: member,
                    value: shown
                        .and_then(|s| s.get(*member).cloned())
                        .or_else(|| values.get(member).cloned())
                        .unwrap_or_default(),
                    default: defaults.get(member).cloned().unwrap_or_default(),
                })
                .collect(),
        })
        .collect();
    // A setting that is not in any group is a bug worth noticing in development.
    let placed: usize = GROUPS.iter().map(|(_, m)| m.len()).sum();
    debug_assert_eq!(placed, values.len(), "every setting needs a group");
    if placed != values.len() {
        let known: Vec<&str> = GROUPS.iter().flat_map(|(_, m)| m.iter().copied()).collect();
        let rest = values
            .iter()
            .filter(|(k, _)| !known.contains(k))
            .map(|(k, v)| Field {
                key: k,
                value: v.clone(),
                default: defaults.get(k).cloned().unwrap_or_default(),
            })
            .collect();
        groups.push(Group {
            key: "other",
            fields: rest,
        });
    }
    groups
}

async fn settings_page(
    State(state): State<PageState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let session = match authenticate(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let current = state.shared.settings.load();
    render(
        &state,
        SettingsPage {
            ctx: state.ctx("/admin/settings"),
            admin: admin_ctx(&state, &session),
            groups: groups(&current, None),
            errors: Vec::new(),
            saved: query.contains_key("saved"),
        },
    )
}

// Validates the whole form, then stores only the values that differ from the code defaults.
async fn settings_save(
    State(state): State<PageState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let session = match authenticate(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(r) = check_csrf(&session, &state, &form) {
        return *r;
    }
    let defaults = Settings::default().as_strings();
    let mut submitted: HashMap<String, String> = HashMap::new();
    for key in defaults.keys() {
        // Unchecked checkboxes are absent from the form.
        let value = form
            .get(*key)
            .cloned()
            .unwrap_or_else(|| "false".to_string());
        submitted.insert(key.to_string(), value);
    }
    // Saved: redirect, so a refresh re-reads the page instead of re-posting the form.
    // Invalid: the form comes back with what was typed, as a 422.
    match save_settings(
        &state.shared.store,
        &state.shared.settings,
        &submitted,
        state.shared.env,
        state.shared.max_blob_bytes,
    )
    .await
    {
        Ok(_) => Redirect::to(&format!("{}?saved", state.admin_href("/settings"))).into_response(),
        Err(SaveError::Invalid(errors)) => {
            let current = state.shared.settings.load();
            let mut response = render(
                &state,
                SettingsPage {
                    ctx: state.ctx("/admin/settings"),
                    admin: admin_ctx(&state, &session),
                    groups: groups(&current, Some(&submitted)),
                    errors,
                    saved: false,
                },
            );
            *response.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
            response
        }
        Err(SaveError::Db(e)) => db_error(&state, e),
    }
}

struct KeyRow {
    hash_hex: String,
    name: String,
    scope: &'static str,
    created: String,
    last_used: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/keys.html")]
struct KeysPage<'a> {
    ctx: Ctx<'a>,
    admin: AdminCtx,
    rows: Vec<KeyRow>,
    // Shown exactly once, right after creation.
    new_key: Option<String>,
    error: Option<String>,
}

fn key_rows(keys: Vec<ApiKey>) -> Vec<KeyRow> {
    keys.into_iter()
        .map(|k| KeyRow {
            hash_hex: hex(&k.key_hash),
            name: k.name,
            scope: k.scope.as_str(),
            created: format_time(k.created_at),
            last_used: k.last_used_on.map(format_date),
        })
        .collect()
}

async fn keys_page(
    State(state): State<PageState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let session = match authenticate(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let new_key = query
        .get("new")
        .and_then(|nonce| take_fresh_key(&state, &session, nonce));
    render_keys(&state, &session, new_key, None).await
}

// Parks a minted key and returns the nonce the redirect carries.
fn park_fresh_key(state: &PageState, session: &Session, key: String) -> Option<String> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).ok()?;
    let nonce = URL_SAFE_NO_PAD.encode(random);
    let now = now();
    let mut fresh = state
        .shared
        .fresh_keys
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    fresh.retain(|k| k.expires > now);
    fresh.push(FreshKey {
        nonce: nonce.clone(),
        session_nonce: session.nonce,
        key,
        expires: now + FRESH_KEY_SECS,
    });
    Some(nonce)
}

// The parked key for this nonce and session, removed on the way out: shown once, then gone.
fn take_fresh_key(state: &PageState, session: &Session, nonce: &str) -> Option<String> {
    let now = now();
    let mut fresh = state
        .shared
        .fresh_keys
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    fresh.retain(|k| k.expires > now);
    let at = fresh.iter().position(|k| {
        constant_time_eq(k.nonce.as_bytes(), nonce.as_bytes())
            && constant_time_eq(&k.session_nonce, &session.nonce)
    })?;
    Some(fresh.swap_remove(at).key)
}

async fn render_keys(
    state: &PageState,
    session: &Session,
    new_key: Option<String>,
    error: Option<String>,
) -> Response {
    let keys = match state.shared.store.list_api_keys().await {
        Ok(keys) => keys,
        Err(e) => return db_error(state, e),
    };
    render(
        state,
        KeysPage {
            ctx: state.ctx("/admin/keys"),
            admin: admin_ctx(state, session),
            rows: key_rows(keys),
            new_key,
            error,
        },
    )
}

async fn keys_create(
    State(state): State<PageState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let session = match authenticate(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(r) = check_csrf(&session, &state, &form) {
        return *r;
    }
    let name = form.get("name").map(|n| n.trim()).unwrap_or("");
    let scope = form.get("scope").and_then(|s| Scope::parse(s));
    let (Some(scope), false) = (scope, name.is_empty() || name.len() > 80) else {
        let error = state.ctx("/admin/keys").t("admin-keys-invalid");
        return render_keys(&state, &session, None, Some(error)).await;
    };
    // The key travels to the next page through a one-time nonce, never in this response.
    // The first admin key ends the bootstrap session that minted it, so that one is shown
    // on the login page instead, ready to sign in with.
    let next = if session.bootstrap && scope == Scope::Admin {
        "/login"
    } else {
        "/keys"
    };
    match mint_key(&state.shared.store, name, scope, now()).await {
        Ok(text) => match park_fresh_key(&state, &session, text) {
            Some(nonce) => {
                Redirect::to(&format!("{}?new={nonce}", state.admin_href(next))).into_response()
            }
            None => error_page(&state, StatusCode::INTERNAL_SERVER_ERROR),
        },
        Err(e) => db_error(&state, e),
    }
}

async fn keys_delete(
    State(state): State<PageState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let session = match authenticate(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(r) = check_csrf(&session, &state, &form) {
        return *r;
    }
    let Some(hash) = form.get("key_hash").and_then(|h| unhex(h)) else {
        return error_page(&state, StatusCode::BAD_REQUEST);
    };
    if let Err(e) = state.shared.store.delete_api_key(&hash).await {
        return db_error(&state, e);
    }
    Redirect::to(&state.admin_href("/keys")).into_response()
}

// Ends the key's sessions without deleting it (SPEC §8); the key keeps working for the API.
async fn keys_end_sessions(
    State(state): State<PageState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let session = match authenticate(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(r) = check_csrf(&session, &state, &form) {
        return *r;
    }
    let Some(hash) = form.get("key_hash").and_then(|h| unhex(h)) else {
        return error_page(&state, StatusCode::BAD_REQUEST);
    };
    if let Err(e) = state.shared.store.end_api_key_sessions(&hash, now()).await {
        return db_error(&state, e);
    }
    Redirect::to(&state.admin_href("/keys")).into_response()
}

pub(crate) enum SaveError {
    Invalid(Vec<String>),
    Db(shhnote_store::Error),
}

// Validates a complete set of settings, stores only what differs from the defaults and
// swaps the live settings. Shared by the panel and the admin API.
pub(crate) async fn save_settings(
    store: &Store,
    cell: &SettingsCell,
    submitted: &HashMap<String, String>,
    env: AppEnv,
    max_blob_bytes: u64,
) -> Result<Settings, SaveError> {
    let (mut settings, mut errors) = Settings::with_overrides(submitted, env);
    errors.extend(settings.check_blob_limit(max_blob_bytes));
    // Setup is derived from these two being set (D-29); once set they can change but not go
    // back to empty, so the setup gate never re-arms.
    let current = cell.load();
    for (key, before, after) in [
        ("site_name", &current.site_name, &settings.site_name),
        (
            "contact_email",
            &current.contact_email,
            &settings.contact_email,
        ),
    ] {
        if !before.is_empty() && after.is_empty() {
            errors.push(format!("setting {key} cannot be cleared once set"));
        }
    }
    if !errors.is_empty() {
        return Err(SaveError::Invalid(errors));
    }
    let defaults = Settings::default().as_strings();
    for (key, value) in settings.as_strings() {
        let result = if defaults.get(key) == Some(&value) {
            store.clear_setting(key).await
        } else {
            store.set_setting(key, &value).await
        };
        result.map_err(SaveError::Db)?;
    }
    cell.store(settings.clone());
    Ok(settings)
}

// A new API key: 32 random bytes, returned once, stored only as a hash.
pub(crate) async fn mint_key(
    store: &Store,
    name: &str,
    scope: Scope,
    now: i64,
) -> Result<String, shhnote_store::Error> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| shhnote_store::Error::Protocol(e.to_string()))?;
    let text = URL_SAFE_NO_PAD.encode(key);
    store
        .create_api_key(&credential_hash(text.as_bytes()), name, scope, now)
        .await?;
    Ok(text)
}

fn db_error(state: &PageState, error: shhnote_store::Error) -> Response {
    crate::log_error!("admin: database error: {error}");
    error_page(state, StatusCode::INTERNAL_SERVER_ERROR)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// A key id as the panel and API print it: exactly the 64 hex digits of the hash. The digit
// check comes first, so slicing by byte offset can never land inside a multibyte character.
pub(crate) fn unhex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_round_trip_and_reject_tampering() {
        let secret = b"a secret key of some length.....";
        let session = Session {
            key_hash: [3; 32],
            bootstrap: true,
            nonce: [9; 16],
            issued_at: 1_799_956_800,
            expires: 1_800_000_000,
        };
        let text = session.encode(secret);
        let back = Session::decode(&text, secret).unwrap();
        assert_eq!(
            (
                back.key_hash,
                back.bootstrap,
                back.nonce,
                back.issued_at,
                back.expires
            ),
            ([3; 32], true, [9; 16], 1_799_956_800, 1_800_000_000)
        );
        assert!(Session::decode(&text, b"another secret key of some length").is_none());
        let mut forged = text.clone();
        forged.replace_range(2..3, if &text[2..3] == "A" { "B" } else { "A" });
        assert!(Session::decode(&forged, secret).is_none());
        assert_eq!(session.csrf(secret), session.csrf(secret));
        assert_ne!(
            session.csrf(secret),
            Session {
                nonce: [8; 16],
                ..session
            }
            .csrf(secret)
        );
    }

    #[test]
    fn unhex_accepts_only_a_full_hex_hash() {
        let id = hex(&[0xab; 32]);
        assert_eq!(unhex(&id), Some([0xab; 32]));
        for bad in [
            "",
            "ab",
            &id[..62],
            &format!("{id}ab"),
            &format!("0é{}", "0".repeat(61)),
            &format!("zz{}", &id[2..]),
        ] {
            assert_eq!(unhex(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn reads_the_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; shh_admin=abc.def; x=y"),
        );
        assert_eq!(cookie_value(&headers), Some("abc.def"));
    }
}
