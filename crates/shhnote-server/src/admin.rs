use std::collections::HashMap;

use askama::Template;
use axum::{
    Form, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use shhnote_core::{
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

pub(crate) fn routes() -> Router<PageState> {
    Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/settings", get(settings_page).post(settings_save))
        .route("/keys", get(keys_page).post(keys_create))
        .route("/keys/delete", post(keys_delete))
}

// A signed, stateless session: who is logged in and until when. Every request re-checks that
// the key still exists, so deleting a key ends its sessions.
#[derive(Clone, Copy)]
struct Session {
    key_hash: [u8; 32],
    bootstrap: bool,
    nonce: [u8; 16],
    expires: i64,
}

type HmacSha256 = Hmac<Sha256>;

fn mac(secret: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
        let mut payload = Vec::with_capacity(57);
        payload.push(u8::from(self.bootstrap));
        payload.extend_from_slice(&self.key_hash);
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
        if payload.len() != 57 || !constant_time_eq(&mac(secret, &payload), &tag) {
            return None;
        }
        Some(Self {
            bootstrap: payload[0] == 1,
            key_hash: payload[1..33].try_into().ok()?,
            expires: i64::from_be_bytes(payload[33..41].try_into().ok()?),
            nonce: payload[41..57].try_into().ok()?,
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
    let login = Box::new(Redirect::to(&state.href("/admin/login")).into_response());
    let Some(session) =
        cookie_value(headers).and_then(|v| Session::decode(v, &state.shared.secret_key))
    else {
        return Err(login);
    };
    if session.expires <= now() {
        return Err(login);
    }
    let valid = if session.bootstrap {
        bootstrap_allowed(state).await
    } else {
        matches!(state.shared.store.find_api_key(&session.key_hash).await, Ok(Some(key)) if key.scope == Scope::Admin)
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
}

async fn login_page(State(state): State<PageState>, headers: HeaderMap) -> Response {
    if authenticate(&state, &headers).await.is_ok() {
        return Redirect::to(&state.href("/admin")).into_response();
    }
    render(
        &state,
        LoginPage {
            ctx: state.ctx("/admin/login"),
            error: None,
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
        };
        let mut response = render(&state, page);
        *response.status_mut() = status;
        response
    };
    if state.shared.limiter.check(Endpoint::Login, ip).is_err() {
        return fail("admin-login-limited", StatusCode::TOO_MANY_REQUESTS);
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
    let session = Session {
        key_hash: hash,
        bootstrap,
        nonce,
        expires: now() + SESSION_SECS,
    };
    let mut response = Redirect::to(&state.href("/admin")).into_response();
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

async fn logout(State(state): State<PageState>) -> Response {
    let mut response = Redirect::to(&state.href("/admin/login")).into_response();
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
            "regions",
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

async fn settings_page(State(state): State<PageState>, headers: HeaderMap) -> Response {
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
            saved: false,
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
    let new_settings =
        match save_settings(&state.shared.store, &state.shared.settings, &submitted).await {
            Ok(settings) => settings,
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
                return response;
            }
            Err(SaveError::Db(e)) => return db_error(&state, e),
        };
    render(
        &state,
        SettingsPage {
            ctx: state.ctx("/admin/settings"),
            admin: admin_ctx(&state, &session),
            groups: groups(&new_settings, None),
            errors: Vec::new(),
            saved: true,
        },
    )
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

async fn keys_page(State(state): State<PageState>, headers: HeaderMap) -> Response {
    let session = match authenticate(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    render_keys(&state, &session, None, None).await
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
    match mint_key(&state.shared.store, name, scope, now()).await {
        Ok(text) => render_keys(&state, &session, Some(text), None).await,
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
    Redirect::to(&state.href("/admin/keys")).into_response()
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
) -> Result<Settings, SaveError> {
    let (settings, errors) = Settings::with_overrides(submitted);
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.len() > 128 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
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
            expires: 1_800_000_000,
        };
        let text = session.encode(secret);
        let back = Session::decode(&text, secret).unwrap();
        assert_eq!(
            (back.key_hash, back.bootstrap, back.nonce, back.expires),
            ([3; 32], true, [9; 16], 1_800_000_000)
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
    fn reads_the_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; shh_admin=abc.def; x=y"),
        );
        assert_eq!(cookie_value(&headers), Some("abc.def"));
    }
}
