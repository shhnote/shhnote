use std::collections::{BTreeMap, HashMap};

use axum::{
    Json, Router,
    extract::{FromRequest, Query, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use shhnote_core::{secret::credential_hash, settings::Settings};
use shhnote_store::Scope;

use crate::{
    admin::{SaveError, constant_time_eq, hex, mint_key, save_settings, unhex},
    api::{ApiState, error_response},
    clock::{format_date, now},
    ratelimit::{Endpoint, peer_of},
};

// The admin panel's operations as JSON (SPEC §8): the same checks, the same store calls,
// for operators who script their instance.
pub fn routes(state: ApiState) -> Router<ApiState> {
    Router::new()
        .route("/stats", get(stats))
        .route("/settings", get(settings).patch(settings_patch))
        .route("/keys", get(keys).post(keys_create))
        .route("/keys/delete", post(keys_delete))
        .layer(middleware::from_fn_with_state(state, require_admin))
        .layer(middleware::map_response(crate::admin::no_store))
}

// Either an `admin` API key or, on a fresh install, the bootstrap token. The login bucket is
// consulted before the lookup and charged for every failure (SPEC §8): a limited client gets
// 429 even for a right guess, so keys cannot be guessed at speed.
async fn require_admin(State(state): State<ApiState>, req: Request, next: Next) -> Response {
    let limited = error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "Too many attempts. Please wait a little and try again.",
    );
    let ip = state
        .limiter
        .client_ip(peer_of(req.extensions()), req.headers());
    if state.limiter.exhausted(Endpoint::Login, ip) {
        return limited;
    }
    let hash = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| credential_hash(token.trim().as_bytes()));
    let mut allowed = false;
    if let Some(hash) = hash {
        match state.store.find_api_key(&hash).await {
            Ok(Some(key)) if key.scope == Scope::Admin => {
                let _ = state.store.touch_api_key(&hash, now()).await;
                allowed = true;
            }
            Ok(_) => {
                if let Some(bootstrap) = state.admin_token_hash
                    && constant_time_eq(&bootstrap, &hash)
                    && matches!(state.store.admin_key_count().await, Ok(0))
                {
                    allowed = true;
                }
            }
            Err(e) => {
                crate::log_error!("admin api: database error: {e}");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "Something went wrong.",
                );
            }
        }
    }
    if !allowed {
        if state.limiter.check(Endpoint::Login, ip).is_err() {
            return limited;
        }
        return error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "An admin API key is required.",
        );
    }
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn db_error(e: shhnote_store::Error) -> Response {
    crate::log_error!("admin api: database error: {e}");
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Something went wrong.",
    )
}

#[derive(Deserialize)]
struct StatsQuery {
    days: Option<i64>,
}

#[derive(Serialize)]
struct DayOut {
    day: String,
    created: i64,
    viewed: i64,
    burned: i64,
    expired: i64,
    removed: i64,
    reports: i64,
}

#[derive(Serialize)]
struct StatsOut {
    created: i64,
    viewed: i64,
    burned: i64,
    expired: i64,
    removed: i64,
    reports: i64,
    active: i64,
    days: Vec<DayOut>,
}

async fn stats(State(state): State<ApiState>, Query(query): Query<StatsQuery>) -> Response {
    let days = query.days.unwrap_or(30).clamp(1, 400);
    let totals = match state.store.stats().await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    let daily = match state.store.daily(now() - days * 86_400).await {
        Ok(d) => d,
        Err(e) => return db_error(e),
    };
    let out = StatsOut {
        created: totals.created,
        viewed: totals.viewed,
        burned: totals.burned,
        expired: totals.expired,
        removed: totals.removed,
        reports: totals.reports,
        active: totals.active,
        days: daily
            .into_iter()
            .rev()
            .map(|d| DayOut {
                day: format_date(d.day),
                created: d.created,
                viewed: d.viewed,
                burned: d.burned,
                expired: d.expired,
                removed: d.removed,
                reports: d.reports,
            })
            .collect(),
    };
    Json(out).into_response()
}

#[derive(Serialize)]
struct SettingsOut {
    values: BTreeMap<&'static str, String>,
    defaults: BTreeMap<&'static str, String>,
    overridden: Vec<&'static str>,
}

fn settings_out(current: &Settings) -> SettingsOut {
    let values = current.as_strings();
    let defaults = Settings::default().as_strings();
    let overridden = values
        .iter()
        .filter(|(k, v)| defaults.get(*k) != Some(v))
        .map(|(k, _)| *k)
        .collect();
    SettingsOut {
        values,
        defaults,
        overridden,
    }
}

async fn settings(State(state): State<ApiState>) -> Response {
    Json(settings_out(&state.settings.load())).into_response()
}

// A JSON value as the string form a setting is stored in: scalars as text, lists of
// scalars comma-separated, anything else as JSON. `null` resets the key to its default.
fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Array(items) if items.iter().all(|i| i.is_number() || i.is_string()) => Some(
            items
                .iter()
                .map(|i| match i {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(","),
        ),
        other => Some(other.to_string()),
    }
}

#[derive(Serialize)]
struct InvalidSettings {
    error: InvalidDetail,
    details: Vec<String>,
}

#[derive(Serialize)]
struct InvalidDetail {
    code: &'static str,
    message: &'static str,
}

// Partial update: unknown keys are rejected, the rest is merged over the current values and
// validated as a whole, exactly like the panel's form.
async fn settings_patch(
    State(state): State<ApiState>,
    Strict(patch): Strict<HashMap<String, Value>>,
) -> Response {
    let defaults = Settings::default().as_strings();
    let mut submitted: HashMap<String, String> = state
        .settings
        .load()
        .as_strings()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    let mut details = Vec::new();
    for (key, value) in &patch {
        let Some(default) = defaults.get(key.as_str()) else {
            details.push(format!("unknown setting {key}"));
            continue;
        };
        submitted.insert(
            key.clone(),
            value_to_string(value).unwrap_or_else(|| default.clone()),
        );
    }
    if details.is_empty() {
        match save_settings(&state.store, &state.settings, &submitted, state.env).await {
            Ok(settings) => return Json(settings_out(&settings)).into_response(),
            Err(SaveError::Invalid(errors)) => details = errors,
            Err(SaveError::Db(e)) => return db_error(e),
        }
    }
    let body = InvalidSettings {
        error: InvalidDetail {
            code: "invalid_settings",
            message: "Nothing was changed; see details.",
        },
        details,
    };
    (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}

#[derive(Serialize)]
struct KeyOut {
    id: String,
    name: String,
    scope: &'static str,
    created_at: i64,
    last_used_on: Option<i64>,
}

async fn keys(State(state): State<ApiState>) -> Response {
    let keys = match state.store.list_api_keys().await {
        Ok(k) => k,
        Err(e) => return db_error(e),
    };
    let out: Vec<KeyOut> = keys
        .into_iter()
        .map(|k| KeyOut {
            id: hex(&k.key_hash),
            name: k.name,
            scope: k.scope.as_str(),
            created_at: k.created_at,
            last_used_on: k.last_used_on,
        })
        .collect();
    Json(serde_json::json!({ "keys": out })).into_response()
}

#[derive(Deserialize)]
struct NewKey {
    name: String,
    scope: String,
}

// A JSON body on the admin API: a rejection is answered in the shared error shape, never
// with the framework's plain-text default.
struct Strict<T>(T);

impl<S, T> FromRequest<S> for Strict<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Response> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(_) => Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "The body is not valid JSON for this endpoint.",
            )),
        }
    }
}

async fn keys_create(State(state): State<ApiState>, Strict(body): Strict<NewKey>) -> Response {
    let name = body.name.trim();
    let scope = Scope::parse(&body.scope);
    let (Some(scope), false) = (scope, name.is_empty() || name.len() > 80) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_key",
            "Give the key a name of up to 80 characters and a scope of admin or user.",
        );
    };
    let created_at = now();
    let key = match mint_key(&state.store, name, scope, created_at).await {
        Ok(key) => key,
        Err(e) => return db_error(e),
    };
    let out = serde_json::json!({
        "key": key,
        "id": hex(&credential_hash(key.as_bytes())),
        "name": name,
        "scope": scope.as_str(),
        "created_at": created_at,
    });
    (StatusCode::CREATED, Json(out)).into_response()
}

#[derive(Deserialize)]
struct DeleteKey {
    id: String,
}

async fn keys_delete(State(state): State<ApiState>, Strict(body): Strict<DeleteKey>) -> Response {
    let Some(hash) = unhex(&body.id) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_key", "Unknown key id.");
    };
    match state.store.delete_api_key(&hash).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error_response(StatusCode::NOT_FOUND, "no_such_key", "Unknown key id."),
        Err(e) => db_error(e),
    }
}
