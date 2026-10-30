use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Multipart, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use shhnote_core::{
    config::Config,
    fragment,
    padding::PaddingPolicy,
    padding::blob_len,
    secret::credential_hash,
    settings::{Region, Settings, SettingsCell},
};
use shhnote_store::{Lifetime, NewSecret, Served, Store};

use crate::{
    ratelimit::{Endpoint, RateLimiter, limit},
    storage::{Blobs, Spool},
};

pub const CLAIM_TOKEN_HEADER: HeaderName = HeaderName::from_static("x-shh-claim-token");
pub const EXPIRES_IN_HEADER: HeaderName = HeaderName::from_static("x-shh-expires-in-hours");

#[derive(Clone)]
pub struct ApiState {
    pub store: Store,
    pub settings: Arc<SettingsCell>,
    pub limits: Limits,
    pub limiter: Arc<RateLimiter>,
    // The external tier, if `SHH_STORAGE` enables one.
    pub storage: Option<Arc<Blobs>>,
    // SHA-256 of SHH_ADMIN_TOKEN; honoured only while no admin key exists (SPEC §8).
    pub admin_token_hash: Option<[u8; 32]>,
}

impl ApiState {
    pub fn new(
        store: Store,
        settings: Settings,
        config: &Config,
        storage: Option<Arc<Blobs>>,
    ) -> Self {
        let settings = Arc::new(SettingsCell::new(settings));
        let limiter = RateLimiter::new(settings.clone(), config.trusted_proxies.clone());
        Self {
            store,
            settings,
            limits: Limits::from_config(config),
            limiter: Arc::new(limiter),
            storage,
            admin_token_hash: config
                .admin_token
                .as_ref()
                .map(|t| credential_hash(t.expose().as_bytes())),
        }
    }
}

// Deployment limits from the environment, as opposed to runtime settings from the database.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub inline_max: u64,
    pub external_max_object: u64,
    pub external_enabled: bool,
}

impl Limits {
    pub fn from_config(config: &Config) -> Self {
        Self {
            inline_max: config.storage.inline_max,
            external_max_object: config.storage.external_max_object,
            external_enabled: config.storage.external.is_some(),
        }
    }

    fn max_blob_bytes(self) -> u64 {
        if self.external_enabled {
            self.external_max_object
        } else {
            self.inline_max
        }
    }
}

// Each API version gets its own router, so a new version can change things without breaking the old one.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .nest("/v1", v1(state))
        .fallback(endpoint_not_found)
}

fn v1(state: ApiState) -> Router {
    // Room for the multipart framing around the largest blob we accept.
    let body_limit = (state.limits.max_blob_bytes() + 16 * 1024) as usize;
    let limited =
        |endpoint: Endpoint| middleware::from_fn_with_state((state.clone(), endpoint), limit);
    Router::new()
        .route("/", get(info))
        .route("/config", get(config))
        .route(
            "/secrets",
            post(create)
                .layer(DefaultBodyLimit::max(body_limit))
                .layer(limited(Endpoint::Create)),
        )
        .route(
            "/secrets/reveal",
            post(reveal).layer(limited(Endpoint::Reveal)),
        )
        .route(
            "/secrets/confirm",
            post(confirm).layer(limited(Endpoint::Confirm)),
        )
        .route("/secrets/burn", post(burn).layer(limited(Endpoint::Burn)))
        .route("/reports", post(report).layer(limited(Endpoint::Report)))
        .nest("/admin", crate::admin_api::routes(state.clone()))
        .with_state(state)
}

#[derive(Serialize)]
struct Info {
    name: &'static str,
    version: &'static str,
}

async fn info() -> Json<Info> {
    Json(Info {
        name: "shhnote",
        version: "v1",
    })
}

// Instance policy for clients and integrators. Nothing here is per-secret (SPEC §4).
#[derive(Serialize)]
struct ConfigResponse<'a> {
    fragment_version: u8,
    padding: PaddingResponse<'a>,
    inline_max: u64,
    max_blob_bytes: u64,
    claim_window_secs: i64,
    min_ttl_secs: i64,
    max_ttl_secs: i64,
    default_ttl_secs: i64,
    ttl_presets: &'a [i64],
    text_max_bytes: u64,
    files_enabled: bool,
    regions: &'a [Region],
}

#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
enum PaddingResponse<'a> {
    Padme { min: u64 },
    Buckets { ladder: &'a [u64] },
}

async fn config(State(state): State<ApiState>) -> Json<ConfigResponse<'static>> {
    // The settings live for the process, so handing out references is fine.
    let settings: &'static Settings = Box::leak(Box::new((*state.settings.load()).clone()));
    Json(ConfigResponse {
        fragment_version: fragment::VERSION,
        padding: match &settings.padding {
            PaddingPolicy::Padme { min } => PaddingResponse::Padme { min: *min },
            PaddingPolicy::Buckets { ladder } => PaddingResponse::Buckets { ladder },
        },
        inline_max: state.limits.inline_max,
        max_blob_bytes: state.limits.max_blob_bytes(),
        claim_window_secs: settings.claim_window_secs,
        min_ttl_secs: settings.min_ttl_secs,
        max_ttl_secs: settings.max_ttl_secs,
        default_ttl_secs: settings.default_ttl_secs,
        ttl_presets: &settings.ttl_presets,
        text_max_bytes: settings.text_max_bytes,
        files_enabled: settings.files_enabled,
        regions: &settings.regions,
    })
}

#[derive(Deserialize)]
struct CreateMeta {
    lookup_key: String,
    burn_key: String,
    lifetime: String,
    ttl_seconds: i64,
}

// `meta` comes first so the request can be refused before the blob is read.
async fn create(
    State(state): State<ApiState>,
    mut multipart: Multipart,
) -> Result<StatusCode, ApiError> {
    let meta_field = next_field(&mut multipart, "meta").await?;
    let meta_text = meta_field.text().await.map_err(multipart_error)?;
    if meta_text.len() > 4096 {
        return Err(ApiError::bad_request("invalid_meta"));
    }
    let meta: CreateMeta =
        serde_json::from_str(&meta_text).map_err(|_| ApiError::bad_request("invalid_meta"))?;
    let lookup_key =
        decode32(&meta.lookup_key).ok_or(ApiError::bad_request("invalid_lookup_key"))?;
    let burn_key = decode32(&meta.burn_key).ok_or(ApiError::bad_request("invalid_burn_key"))?;
    let lifetime =
        Lifetime::parse(&meta.lifetime).ok_or(ApiError::bad_request("invalid_lifetime"))?;
    let settings = state.settings.load();
    if !(settings.min_ttl_secs..=settings.max_ttl_secs).contains(&meta.ttl_seconds) {
        return Err(ApiError::bad_request("invalid_ttl"));
    }

    let mut blob_field = next_field(&mut multipart, "blob").await?;
    // Small blobs stay in memory; once one outgrows the inline tier it is spooled to disk.
    // With the inline tier switched off (and an external one present) nothing stays in memory.
    let inline_allowed = settings.inline_enabled || state.storage.is_none();
    let memory_limit = if inline_allowed {
        blob_len(state.limits.inline_max) as usize
    } else {
        0
    };
    let mut sink = Sink::Memory(Vec::new());
    while let Some(chunk) = blob_field.chunk().await.map_err(multipart_error)? {
        if let (Sink::Memory(buf), Some(storage)) = (&mut sink, &state.storage)
            && buf.len() + chunk.len() > memory_limit
        {
            let mut spool = storage.spool().await.map_err(ApiError::internal)?;
            spool.write(buf).await.map_err(ApiError::internal)?;
            sink = Sink::Spool(spool);
        }
        match &mut sink {
            Sink::Memory(buf) => buf.extend_from_slice(&chunk),
            Sink::Spool(spool) => spool.write(&chunk).await.map_err(ApiError::internal)?,
        }
    }
    let len = match &sink {
        Sink::Memory(buf) => buf.len() as u64,
        Sink::Spool(spool) => spool.bytes_written(),
    };
    let bucket = settings
        .padding
        .bucket_for_blob_len(len)
        .map_err(|_| ApiError::bad_request("invalid_blob_length"))?;
    if bucket > state.limits.max_blob_bytes() {
        return Err(ApiError::TooLarge);
    }
    // The server cannot tell files from text, but with files switched off nothing larger than
    // the biggest possible text secret needs to be accepted (SPEC §6).
    if !settings.files_enabled && bucket > text_only_bucket(&settings) {
        return Err(ApiError::bad_request("files_disabled"));
    }

    let now = now();
    let expires_at = now + meta.ttl_seconds;
    let secret = |blob, external_ref| NewSecret {
        lookup_key,
        burn_key,
        lifetime,
        bucket,
        blob,
        external_ref,
        expires_at,
    };
    match sink {
        Sink::Memory(buf) if bucket <= state.limits.inline_max && inline_allowed => {
            match state.store.create(&secret(Some(buf), None), now).await {
                Ok(true) => Ok(StatusCode::CREATED),
                Ok(false) => Err(ApiError::bad_request("duplicate_key")),
                Err(e) => Err(ApiError::internal(e)),
            }
        }
        // A blob above the inline ceiling that never spilled means there is no external tier.
        Sink::Memory(_) => Err(ApiError::TooLarge),
        Sink::Spool(spool) => {
            let storage = state.storage.as_ref().ok_or(ApiError::Internal)?;
            // The tier ceiling counts everything in it, pending deletes included (SPEC §6).
            let used = state
                .store
                .external_bytes()
                .await
                .map_err(ApiError::internal)?;
            if used + bucket > storage.max_total_bytes() {
                return Err(ApiError::StorageFull);
            }
            let spooled = spool.finish().await.map_err(ApiError::internal)?;
            let key = Blobs::new_key().map_err(ApiError::internal)?;
            storage
                .put(&key, spooled)
                .await
                .map_err(ApiError::internal)?;
            // Only an active row makes the object reachable; without one it is garbage.
            match state
                .store
                .create(&secret(None, Some(key.clone())), now)
                .await
            {
                Ok(true) => Ok(StatusCode::CREATED),
                other => {
                    if let Err(e) = storage.delete(&key).await {
                        eprintln!("storage: could not remove orphaned object: {e}");
                    }
                    match other {
                        Ok(_) => Err(ApiError::bad_request("duplicate_key")),
                        Err(e) => Err(ApiError::internal(e)),
                    }
                }
            }
        }
    }
}

enum Sink {
    Memory(Vec<u8>),
    Spool(Spool),
}

// The largest padded size a text-only secret can need: the text limit with room for JSON
// escaping (worst case doubles it) and the manifest around it.
fn text_only_bucket(settings: &Settings) -> u64 {
    let payload = 2 * settings.text_max_bytes + 1024;
    settings.padding.padded_size(payload).unwrap_or(0)
}

#[derive(Deserialize)]
struct RevealBody {
    lookup: String,
    claim_token: Option<String>,
}

// Single-view: claim (or re-download with the claim token). TTL: plain read. Anything else: the uniform negative.
async fn reveal(
    State(state): State<ApiState>,
    Json(body): Json<RevealBody>,
) -> Result<Response, ApiError> {
    let lookup_key = credential_hash(&decode32_or_random(&body.lookup)?);
    let now = now();

    if let Some(token) = &body.claim_token {
        let claim_key = credential_hash(&decode32_or_random(token)?);
        return match state.store.redownload(&lookup_key, &claim_key, now).await {
            Ok(Some(served)) => blob_response(&state, served, HeaderMap::new()).await,
            Ok(None) => Err(ApiError::NotFound),
            Err(e) => Err(ApiError::internal(e)),
        };
    }

    let mut token = [0u8; 32];
    getrandom::fill(&mut token).map_err(|_| ApiError::Internal)?;
    let claim_key = credential_hash(&token);
    let window = state.settings.load().claim_window_secs;
    match state
        .store
        .claim(&lookup_key, &claim_key, now, window)
        .await
    {
        Ok(Some(served)) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                CLAIM_TOKEN_HEADER,
                header_value(&URL_SAFE_NO_PAD.encode(token)),
            );
            return blob_response(&state, served, headers).await;
        }
        Ok(None) => {}
        Err(e) => return Err(ApiError::internal(e)),
    }

    match state.store.read_ttl(&lookup_key, now).await {
        Ok(Some(ttl)) => {
            // Whole hours, rounded up: coarse on purpose, and never an absolute time.
            let remaining = (ttl.expires_at - now).max(1);
            let hours = (remaining + 3599) / 3600;
            let mut headers = HeaderMap::new();
            headers.insert(EXPIRES_IN_HEADER, header_value(&hours.to_string()));
            blob_response(&state, ttl.served, headers).await
        }
        Ok(None) => Err(ApiError::NotFound),
        Err(e) => Err(ApiError::internal(e)),
    }
}

// Inline blobs come from the row; external ones are streamed through the server, never
// linked to directly (SPEC §6).
async fn blob_response(
    state: &ApiState,
    served: Served,
    mut headers: HeaderMap,
) -> Result<Response, ApiError> {
    let body = match (served.blob, served.external_ref) {
        (Some(blob), _) => Body::from(blob),
        (None, Some(key)) => {
            let storage = state.storage.as_ref().ok_or_else(|| {
                ApiError::internal("external blob requested but no external tier is configured")
            })?;
            storage.get(&key).await.map_err(ApiError::internal)?
        }
        (None, None) => return Err(ApiError::internal("row has neither blob nor object")),
    };
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_LENGTH,
        header_value(&blob_len(served.bucket).to_string()),
    );
    Ok((StatusCode::OK, headers, body).into_response())
}

#[derive(Deserialize)]
struct ConfirmBody {
    lookup: String,
    claim_token: String,
}

async fn confirm(
    State(state): State<ApiState>,
    Json(body): Json<ConfirmBody>,
) -> Result<StatusCode, ApiError> {
    let lookup_key = credential_hash(&decode32_or_random(&body.lookup)?);
    let claim_key = credential_hash(&decode32_or_random(&body.claim_token)?);
    match state.store.confirm(&lookup_key, &claim_key, now()).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(ApiError::NotFound),
        Err(e) => Err(ApiError::internal(e)),
    }
}

#[derive(Deserialize)]
struct BurnBody {
    burn_token: String,
}

async fn burn(
    State(state): State<ApiState>,
    Json(body): Json<BurnBody>,
) -> Result<StatusCode, ApiError> {
    let burn_key = credential_hash(&decode32_or_random(&body.burn_token)?);
    match state.store.burn(&burn_key, now()).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(ApiError::NotFound),
        Err(e) => Err(ApiError::internal(e)),
    }
}

#[derive(Deserialize)]
struct ReportBody {
    lookup: String,
}

#[derive(Serialize)]
struct ReportResponse {
    status: &'static str,
}

// Always the same answer. A malformed identifier is not notice, so it gets no ledger row.
async fn report(
    State(state): State<ApiState>,
    Json(body): Json<ReportBody>,
) -> Result<Json<ReportResponse>, ApiError> {
    if let Some(lookup) = decode32(&body.lookup) {
        state
            .store
            .report(&credential_hash(&lookup), now())
            .await
            .map_err(ApiError::internal)?;
    }
    Ok(Json(ReportResponse { status: "received" }))
}

async fn next_field<'a>(
    multipart: &'a mut Multipart,
    expected: &str,
) -> Result<axum::extract::multipart::Field<'a>, ApiError> {
    let field = multipart
        .next_field()
        .await
        .map_err(multipart_error)?
        .ok_or(ApiError::bad_request("invalid_multipart"))?;
    if field.name() != Some(expected) {
        return Err(ApiError::bad_request("invalid_multipart"));
    }
    Ok(field)
}

// The body limit surfaces as a multipart error; keep it a 413 rather than a generic 400.
fn multipart_error(e: axum::extract::multipart::MultipartError) -> ApiError {
    if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::TooLarge
    } else {
        ApiError::bad_request("invalid_multipart")
    }
}

fn decode32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 43 {
        return None;
    }
    URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()
}

// Malformed identifiers are replaced by fresh random bytes and run through the full path,
// so they cost the same as a real miss and can never hit a planted row (SPEC §4).
fn decode32_or_random(text: &str) -> Result<[u8; 32], ApiError> {
    match decode32(text) {
        Some(bytes) => Ok(bytes),
        None => {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| ApiError::Internal)?;
            Ok(bytes)
        }
    }
}

fn header_value(text: &str) -> HeaderValue {
    HeaderValue::from_str(text).expect("base64url and digits are valid header text")
}

pub use crate::clock::now;

pub enum ApiError {
    BadRequest(&'static str),
    TooLarge,
    // The external tier's ceiling is reached; small secrets still work.
    StorageFull,
    // The one response every failed secret operation gets (SPEC §4).
    NotFound,
    Internal,
}

impl ApiError {
    fn bad_request(code: &'static str) -> Self {
        Self::BadRequest(code)
    }

    fn internal(e: impl std::fmt::Display) -> Self {
        eprintln!("store error: {e}");
        Self::Internal
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: &'static str,
}

pub(crate) fn error_response(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Response {
    let body = ErrorBody {
        error: ErrorDetail { code, message },
    };
    (status, Json(body)).into_response()
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(code) => {
                error_response(StatusCode::BAD_REQUEST, code, "The request is not valid.")
            }
            Self::TooLarge => error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                "The blob is larger than this instance accepts.",
            ),
            Self::StorageFull => error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "storage_full",
                "This instance has no room for large secrets right now.",
            ),
            Self::NotFound => uniform_negative(),
            Self::Internal => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "Something went wrong.",
            ),
        }
    }
}

pub fn uniform_negative() -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found", "No secret matches.")
}

// API clients expect JSON errors, never the website's HTML error pages.
async fn endpoint_not_found() -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "no_such_endpoint",
        "This endpoint does not exist.",
    )
}
