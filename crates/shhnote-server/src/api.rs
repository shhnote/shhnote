use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, FromRequest, Multipart, Request, State, multipart::Field},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use shhnote_core::{
    config::Config,
    config::{AppEnv, WebMode},
    fragment,
    padding::PaddingPolicy,
    padding::blob_len,
    secret::credential_hash,
    settings::{Region, Settings, SettingsCell},
};
use shhnote_store::{Lifetime, NewSecret, Served, Store};
use tokio::sync::Semaphore;

use crate::{
    ratelimit::{Endpoint, RateLimiter, limit},
    storage::{Blobs, Spool, object_bytes},
};

pub const CLAIM_TOKEN_HEADER: HeaderName = HeaderName::from_static("x-shh-claim-token");
// Public on `/config`, `/health` and every page footer (D-27): tagged open-source releases.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct ApiState {
    pub store: Store,
    pub settings: Arc<SettingsCell>,
    pub limits: Limits,
    pub limiter: Arc<RateLimiter>,
    // The external tier, if `SHH_STORAGE` enables one.
    pub storage: Option<Arc<Blobs>>,
    // One permit per upload in flight (`SHH_MAX_UPLOADS`), so stalled uploads cannot pile up.
    pub uploads: Arc<Semaphore>,
    // SHA-256 of SHH_ADMIN_TOKEN; honoured only while no admin key exists (SPEC §8).
    pub admin_token_hash: Option<[u8; 32]>,
    // Decides the URL rule for settings (SPEC §7.2).
    pub env: AppEnv,
    pub web_mode: WebMode,
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
            uploads: Arc::new(Semaphore::new(config.max_uploads as usize)),
            admin_token_hash: config
                .admin_token
                .as_ref()
                .map(|t| credential_hash(t.expose().as_bytes())),
            env: config.env,
            web_mode: config.web,
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
        .route("/health", get(health))
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
    server_version: &'static str,
    web_mode: &'static str,
}

#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
enum PaddingResponse<'a> {
    Padme { min: u64 },
    Buckets { ladder: &'a [u64] },
}

async fn config(State(state): State<ApiState>) -> Response {
    // Serialised while the snapshot is held; nothing from it outlives the request.
    let settings = state.settings.load();
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
        server_version: SERVER_VERSION,
        web_mode: state.web_mode.as_str(),
    })
    .into_response()
}

// Readiness for orchestrators: the process is up and the database answers. Says nothing else.
async fn health(State(state): State<ApiState>) -> Response {
    let (status, text) = match state.store.ping().await {
        Ok(()) => (StatusCode::OK, "ok"),
        Err(e) => {
            crate::log_error!("health: database error: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, "degraded")
        }
    };
    let mut response = (
        status,
        Json(serde_json::json!({ "status": text, "version": SERVER_VERSION })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Deserialize)]
struct CreateMeta {
    lookup_key: String,
    burn_key: String,
    lifetime: String,
    ttl_seconds: i64,
}

// The `meta` part is tiny; anything bigger is not a client of ours.
const META_MAX_BYTES: usize = 4096;
// A body chunk must arrive within this; a client that goes quiet is cut (SPEC §7.1).
const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// The whole upload must finish at this rate or better, with a floor for small instances.
const UPLOAD_MIN_BYTES_PER_SEC: u64 = 32 * 1024;
const UPLOAD_MIN_DEADLINE: Duration = Duration::from_secs(60);

// Multipart framing around the blob: boundaries and part headers. The body limit allows this
// much on top of the largest blob, so a declared length is at most this far above the blob.
const FRAMING_SLACK: u64 = 16 * 1024;

// How many bytes the blob can be at most, from the request's Content-Length minus the `meta`
// part (SPEC §4: the declared length). Without a Content-Length the worst case is assumed.
fn declared_blob_upper(headers: &HeaderMap, meta_len: usize, max_blob: u64) -> u64 {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
        .map_or(max_blob + FRAMING_SLACK, |total| {
            total.saturating_sub(meta_len as u64)
        })
}

fn upload_deadline(max_blob_bytes: u64) -> Instant {
    let needed = Duration::from_secs(max_blob_bytes / UPLOAD_MIN_BYTES_PER_SEC);
    Instant::now() + needed.max(UPLOAD_MIN_DEADLINE)
}

// `meta` comes first so the request can be refused before the blob is read.
async fn create(
    State(state): State<ApiState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<StatusCode, ApiError> {
    // Held until the row is written, so the cap counts the whole upload.
    let _slot = state
        .uploads
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::TooBusy)?;
    let deadline = upload_deadline(state.limits.max_blob_bytes());
    let meta_field = next_field(&mut multipart, "meta").await?;
    let meta_bytes = read_capped(meta_field, META_MAX_BYTES).await?;
    let meta: CreateMeta =
        serde_json::from_slice(&meta_bytes).map_err(|_| ApiError::bad_request("invalid_meta"))?;
    let lookup_key =
        decode32(&meta.lookup_key).ok_or(ApiError::bad_request("invalid_lookup_key"))?;
    let burn_key = decode32(&meta.burn_key).ok_or(ApiError::bad_request("invalid_burn_key"))?;
    let lifetime =
        Lifetime::parse(&meta.lifetime).ok_or(ApiError::bad_request("invalid_lifetime"))?;
    let settings = state.settings.load();
    if !(settings.min_ttl_secs..=settings.max_ttl_secs).contains(&meta.ttl_seconds) {
        return Err(ApiError::bad_request("invalid_ttl"));
    }

    // The length, size-policy and ceiling checks run against the declared length before the
    // first blob byte is spooled, and again as bytes arrive (SPEC §6.1).
    let max_blob = blob_len(state.limits.max_blob_bytes());
    let text_only = if settings.files_enabled {
        None
    } else {
        Some(blob_len(text_only_bucket(&settings)))
    };
    let too_big = |bytes: u64| {
        if bytes > max_blob {
            Some(ApiError::TooLarge)
        } else if text_only.is_some_and(|cap| bytes > cap) {
            Some(ApiError::bad_request("files_disabled"))
        } else {
            None
        }
    };
    let upper = declared_blob_upper(&headers, meta_bytes.len(), max_blob);
    if let Some(err) = too_big(upper.saturating_sub(FRAMING_SLACK)) {
        return Err(err);
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
    let mut reservation = None;
    while let Some(chunk) = next_chunk(&mut blob_field, deadline).await? {
        if let (Sink::Memory(buf), Some(storage)) = (&mut sink, &state.storage)
            && buf.len() + chunk.len() > memory_limit
        {
            // Spilling to disk: the declared size is held against the ceiling from here on,
            // so uploads in flight can never fill the disk past it (D-20).
            reservation = Some(
                storage
                    .reserve(&state.store, upper)
                    .await
                    .map_err(ApiError::internal)?
                    .ok_or(ApiError::StorageFull)?,
            );
            let mut spool = storage.spool().await.map_err(ApiError::internal)?;
            spool.write(buf).await.map_err(ApiError::internal)?;
            sink = Sink::Spool(spool);
        }
        match &mut sink {
            Sink::Memory(buf) => buf.extend_from_slice(&chunk),
            Sink::Spool(spool) => {
                spool.write(&chunk).await.map_err(ApiError::internal)?;
                let written = spool.bytes_written();
                if written > upper {
                    return Err(ApiError::bad_request("invalid_blob_length"));
                }
                if let Some(err) = too_big(written) {
                    return Err(err);
                }
            }
        }
    }
    let len = match &sink {
        Sink::Memory(buf) => buf.len() as u64,
        Sink::Spool(spool) => spool.bytes_written(),
    };
    // A fresh snapshot: a setting changed while the body was uploading applies to it.
    let settings = state.settings.load();
    if !(settings.min_ttl_secs..=settings.max_ttl_secs).contains(&meta.ttl_seconds) {
        return Err(ApiError::bad_request("invalid_ttl"));
    }
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
    // On the expiry grid, so the row never holds the creation second (SPEC §3, D-18).
    let expires_at = shhnote_core::expiry::expires_at(now, meta.ttl_seconds);
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
                // A duplicate key is answered like a success and writes nothing (D-21): a
                // different answer would tell a hash holder whether the secret still exists.
                Ok(_) => Ok(StatusCode::CREATED),
                Err(e) => Err(ApiError::internal(e)),
            }
        }
        // A blob above the inline ceiling that never spilled means there is no external tier.
        Sink::Memory(_) => Err(ApiError::TooLarge),
        Sink::Spool(spool) => {
            let storage = state.storage.as_ref().ok_or(ApiError::Internal)?;
            // The exact size is known now; the reservation shrinks to it and the ceiling check
            // was already made when the spool started.
            let mut reservation = reservation.ok_or(ApiError::Internal)?;
            reservation.shrink_to(object_bytes(bucket));
            let spooled = spool.finish().await.map_err(ApiError::internal)?;
            let key = Blobs::new_key().map_err(ApiError::internal)?;
            storage
                .put(&key, spooled)
                .await
                .map_err(ApiError::internal)?;
            // Only an active row makes the object reachable; without one it is garbage, and
            // the guard removes it if the request is cancelled before the row is written.
            let guard = OrphanGuard {
                storage: storage.clone(),
                key: key.clone(),
                armed: true,
            };
            match state
                .store
                .create(&secret(None, Some(key.clone())), now)
                .await
            {
                Ok(true) => {
                    guard.disarm();
                    reservation.commit();
                    Ok(StatusCode::CREATED)
                }
                // Duplicate (D-21): the object goes, the reservation is given back, and the
                // answer is the same 201.
                Ok(false) => {
                    drop(guard);
                    Ok(StatusCode::CREATED)
                }
                Err(e) => {
                    drop(guard);
                    Err(ApiError::internal(e))
                }
            }
        }
    }
}

enum Sink {
    Memory(Vec<u8>),
    Spool(Spool),
}

// Deletes a freshly written object unless the row for it was written. Dropping a request
// mid-way (the client went away) runs this like any other error path.
struct OrphanGuard {
    storage: Arc<Blobs>,
    key: String,
    armed: bool,
}

impl OrphanGuard {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for OrphanGuard {
    fn drop(&mut self) {
        if self.armed {
            let storage = self.storage.clone();
            let key = std::mem::take(&mut self.key);
            tokio::spawn(async move {
                if let Err(e) = storage.delete(&key).await {
                    crate::log_error!("storage: could not remove orphaned object: {e}");
                }
            });
        }
    }
}

// The largest padded size a text-only secret can need: the text limit with room for JSON
// escaping (worst case doubles it) and the manifest around it.
fn text_only_bucket(settings: &Settings) -> u64 {
    let payload = settings
        .text_max_bytes
        .saturating_mul(2)
        .saturating_add(1024);
    settings.padding.padded_size(payload).unwrap_or(0)
}

// A JSON body on a credential endpoint. Anything the framework would reject (bad JSON, wrong
// types, missing fields, no Content-Type) becomes an empty body instead, so the handler runs
// its normal path with random credentials and the answer stays uniform (SPEC §4).
struct Lenient<T>(T);

impl<S, T> FromRequest<S> for Lenient<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Default,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        let body = Bytes::from_request(req, state).await.unwrap_or_default();
        Ok(Self(serde_json::from_slice(&body).unwrap_or_default()))
    }
}

#[derive(Deserialize, Default)]
struct RevealBody {
    lookup: String,
    claim_token: Option<String>,
}

// Single-view: claim (or re-download with the claim token). TTL: plain read. Anything else: the uniform negative.
async fn reveal(
    State(state): State<ApiState>,
    Lenient(body): Lenient<RevealBody>,
) -> Result<Response, ApiError> {
    let lookup_key = credential_hash(&decode32_or_random(&body.lookup)?);
    let now = now();

    if let Some(token) = &body.claim_token {
        let claim_key = credential_hash(&decode32_or_random(token)?);
        return match state.store.redownload(&lookup_key, &claim_key, now).await {
            Ok(Some(served)) => {
                let body = open_blob(&state, &served).await?;
                Ok(blob_response(served.bucket, body, HeaderMap::new()))
            }
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
        .begin_claim(&lookup_key, &claim_key, now, window)
        .await
    {
        Ok(Some((pending, served))) => {
            // The object is opened first; if it cannot be served the claim is rolled back and
            // the row stays as it was (SPEC §5.1).
            let body = open_blob(&state, &served).await?;
            pending.commit().await.map_err(ApiError::internal)?;
            let mut headers = HeaderMap::new();
            headers.insert(
                CLAIM_TOKEN_HEADER,
                header_value(&URL_SAFE_NO_PAD.encode(token)),
            );
            return Ok(blob_response(served.bucket, body, headers));
        }
        Ok(None) => {}
        Err(e) => return Err(ApiError::internal(e)),
    }

    // A TTL read says nothing about remaining lifetime (SPEC §5.2): the recipient is told
    // only what they need, which is to keep what they were sent.
    match state.store.read_ttl(&lookup_key, now).await {
        Ok(Some(ttl)) => {
            let body = open_blob(&state, &ttl.served).await?;
            Ok(blob_response(ttl.served.bucket, body, HeaderMap::new()))
        }
        Ok(None) => Err(ApiError::NotFound),
        Err(e) => Err(ApiError::internal(e)),
    }
}

// Inline blobs come from the row; external ones are streamed through the server, never
// linked to directly (SPEC §6).
// The bytes to serve. A row whose object cannot be opened (gone, or the store is unreachable)
// is answered like a secret that does not exist (SPEC §4); the fault is logged without the key.
async fn open_blob(state: &ApiState, served: &Served) -> Result<Body, ApiError> {
    match (&served.blob, &served.external_ref) {
        (Some(blob), _) => Ok(Body::from(blob.clone())),
        (None, Some(key)) => {
            let Some(storage) = state.storage.as_ref() else {
                crate::log_error!("external blob requested but no external tier is configured");
                return Err(ApiError::NotFound);
            };
            storage.get(key).await.map_err(|e| {
                crate::log_error!("storage: object could not be opened: {e}");
                ApiError::NotFound
            })
        }
        (None, None) => {
            crate::log_error!("row has neither blob nor object");
            Err(ApiError::NotFound)
        }
    }
}

fn blob_response(bucket: u64, body: Body, mut headers: HeaderMap) -> Response {
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_LENGTH,
        header_value(&blob_len(bucket).to_string()),
    );
    (StatusCode::OK, headers, body).into_response()
}

#[derive(Deserialize, Default)]
struct ConfirmBody {
    lookup: String,
    claim_token: String,
}

async fn confirm(
    State(state): State<ApiState>,
    Lenient(body): Lenient<ConfirmBody>,
) -> Result<StatusCode, ApiError> {
    let lookup_key = credential_hash(&decode32_or_random(&body.lookup)?);
    let claim_key = credential_hash(&decode32_or_random(&body.claim_token)?);
    match state.store.confirm(&lookup_key, &claim_key, now()).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(ApiError::NotFound),
        Err(e) => Err(ApiError::internal(e)),
    }
}

#[derive(Deserialize, Default)]
struct BurnBody {
    burn_token: String,
}

async fn burn(
    State(state): State<ApiState>,
    Lenient(body): Lenient<BurnBody>,
) -> Result<StatusCode, ApiError> {
    let burn_key = credential_hash(&decode32_or_random(&body.burn_token)?);
    match state.store.burn(&burn_key, now()).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(ApiError::NotFound),
        Err(e) => Err(ApiError::internal(e)),
    }
}

#[derive(Deserialize, Default)]
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
    Lenient(body): Lenient<ReportBody>,
) -> Result<Json<ReportResponse>, ApiError> {
    // A malformed identifier is replaced by random bytes and run through the same statements,
    // so a reporter learns nothing from timing either (SPEC §4).
    let lookup = decode32_or_random(&body.lookup)?;
    state
        .store
        .report(&credential_hash(&lookup), now())
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(ReportResponse { status: "received" }))
}

// Reads a small part in chunks and refuses the moment the cap is passed, so an oversized
// part costs no more memory than the cap (SPEC §4). Takes the field by value: the multipart
// stream only moves on once the field is dropped.
async fn read_capped(mut field: Field<'_>, cap: usize) -> Result<Vec<u8>, ApiError> {
    let deadline = Instant::now() + BODY_IDLE_TIMEOUT;
    let mut bytes = Vec::new();
    while let Some(chunk) = next_chunk(&mut field, deadline).await? {
        if bytes.len() + chunk.len() > cap {
            return Err(ApiError::bad_request("invalid_meta"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

// Each chunk must arrive within the idle timeout, and the whole part before `deadline`.
async fn next_chunk(field: &mut Field<'_>, deadline: Instant) -> Result<Option<Bytes>, ApiError> {
    let wait = BODY_IDLE_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
    match tokio::time::timeout(wait, field.chunk()).await {
        Ok(chunk) => chunk.map_err(multipart_error),
        Err(_) => Err(ApiError::Timeout),
    }
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
    // Every upload slot is taken (`SHH_MAX_UPLOADS`).
    TooBusy,
    // The client stopped sending mid-body.
    Timeout,
    // The one response every failed secret operation gets (SPEC §4).
    NotFound,
    Internal,
}

impl ApiError {
    fn bad_request(code: &'static str) -> Self {
        Self::BadRequest(code)
    }

    fn internal(e: impl std::fmt::Display) -> Self {
        crate::log_error!("store error: {e}");
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
            Self::TooBusy => {
                let mut response = error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "too_busy",
                    "Too many uploads are in progress; try again shortly.",
                );
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
                response
            }
            Self::Timeout => error_response(
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "The request body did not arrive in time.",
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
