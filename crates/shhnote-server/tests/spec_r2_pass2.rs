// Security review round 2, pass 2 (resource exhaustion, races and lifecycle). See
// docs/security-review/round-2/pass2.md. Tests that reproduce a finding assert what the spec
// requires, so they fail while the finding stands; the others pin properties that hold.
//
// Temporary files for the local tier go under the (gitignored) `target/` directory, not
// /tmp, which is a small tmpfs on the review machine.
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::stream;
use serde_json::{Value, json};
use shhnote_core::{
    config::{AppEnv, Config},
    expiry,
    padding::blob_len,
    secret::credential_hash,
    settings::Settings,
};
use shhnote_server::{api::ApiState, app, scheduler, storage::Blobs};
use shhnote_store::{Lifetime, NewSecret, Scope, Store, sqlite_path_for_tests};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};
use tower::ServiceExt;

const ADMIN_KEY: &str = "review-admin-key-of-at-least-32-characters";
const BOUNDARY: &str = "----review-r2-pass2";
// The smallest padded size above the 64 KiB inline ceiling used below (Padmé step is 2 KiB there).
const SMALL_EXTERNAL: u64 = 65_536 + 2048;
const LARGE: u64 = 131_072;

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/review-r2-pass2")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn base_vars() -> HashMap<String, String> {
    [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
        ("SHH_INLINE_MAX", "65536B"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

const LOOSE: &[(&str, &str)] = &[
    ("rate_create_per_hour", "100000"),
    ("rate_reveal_per_hour", "100000"),
    ("rate_confirm_per_hour", "100000"),
    ("rate_burn_per_hour", "100000"),
    ("rate_report_per_hour", "100000"),
];

struct Built {
    app: Router,
    store: Store,
    blobs: Option<Arc<Blobs>>,
    config: Config,
}

async fn build_with(
    name: &str,
    tier: &[(&str, &str)],
    overrides: &[(&str, &str)],
    admin_key: bool,
) -> Built {
    let mut vars = base_vars();
    vars.extend(tier.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let config = Config::from_vars(&vars).unwrap();
    let blobs = match &config.storage.external {
        Some(external) => Some(Arc::new(Blobs::open(external).await.unwrap())),
        None => None,
    };
    let path = sqlite_path_for_tests(&format!("review-r2-pass2-{name}"));
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let mut all: HashMap<String, String> = LOOSE
        .iter()
        .chain(overrides.iter())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    all.entry("site_name".to_string())
        .or_insert_with(|| "Test".to_string());
    all.entry("contact_email".to_string())
        .or_insert_with(|| "ops@example.test".to_string());
    let (settings, warnings) = Settings::with_overrides(&all, AppEnv::Local);
    assert!(warnings.is_empty(), "{warnings:?}");
    if admin_key {
        store
            .create_api_key(
                &credential_hash(ADMIN_KEY.as_bytes()),
                "test",
                Scope::Admin,
                0,
            )
            .await
            .unwrap();
    }
    let app = app::router(
        &config,
        ApiState::new(store.clone(), settings, &config, blobs.clone()),
    );
    Built {
        app,
        store,
        blobs,
        config,
    }
}

async fn local(name: &str, ceiling: u64, extra: &[(&str, &str)]) -> (Built, PathBuf) {
    let root = scratch(name);
    let mut tier = vec![
        ("SHH_STORAGE", "local"),
        ("SHH_LOCAL_PATH", root.to_str().unwrap()),
    ];
    let ceiling = format!("{ceiling}B");
    tier.push(("SHH_LOCAL_MAX_TOTAL_BYTES", &ceiling));
    tier.extend_from_slice(extra);
    let built = build_with(name, &tier, &[], true).await;
    (built, root)
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

struct Keys {
    lookup: [u8; 32],
    burn_token: [u8; 32],
}

fn keys() -> Keys {
    Keys {
        lookup: random32(),
        burn_token: random32(),
    }
}

fn meta(keys: &Keys, lifetime: &str) -> Value {
    json!({
        "lookup_key": b64(&credential_hash(&keys.lookup)),
        "burn_key": b64(&credential_hash(&keys.burn_token)),
        "lifetime": lifetime,
        "ttl_seconds": 86400,
    })
}

fn raw_blob(bucket: u64) -> Vec<u8> {
    let mut blob = vec![0u8; blob_len(bucket) as usize];
    getrandom::fill(&mut blob).unwrap();
    blob
}

fn meta_part(meta: &str) -> String {
    format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{meta}\r\n"
    )
}

fn blob_head() -> String {
    format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
}

fn closing() -> String {
    format!("\r\n--{BOUNDARY}--\r\n")
}

fn multipart(body: Body) -> Request<Body> {
    Request::post("/api/v1/secrets")
        .header(header::HOST, "localhost")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(body)
        .unwrap()
}

fn create_body(meta: &Value, blob: &[u8]) -> Vec<u8> {
    let mut body = meta_part(&meta.to_string()).into_bytes();
    body.extend_from_slice(blob_head().as_bytes());
    body.extend_from_slice(blob);
    body.extend_from_slice(closing().as_bytes());
    body
}

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

impl Reply {
    fn code(&self) -> String {
        serde_json::from_slice::<Value>(&self.body)
            .ok()
            .and_then(|v| v["error"]["code"].as_str().map(str::to_string))
            .unwrap_or_default()
    }
}

async fn send(app: &Router, req: Request<Body>) -> Reply {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_else(|e| format!("<body error: {e}>").into_bytes());
    Reply { status, body }
}

async fn create(app: &Router, keys: &Keys, lifetime: &str, blob: &[u8]) -> Reply {
    let body = create_body(&meta(keys, lifetime), blob);
    let mut req = multipart(Body::from(body.clone()));
    req.headers_mut()
        .insert(header::CONTENT_LENGTH, body.len().into());
    send(app, req).await
}

async fn post_json(app: &Router, path: &str, body: Value) -> Reply {
    let req = Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    send(app, req).await
}

async fn burn(app: &Router, keys: &Keys) -> Reply {
    post_json(
        app,
        "/api/v1/secrets/burn",
        json!({"burn_token": b64(&keys.burn_token)}),
    )
    .await
}

fn channel_body() -> (mpsc::Sender<Bytes>, Body) {
    let (tx, rx) = mpsc::channel::<Bytes>(4);
    let stream = stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|c| (Ok::<Bytes, io::Error>(c), rx))
    });
    (tx, Body::from_stream(stream))
}

fn dir_stats(dir: &Path) -> (usize, u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut count = 0;
    let mut bytes = 0;
    for entry in entries.flatten() {
        count += 1;
        bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
    }
    (count, bytes)
}

async fn wait_until(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

// ---------------------------------------------------------------------------------------
// F-2-1: S3 bodies are read without a timeout (versioning check, listing pages, error bodies)

const MODE_OK: u8 = 0;
// Status line and headers announcing a 100-byte body, then silence.
const MODE_HEADERS_ONLY: u8 = 1;

// An S3 stand-in. In `MODE_OK` every request gets `200` with an empty body; in
// `MODE_HEADERS_ONLY` it answers a `500` whose body never arrives.
async fn fake_s3(mode: Arc<AtomicU8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mode = mode.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if socket.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                let _ = socket.read_exact(&mut body).await;
                if mode.load(Ordering::SeqCst) == MODE_HEADERS_ONLY {
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 100\r\n\r\n",
                        )
                        .await;
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    return;
                }
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    addr
}

// SPEC §6.1: "The S3 client applies connect, request and body timeouts" (S-12). A response
// whose headers arrive but whose body does not must not hang startup, the scrubber or an
// upload slot. `RESPONSE_TIMEOUT` is 10 s, so a bounded client returns well within 20 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spec_r2_pass2_s3_headers_only_body_hangs_open_scrub_and_create() {
    let mode = Arc::new(AtomicU8::new(MODE_OK));
    let addr = fake_s3(mode.clone()).await;
    let spool = scratch("s3-headers-only-spool");
    let endpoint = format!("http://{addr}");
    let built = build_with(
        "s3-headers-only",
        &[
            ("SHH_STORAGE", "s3"),
            ("SHH_S3_BUCKET", "review"),
            ("SHH_S3_REGION", "us-east-1"),
            ("SHH_S3_ENDPOINT", &endpoint),
            ("SHH_S3_ACCESS_KEY_ID", "AKIDREVIEW"),
            ("SHH_S3_SECRET_ACCESS_KEY", "review-secret"),
            ("SHH_S3_MAX_TOTAL_BYTES", "1000000000B"),
            ("SHH_SPOOL_PATH", spool.to_str().unwrap()),
        ],
        &[],
        true,
    )
    .await;
    let app = built.app.clone();
    let parked = keys();
    assert_eq!(
        create(&app, &parked, "ttl", &raw_blob(LARGE)).await.status,
        StatusCode::CREATED
    );
    assert_eq!(burn(&app, &parked).await.status, StatusCode::NO_CONTENT);

    mode.store(MODE_HEADERS_ONLY, Ordering::SeqCst);
    let limit = Duration::from_secs(20);
    let (k, blob) = (keys(), raw_blob(LARGE));
    let (scrub, create_done) = tokio::join!(
        tokio::time::timeout(
            limit,
            scheduler::scrub(&built.store, built.blobs.as_deref())
        ),
        tokio::time::timeout(limit, create(&app, &k, "ttl", &blob)),
    );
    // A second `open` (the startup versioning check) on its own: run together with the
    // create above, its `clear_parts` would remove the create's spool file first (F-2-2).
    let external = &built.config.storage.external;
    let open = tokio::time::timeout(limit, Blobs::open(external.as_ref().unwrap())).await;
    let spool_left = dir_stats(&spool);
    let _ = tokio::fs::remove_dir_all(&spool).await;
    assert!(
        open.is_ok() && scrub.is_ok() && create_done.is_ok(),
        "after {limit:?}: startup versioning check finished={}, scrub finished={}, create finished={} (spool dir holds {spool_left:?})",
        open.is_ok(),
        scrub.is_ok(),
        create_done.is_ok()
    );
}

// ---------------------------------------------------------------------------------------
// F-2-2: a second process's startup (rolling deploy) destroys the first process's work

// SPEC §6.1: "The row is written last, so an object without a row is garbage" and "At
// startup the server lists the tier, deletes unreferenced objects". Together, with two
// processes on one tier, the new one's sweep deletes an object the old one has stored but
// not yet referenced, and its `clear_parts` removes the old one's in-flight spool files.
#[tokio::test]
async fn spec_r2_pass2_second_process_startup_destroys_in_flight_objects_and_spools() {
    let root = scratch("rolling-deploy");
    let external = shhnote_core::config::ExternalStorage::Local {
        path: root.clone(),
        max_total_bytes: 1_000_000_000,
    };
    let path = sqlite_path_for_tests("review-r2-pass2-rolling");
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let old = Blobs::open(&external).await.unwrap();

    // Old process: object stored, row not yet written (the moment between `put` and `create`).
    let mut spool = old.spool().await.unwrap();
    spool.write(&raw_blob(LARGE)).await.unwrap();
    let key = Blobs::new_key().unwrap();
    old.put(&key, spool.finish().await.unwrap()).await.unwrap();
    // Old process: another upload still spooling.
    let mut in_flight = old.spool().await.unwrap();
    in_flight.write(&[7u8; 70_000]).await.unwrap();

    // New process starts on the same tier.
    let new = Blobs::open(&external).await.unwrap();
    let sweep = new.collect_orphans(&store).await.unwrap();

    // Old process goes on: writes the row, then finishes the other upload.
    let now = 1_800_000_000;
    let inserted = store
        .create(
            &NewSecret {
                lookup_key: random32(),
                burn_key: random32(),
                lifetime: Lifetime::Ttl,
                bucket: LARGE,
                blob: None,
                external_ref: Some(key.clone()),
                expires_at: now + 86_400,
            },
            now,
        )
        .await
        .unwrap();
    assert!(inserted);
    let object_still_there = old.get(&key).await.is_ok();
    in_flight.write(&[7u8; 1000]).await.unwrap();
    let key2 = Blobs::new_key().unwrap();
    let second_upload = old.put(&key2, in_flight.finish().await.unwrap()).await;
    let _ = tokio::fs::remove_dir_all(&root).await;

    assert_eq!(
        sweep.removed, 0,
        "the new process deleted an object a row was about to reference"
    );
    assert!(
        object_still_there,
        "the committed row points at a deleted object"
    );
    assert!(
        second_upload.is_ok(),
        "the in-flight upload failed because its spool was cleared: {second_upload:?}"
    );
}

// ---------------------------------------------------------------------------------------
// F-2-3: the scrubber starves behind SCRUB_BATCH persistently failing deletes

// SPEC §5 / file-uploads skill: parked objects are retried on every pass "until each is
// confirmed gone". `pending_deletes_after` walks the set in key order with a cursor, so 200 rows that
// fail every tick (an object that cannot be removed), every row behind them is never visited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spec_r2_pass2_scrubber_starves_behind_200_failing_deletes() {
    let (built, root) = local("scrub-starve", 1_000_000_000, &[]).await;
    let app = built.app.clone();
    let blob = raw_blob(SMALL_EXTERNAL);
    // The "good" row sorts last on the primary key (hash starting 0xff); the poison rows sort
    // before it (hash not starting 0xff).
    let good = loop {
        let k = keys();
        if credential_hash(&k.lookup)[0] == 0xff {
            break k;
        }
    };
    let poison: Vec<Keys> = std::iter::repeat_with(keys)
        .filter(|k| credential_hash(&k.lookup)[0] != 0xff)
        .take(scheduler::SCRUB_BATCH as usize + 10)
        .collect();
    for k in poison.iter().chain(std::iter::once(&good)) {
        assert_eq!(
            create(&app, k, "ttl", &blob).await.status,
            StatusCode::CREATED
        );
    }
    // Which object is the good one: the only row whose key sorts last.
    let mut refs: Vec<(Vec<u8>, String)> = built.store.pending_deletes().await.unwrap();
    assert!(refs.is_empty());
    for k in poison.iter().chain(std::iter::once(&good)) {
        assert_eq!(burn(&app, k).await.status, StatusCode::NO_CONTENT);
    }
    refs = built.store.pending_deletes().await.unwrap();
    assert_eq!(refs.len(), poison.len() + 1);
    let good_key_hash = credential_hash(&good.lookup).to_vec();
    let good_ref = refs
        .iter()
        .find(|(k, _)| *k == good_key_hash)
        .map(|(_, r)| r.clone())
        .unwrap();
    // Make every poison object undeletable: a directory where the file was.
    for (lookup_key, external_ref) in &refs {
        if *lookup_key == good_key_hash {
            continue;
        }
        let file = root
            .join("blobs")
            .join(external_ref.strip_prefix("blobs/").unwrap());
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
    }
    let good_file = root
        .join("blobs")
        .join(good_ref.strip_prefix("blobs/").unwrap());
    assert!(good_file.is_file());

    for _ in 0..5 {
        scheduler::scrub(&built.store, built.blobs.as_deref()).await;
    }
    let still_pending = built
        .store
        .pending_deletes()
        .await
        .unwrap()
        .iter()
        .any(|(k, _)| *k == good_key_hash);
    let good_object_left = good_file.is_file();
    let _ = tokio::fs::remove_dir_all(&root).await;
    assert!(
        !still_pending && !good_object_left,
        "after 5 scrub passes the deletable object is still parked (row pending: {still_pending}, object on disk: {good_object_left}) behind {} undeletable ones",
        poison.len()
    );
}

// ---------------------------------------------------------------------------------------
// F-2-4: the setup gate runs a database query per unauthenticated request once the two
// settings are set but no admin key exists, and waits on the pool without a bound

async fn page_within(app: &Router, path: &str, limit: Duration) -> Option<StatusCode> {
    let req = Request::get(path)
        .header(header::HOST, "localhost")
        .body(Body::empty())
        .unwrap();
    tokio::time::timeout(limit, app.clone().oneshot(req))
        .await
        .ok()
        .map(|r| r.unwrap().status())
}

// D-29 says the state is "derived while unmet", which the code does per request. While only
// the admin key is missing, every public request (no rate limit, no authentication) runs
// `SELECT COUNT(*) FROM api_keys WHERE scopes = 'admin'`, a full scan of a table without an
// index on `scopes`, on a pool connection acquired with sqlx's 30 s default and outside the
// 30 s request timeout. Observable here as the cost of the 503 growing with the table.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spec_r2_pass2_half_configured_gate_queries_per_request() {
    const KEYS: usize = 30_000;
    const REQUESTS: usize = 100;
    // Site name and contact set (the defaults of `build_with`), no admin key.
    let half = build_with("gate-half", &[], &[], false).await;
    // Nothing set at all.
    let none = build_with(
        "gate-none",
        &[],
        &[("site_name", ""), ("contact_email", "")],
        false,
    )
    .await;
    for built in [&half, &none] {
        for _ in 0..KEYS {
            built
                .store
                .create_api_key(&random32(), "user", Scope::User, 0)
                .await
                .unwrap();
        }
    }
    // Per-request medians, not totals: one scan or a slow disk's hiccup must not decide this.
    let time = |app: Router| async move {
        // One request first: the pool's first connection and the gate's first derivation are
        // start-up costs, not the per-request cost under test.
        page_within(&app, "/en", Duration::from_secs(30)).await;
        let mut samples = Vec::with_capacity(REQUESTS);
        for _ in 0..REQUESTS {
            let started = std::time::Instant::now();
            assert_eq!(
                page_within(&app, "/en", Duration::from_secs(30)).await,
                Some(StatusCode::SERVICE_UNAVAILABLE)
            );
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        samples[REQUESTS / 2]
    };
    let none_time = time(none.app.clone()).await;
    let half_time = time(half.app.clone()).await;
    // A preflight (no body, no route) pays the same.
    let started = std::time::Instant::now();
    for _ in 0..REQUESTS {
        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/secrets")
            .header(header::HOST, "localhost")
            .header(header::ORIGIN, "http://localhost:3000")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            half.app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let preflight_time = started.elapsed();
    // R-15: the count runs once per admin write or per second, not per request, so the
    // half-configured run may cost a few scans on top of the unconfigured one, never a
    // hundred.
    let started = std::time::Instant::now();
    half.store.admin_key_count().await.unwrap();
    let one_scan = started.elapsed();
    assert!(
        half_time < none_time * 3 + Duration::from_millis(1)
            && half_time < one_scan.max(Duration::from_millis(1)),
        "{REQUESTS} gated page requests: median unconfigured {none_time:?}, half-configured {half_time:?} (preflights {preflight_time:?}, one scan {one_scan:?}) with {KEYS} user keys: the gate scans api_keys per request"
    );
}

// ---------------------------------------------------------------------------------------
// F-2-5: the largest advertised bucket does not fit the body limit

// SPEC §4 / §6.1: `/config` advertises `max_blob_bytes` (a bucket), and the server accepts a
// blob whose bucket is at most that. The route's body limit is `max_blob_bytes + 16 KiB`, but
// a 64 MiB bucket needs 16 KiB of tags plus the header and the multipart framing.
#[tokio::test]
async fn spec_r2_pass2_largest_advertised_bucket_is_accepted() {
    const MAX: u64 = 64 * 1024 * 1024;
    let (built, root) = local(
        "max-bucket",
        400 * 1024 * 1024,
        &[("SHH_EXTERNAL_MAX_OBJECT", "67108864B")],
    )
    .await;
    let config = send(
        &built.app,
        Request::get("/api/v1/config")
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let advertised = serde_json::from_slice::<Value>(&config.body).unwrap()["max_blob_bytes"]
        .as_u64()
        .unwrap();
    assert_eq!(advertised, MAX);
    let reply = create(&built.app, &keys(), "ttl", &raw_blob(MAX)).await;
    let (status, code) = (reply.status, reply.code());
    let _ = tokio::fs::remove_dir_all(&root).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a blob of the advertised maximum bucket ({MAX}) was refused: {status} {code}"
    );
}

// ---------------------------------------------------------------------------------------
// F-2-6 (Low): a stalled upload holds its declared size against the ceiling

// D-20 holds the declared size from the moment the upload spills. The hold lasts as long as
// the upload: up to `max_blob_bytes / 32 KiB` seconds (34 min at the 64 MiB default) for a
// client that trickles one byte every 29 s. Two such uploads here hold 88 % of the ceiling
// after sending 128 KiB each, and a complete small create is refused meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spec_r2_pass2_stalled_declared_uploads_hold_the_ceiling() {
    const CEILING: u64 = 1_000_000;
    const DECLARED: u64 = 450_000;
    let (built, root) = local("declared-hold", CEILING, &[]).await;
    let app = built.app.clone();
    let mut senders = Vec::new();
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let (tx, body) = channel_body();
        let mut req = multipart(body);
        req.headers_mut()
            .insert(header::CONTENT_LENGTH, DECLARED.into());
        let app2 = app.clone();
        tasks.push(tokio::spawn(async move { send(&app2, req).await }));
        tx.send(Bytes::from(meta_part(&meta(&keys(), "ttl").to_string())))
            .await
            .unwrap();
        tx.send(Bytes::from(blob_head())).await.unwrap();
        for _ in 0..2 {
            tx.send(Bytes::from(vec![0u8; 65536])).await.unwrap();
        }
        senders.push(tx);
    }
    let tmp = root.join("tmp");
    assert!(wait_until(|| dir_stats(&tmp).0 == 2).await);
    let (_, spooled) = dir_stats(&tmp);
    let refused = create(&app, &keys(), "ttl", &raw_blob(LARGE)).await;
    drop(senders);
    for t in tasks {
        let _ = t.await;
    }
    assert!(wait_until(|| dir_stats(&tmp).0 == 0).await);
    let accepted = create(&app, &keys(), "ttl", &raw_blob(LARGE)).await;
    let _ = tokio::fs::remove_dir_all(&root).await;
    // Documented behaviour (D-20), recorded so the numbers are on file.
    assert_eq!(
        (refused.status, accepted.status),
        (StatusCode::INSUFFICIENT_STORAGE, StatusCode::CREATED),
        "{spooled} bytes spooled; refused={} {}, accepted={}",
        refused.status,
        refused.code(),
        accepted.status
    );
}

// ---------------------------------------------------------------------------------------
// Checked and clean

// S-4/S-5: a reservation is given back on the duplicate path (D-21) and on a disconnect, so
// neither leaks room from the ceiling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spec_r2_pass2_reservation_is_released_on_duplicate_and_disconnect() {
    // Room for exactly two objects.
    let ceiling = 2 * blob_len(LARGE) + 100;
    let (built, root) = local("reservation-release", ceiling, &[]).await;
    let app = built.app.clone();
    let a = keys();
    let blob = raw_blob(LARGE);
    assert_eq!(
        create(&app, &a, "ttl", &blob).await.status,
        StatusCode::CREATED
    );
    // Duplicate: answered like a success, writes nothing, must give its reservation back.
    assert_eq!(
        create(&app, &a, "ttl", &blob).await.status,
        StatusCode::CREATED
    );
    assert!(wait_until(|| dir_stats(&root.join("blobs")).0 == 1).await);

    // Disconnect after spilling.
    let (tx, body) = channel_body();
    let app2 = app.clone();
    // Declared as one LARGE blob (without a Content-Length the reservation would be the
    // largest object the tier accepts, which this ceiling cannot hold).
    let mut req = multipart(body);
    req.headers_mut().insert(
        header::CONTENT_LENGTH,
        create_body(&meta(&keys(), "ttl"), &blob).len().into(),
    );
    let task = tokio::spawn(async move { send(&app2, req).await });
    tx.send(Bytes::from(meta_part(&meta(&keys(), "ttl").to_string())))
        .await
        .unwrap();
    tx.send(Bytes::from(blob_head())).await.unwrap();
    tx.send(Bytes::from(vec![0u8; 65536])).await.unwrap();
    tx.send(Bytes::from(vec![0u8; 65536])).await.unwrap();
    assert!(wait_until(|| dir_stats(&root.join("tmp")).0 == 1).await);
    task.abort();
    let _ = task.await;
    drop(tx);
    assert!(wait_until(|| dir_stats(&root.join("tmp")).0 == 0).await);

    // The second slot is still free; a third object is refused.
    let second = create(&app, &keys(), "ttl", &blob).await.status;
    let third = create(&app, &keys(), "ttl", &blob).await.status;
    let used = built.store.external_bytes().await.unwrap();
    let _ = tokio::fs::remove_dir_all(&root).await;
    assert_eq!(
        (second, third),
        (StatusCode::CREATED, StatusCode::INSUFFICIENT_STORAGE)
    );
    assert!(used <= ceiling);
}

// S-16 / D-19: concurrent reports all succeed and the daily counter is exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn spec_r2_pass2_fifty_concurrent_reports_count_fifty() {
    let built = build_with("reports-race", &[], &[], true).await;
    let app = built.app.clone();
    let existing = keys();
    assert_eq!(
        create(&app, &existing, "ttl", &raw_blob(65_536))
            .await
            .status,
        StatusCode::CREATED
    );
    let mut tasks = Vec::new();
    for i in 0..50 {
        let app = app.clone();
        let lookup = if i == 0 {
            b64(&existing.lookup)
        } else {
            b64(&random32())
        };
        tasks.push(tokio::spawn(async move {
            post_json(&app, "/api/v1/reports", json!({"lookup": lookup})).await
        }));
    }
    for t in tasks {
        let r = t.await.unwrap();
        assert_eq!(
            r.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&r.body)
        );
    }
    let stats = built.store.stats().await.unwrap();
    assert_eq!((stats.reports, stats.removed, stats.active), (50, 1, 0));
}

// D-18: the grid never puts an expiry before `now + ttl`, never a full grid step past it, and
// a claim window is never empty.
#[test]
fn spec_r2_pass2_expiry_grid_bounds() {
    let nows = [
        0i64,
        1,
        59,
        299,
        3599,
        86_399,
        1_800_012_345,
        1_800_012_345 + 86_399,
    ];
    for ttl in (60..=1_209_600).step_by(7) {
        let g = expiry::grid(ttl);
        for now in nows {
            let e = expiry::expires_at(now, ttl);
            assert!(e >= now + ttl, "ttl {ttl} now {now}");
            assert!(e < now + ttl + g, "ttl {ttl} now {now}");
            assert_eq!(e % g, 0);
        }
    }
    // The 14-day cap plus the daily grid: at most 15 days minus one second from `now`.
    for now in nows {
        assert!(expiry::expires_at(now, 1_209_600) <= now + 1_209_600 + 86_399);
    }
    for window in [60, 61, 900, 86_400] {
        for now in nows {
            let c = expiry::claim_expires_at(now, window);
            assert!(c > now && c >= now + window && c < now + window + 60);
        }
    }
}

// D-23: two keyed requests on the same day write the day once; the second is a no-op.
#[tokio::test]
async fn spec_r2_pass2_last_used_on_is_the_day_and_idempotent() {
    let built = build_with("last-used", &[], &[], true).await;
    let key = random32();
    let hash = credential_hash(&key);
    built
        .store
        .create_api_key(&hash, "k", Scope::User, 0)
        .await
        .unwrap();
    let day = 1_800_000_000 - 1_800_000_000 % 86_400;
    built.store.touch_api_key(&hash, day + 100).await.unwrap();
    built
        .store
        .touch_api_key(&hash, day + 86_399)
        .await
        .unwrap();
    let k = built.store.find_api_key(&hash).await.unwrap().unwrap();
    assert_eq!(k.last_used_on, Some(day));
}

// D-26 / Principle 7: a CORS preflight is answered before any body is read, so a preflight
// that announces a huge body costs nothing; the unread body is not drained and the
// connection is closed after the answer.
#[tokio::test]
async fn spec_r2_pass2_preflight_with_a_huge_body_is_answered_at_once() {
    use shhnote_server::drain::{Drain, track};
    let built = build_with("preflight-body", &[], &[], true).await;
    let drain = Arc::new(Drain::default());
    let app = built
        .app
        .layer(axum::middleware::from_fn_with_state(drain.clone(), track));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(shhnote_server::serve::serve(
        listener,
        app,
        drain,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_secs(1),
    ));
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(
            b"OPTIONS /api/v1/secrets HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost:3000\r\nContent-Length: 50000000\r\n\r\nx",
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let closed = loop {
        match tokio::time::timeout(Duration::from_secs(3), socket.read(&mut buf)).await {
            Ok(Ok(0)) => break true,
            Ok(Ok(n)) => raw.extend_from_slice(&buf[..n]),
            // Headers arrived and the connection is still open after 3 s of silence.
            Ok(Err(_)) | Err(_) => break false,
        }
    };
    let head = String::from_utf8_lossy(&raw).to_string();
    stop_tx.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
    assert!(
        head.starts_with("HTTP/1.1 204"),
        "preflight not answered before the body: {head:?}"
    );
    // Recorded, not required: whether hyper closes the connection it cannot reuse.
    eprintln!("preflight answered; connection closed by the server: {closed}; head: {head:?}");
}
