// Regression tests from the adversarial pass of the security review
// (docs/security-review/findings/SUMMARY.md): each test attacks one property of SPEC.md end
// to end and must fail to break it. Ignored tests are waiting for the step that fixes their
// finding; un-ignore them with the fix.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use shhnote_core::{
    config::AppEnv,
    config::Config,
    container::{File, Payload},
    kdf::Argon2Params,
    padding::{PaddingPolicy, blob_len},
    secret::{self, Randomness, credential_hash},
    settings::Settings,
};
use shhnote_server::{
    api::{ApiState, CLAIM_TOKEN_HEADER, now},
    app, scheduler,
    storage::{Blobs, object_bytes},
};
use shhnote_store::{Scope, Store, sqlite_path_for_tests};
use tower::ServiceExt;

const ADMIN_KEY: &str = "spec-admin-key-of-at-least-32-characters-ok";

// --- harness

const BOUNDARY: &str = "----spec-adversarial";
const BOOTSTRAP: &str = "spec-adversarial-bootstrap-token-0123456789";
// Every rate limit off, so the attacks below measure the server and not the limiter.
const NO_LIMITS: &[(&str, &str)] = &[
    ("rate_create_per_hour", "0"),
    ("rate_reveal_per_hour", "0"),
    ("rate_confirm_per_hour", "0"),
    ("rate_burn_per_hour", "0"),
    ("rate_report_per_hour", "0"),
];

struct Srv {
    app: Router,
    store: Store,
    db: PathBuf,
    blobs: Option<Arc<Blobs>>,
}

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

async fn srv(name: &str, env: &[(&str, &str)], overrides: &[(&str, &str)]) -> Srv {
    srv_with(name, env, overrides, true).await
}

// Before setup (D-29): no admin key, so the bootstrap token still works.
async fn srv_unconfigured(name: &str, env: &[(&str, &str)], overrides: &[(&str, &str)]) -> Srv {
    srv_with(name, env, overrides, false).await
}

async fn srv_with(
    name: &str,
    env: &[(&str, &str)],
    overrides: &[(&str, &str)],
    configured: bool,
) -> Srv {
    let mut vars = map(&[
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
        ("SHH_ADMIN_TOKEN", BOOTSTRAP),
    ]);
    vars.extend(map(env));
    let config = Config::from_vars(&vars).unwrap();
    let blobs = match &config.storage.external {
        Some(external) => Some(Arc::new(Blobs::open(external).await.unwrap())),
        None => None,
    };
    let db = sqlite_path_for_tests(&format!("spec-adv-{name}"));
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", db.display()))
        .await
        .unwrap();
    let mut overrides = map(overrides);
    if configured {
        overrides
            .entry("site_name".to_string())
            .or_insert_with(|| "Test".to_string());
        overrides
            .entry("contact_email".to_string())
            .or_insert_with(|| "ops@example.test".to_string());
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
    let (settings, warnings) = Settings::with_overrides(&overrides, AppEnv::Local);
    assert!(warnings.is_empty(), "{warnings:?}");
    let app = app::router(
        &config,
        ApiState::new(store.clone(), settings, &config, blobs.clone()),
    );
    Srv {
        app,
        store,
        db,
        blobs,
    }
}

#[derive(Debug)]
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn send(app: &Router, req: Request<Body>) -> Reply {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

fn with_peer(mut req: Request<Body>, ip: &str) -> Request<Body> {
    let addr: SocketAddr = match ip.parse::<std::net::IpAddr>().unwrap() {
        std::net::IpAddr::V4(v4) => SocketAddr::from((v4, 40000)),
        std::net::IpAddr::V6(v6) => SocketAddr::from((v6, 40000)),
    };
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

fn json_req(path: &str, body: &Value) -> Request<Body> {
    Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn post(app: &Router, path: &str, body: Value) -> Reply {
    send(app, json_req(path, &body)).await
}

fn multipart(meta: &Value, blob: &[u8]) -> Vec<u8> {
    let mut body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"meta\"\r\n\r\n{meta}\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(blob);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn create_req(body: Body) -> Request<Body> {
    Request::post("/api/v1/secrets")
        .header(header::HOST, "localhost")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(body)
        .unwrap()
}

// A sized body, with the Content-Length a real client sends.
fn create_req_sized(body: Vec<u8>) -> Request<Body> {
    let mut req = create_req(Body::from(body.clone()));
    req.headers_mut()
        .insert(header::CONTENT_LENGTH, body.len().into());
    req
}

async fn create(app: &Router, meta: &Value, blob: &[u8]) -> Reply {
    send(app, create_req_sized(multipart(meta, blob))).await
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn raw_blob(bucket: u64) -> Vec<u8> {
    let mut blob = vec![0u8; blob_len(bucket) as usize];
    for chunk in blob.chunks_mut(32) {
        let r = random32();
        chunk.copy_from_slice(&r[..chunk.len()]);
    }
    blob
}

#[derive(Clone, Copy)]
struct Keys {
    lookup: [u8; 32],
    burn: [u8; 32],
}

fn keys() -> Keys {
    Keys {
        lookup: random32(),
        burn: random32(),
    }
}

fn meta(k: &Keys, lifetime: &str, ttl: i64) -> Value {
    json!({
        "lookup_key": b64(&credential_hash(&k.lookup)),
        "burn_key": b64(&credential_hash(&k.burn)),
        "lifetime": lifetime,
        "ttl_seconds": ttl,
    })
}

async fn make(app: &Router, k: &Keys, lifetime: &str, bucket: u64) {
    let r = create(app, &meta(k, lifetime, 3600), &raw_blob(bucket)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
}

async fn reveal(app: &Router, lookup: &str, claim: Option<&str>) -> Reply {
    let mut body = json!({ "lookup": lookup });
    if let Some(c) = claim {
        body["claim_token"] = json!(c);
    }
    post(app, "/api/v1/secrets/reveal", body).await
}

fn claim_token(r: &Reply) -> String {
    r.headers[CLAIM_TOKEN_HEADER].to_str().unwrap().to_string()
}

fn uniform(r: &Reply) -> bool {
    r.status == StatusCode::NOT_FOUND
        && r.body == br#"{"error":{"code":"not_found","message":"No secret matches."}}"#
}

// Headers minus the ones that legitimately differ per response.
fn header_shape(h: &HeaderMap) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = h
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("?").to_string()))
        .collect();
    v.sort();
    v
}

async fn stats(store: &Store) -> shhnote_store::Stats {
    store.stats().await.unwrap()
}

// ============================================================================================
// A. SPEC §5.1 / §5.3: the race between a reveal and the creator's burn: never both. (The
// reveal-vs-reveal race is in spec_resources.)

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn spec_reveal_and_burn_race_never_both_succeed() {
    let s = srv("a-burn-race", &[], NO_LIMITS).await;
    for _ in 0..20 {
        let k = keys();
        make(&s.app, &k, "single_view", 65536).await;
        let (app1, app2) = (s.app.clone(), s.app.clone());
        let lookup = b64(&k.lookup);
        let burn = b64(&k.burn);
        let r = tokio::spawn(async move { reveal(&app1, &lookup, None).await });
        let b = tokio::spawn(async move {
            post(&app2, "/api/v1/secrets/burn", json!({ "burn_token": burn })).await
        });
        let (r, b) = (r.await.unwrap(), b.await.unwrap());
        let revealed = r.status == StatusCode::OK;
        let burned = b.status == StatusCode::NO_CONTENT;
        assert!(revealed ^ burned, "reveal {} burn {}", r.status, b.status);
    }
}

// ============================================================================================
// B. SPEC §5.1: only the claim token holder re-downloads a claimed secret.

#[tokio::test]
async fn spec_claimed_secret_needs_the_exact_claim_token() {
    let s = srv("b-claim", &[], NO_LIMITS).await;
    let k = keys();
    let other = keys();
    make(&s.app, &k, "single_view", 65536).await;
    make(&s.app, &other, "single_view", 65536).await;
    let lookup = b64(&k.lookup);
    let first = reveal(&s.app, &lookup, None).await;
    assert_eq!(first.status, StatusCode::OK);
    let token = claim_token(&first);
    let other_token = claim_token(&reveal(&s.app, &b64(&other.lookup), None).await);
    let token_bytes = URL_SAFE_NO_PAD.decode(&token).unwrap();

    let mut flipped = token_bytes.clone();
    flipped[0] ^= 1;
    let attempts: Vec<Option<String>> = vec![
        None,
        Some(b64(&random32())),
        Some(other_token.clone()),
        Some(b64(&credential_hash(&token_bytes))),
        Some(b64(&flipped)),
        Some(format!("{token}=")),
        Some(token.to_uppercase()),
        Some(String::new()),
    ];
    for claim in &attempts {
        let r = reveal(&s.app, &lookup, claim.as_deref()).await;
        assert!(uniform(&r), "{claim:?}: {}", r.status);
    }
    // The other claimant's token for its own secret works, not across secrets.
    assert!(uniform(&reveal(&s.app, &lookup, Some(&other_token)).await));
    // The right token works, then confirm ends it for good.
    assert_eq!(reveal(&s.app, &lookup, Some(&token)).await.body, first.body);
    let c = post(
        &s.app,
        "/api/v1/secrets/confirm",
        json!({"lookup": lookup, "claim_token": token}),
    )
    .await;
    assert_eq!(c.status, StatusCode::NO_CONTENT);
    assert!(uniform(&reveal(&s.app, &lookup, Some(&token)).await));
}

#[tokio::test]
async fn spec_claim_token_dies_with_the_window() {
    let s = srv("b-window", &[], NO_LIMITS).await;
    let k = keys();
    make(&s.app, &k, "single_view", 65536).await;
    let first = reveal(&s.app, &b64(&k.lookup), None).await;
    let token = claim_token(&first);
    let lookup_key = credential_hash(&k.lookup);
    let claim_key = credential_hash(&URL_SAFE_NO_PAD.decode(&token).unwrap());
    // Just inside the default 15-minute window, and past the minute it is rounded up to.
    let t = now();
    assert!(
        s.store
            .redownload(&lookup_key, &claim_key, t + 899)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        s.store
            .redownload(&lookup_key, &claim_key, t + 961)
            .await
            .unwrap()
            .is_none()
    );
}

// ============================================================================================
// D. SPEC §4: a burn with a wrong token learns nothing and destroys nothing.

#[tokio::test]
async fn spec_wrong_burn_token_is_indistinguishable_and_harmless() {
    let s = srv("d-burn", &[], NO_LIMITS).await;
    let k = keys();
    make(&s.app, &k, "ttl", 65536).await;
    let burn = |t: String| post(&s.app, "/api/v1/secrets/burn", json!({ "burn_token": t }));
    let mut flipped = k.burn;
    flipped[31] ^= 0x80;
    let wrong = [
        b64(&random32()),
        b64(&flipped),
        b64(&credential_hash(&k.burn)), // the stored value itself
        b64(&k.lookup),                 // the share link's lookup value
        "not base64".to_string(),
        String::new(),
    ];
    let mut shapes = Vec::new();
    for w in wrong {
        let r = burn(w.clone()).await;
        assert!(uniform(&r), "{w}");
        shapes.push(header_shape(&r.headers));
    }
    shapes.dedup();
    assert_eq!(shapes.len(), 1, "{shapes:?}");
    // Nothing was destroyed and nothing was counted.
    assert_eq!(
        reveal(&s.app, &b64(&k.lookup), None).await.status,
        StatusCode::OK
    );
    assert_eq!(stats(&s.store).await.burned, 0);
    // A claimed single-view secret can't be burned either (SPEC §5.3), and says so uniformly.
    let sv = keys();
    make(&s.app, &sv, "single_view", 65536).await;
    assert_eq!(
        reveal(&s.app, &b64(&sv.lookup), None).await.status,
        StatusCode::OK
    );
    assert!(uniform(&burn(b64(&sv.burn)).await));
}

// ============================================================================================
// E. D-3 / §2.12: a database dump holds only hashes, and hashes open nothing.

fn dump(db: &Path) -> Vec<u8> {
    let mut all = std::fs::read(db).unwrap();
    for suffix in ["-wal", "-shm", "-journal"] {
        if let Ok(more) = std::fs::read(format!("{}{suffix}", db.display())) {
            all.extend(more);
        }
    }
    all
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn spec_dump_holds_only_hashes_and_hashes_open_nothing() {
    let s = srv("e-dump", &[], NO_LIMITS).await;
    let ttl = keys();
    let sv = keys();
    make(&s.app, &ttl, "ttl", 65536).await;
    make(&s.app, &sv, "single_view", 65536).await;
    // Claim the single-view one, so a claim key is in the dump too.
    let claimed = reveal(&s.app, &b64(&sv.lookup), None).await;
    let token = URL_SAFE_NO_PAD.decode(claim_token(&claimed)).unwrap();

    let bytes = dump(&s.db);
    for raw in [&ttl.lookup[..], &ttl.burn, &sv.lookup, &sv.burn, &token] {
        assert!(!contains(&bytes, raw), "a raw credential is in the dump");
        assert!(!contains(&bytes, b64(raw).as_bytes()));
    }
    // What the dump does hold: the hashes.
    let ttl_lookup_key = credential_hash(&ttl.lookup);
    let ttl_burn_key = credential_hash(&ttl.burn);
    let claim_key = credential_hash(&token);
    assert!(contains(&bytes, &ttl_lookup_key));
    assert!(contains(&bytes, &ttl_burn_key));
    assert!(contains(&bytes, &claim_key));

    // Present the stored values as credentials everywhere.
    let lk = b64(&ttl_lookup_key);
    assert!(uniform(&reveal(&s.app, &lk, None).await));
    assert!(uniform(
        &reveal(
            &s.app,
            &b64(&credential_hash(&sv.lookup)),
            Some(&b64(&claim_key))
        )
        .await
    ));
    assert!(uniform(
        &post(
            &s.app,
            "/api/v1/secrets/burn",
            json!({"burn_token": b64(&ttl_burn_key)})
        )
        .await
    ));
    assert!(uniform(
        &post(
            &s.app,
            "/api/v1/secrets/confirm",
            json!({"lookup": b64(&credential_hash(&sv.lookup)), "claim_token": b64(&claim_key)})
        )
        .await
    ));
    post(&s.app, "/api/v1/reports", json!({"lookup": lk})).await;
    // Both secrets are untouched: the TTL one still reads, the claim still re-downloads.
    assert_eq!(
        reveal(&s.app, &b64(&ttl.lookup), None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        reveal(&s.app, &b64(&sv.lookup), Some(&b64(&token)))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(stats(&s.store).await.removed, 0);
}

// ============================================================================================
// C. SPEC §4: a reporter learns nothing from status, body or headers (timing is in
// spec_privacy).

#[tokio::test]
async fn spec_report_answer_is_identical_for_every_target() {
    let s = srv("c-report", &[], NO_LIMITS).await;
    const N: usize = 200;
    let mut existing = Vec::new();
    for _ in 0..N {
        let k = keys();
        make(&s.app, &k, "ttl", 65536).await;
        existing.push(k);
    }
    let claimed = keys();
    make(&s.app, &claimed, "single_view", 65536).await;
    reveal(&s.app, &b64(&claimed.lookup), None).await;

    let report = |lookup: String| post(&s.app, "/api/v1/reports", json!({ "lookup": lookup }));
    // Every kind of target: live, claimed, never existed, malformed, already reported.
    let first = report(b64(&existing[0].lookup)).await;
    let mut variants = vec![
        report(b64(&claimed.lookup)).await,
        report(b64(&random32())).await,
        report("garbage".into()).await,
        report(b64(&existing[0].lookup)).await,
    ];
    variants.push(first);
    for v in &variants {
        assert_eq!(v.status, StatusCode::OK);
        assert_eq!(v.body, variants[0].body);
        assert_eq!(header_shape(&v.headers), header_shape(&variants[0].headers));
    }

    // One secret was reported twice: removed once, nothing else touched. The claimed one
    // still exists (and counts) until it is confirmed or its window lapses.
    assert_eq!(stats(&s.store).await.removed, 1);
    assert_eq!(stats(&s.store).await.active as usize, N);
}

// ============================================================================================
// F / G. SPEC §2.8: same-bucket blobs are indistinguishable; the server can't tell a passphrase.

#[tokio::test]
async fn spec_direct_passphrase_text_file_blobs_look_the_same() {
    let s = srv("fg-shapes", &[], NO_LIMITS).await;
    let policy = PaddingPolicy::Padme { min: 65536 };
    let text = Payload {
        text: Some("x".repeat(100)),
        files: vec![],
    };
    let file = Payload {
        text: None,
        files: vec![File {
            name: "a.bin".into(),
            mime: "application/octet-stream".into(),
            bytes: vec![1; 100],
        }],
    };
    let mut blobs = Vec::new();
    for (payload, pass) in [
        (&text, None),
        (&file, None),
        (&text, Some("correct horse")),
        (&file, Some("correct horse")),
    ] {
        // The shipped clients use the default Argon2 parameters in both modes.
        let e = secret::encrypt(
            &Randomness::generate().unwrap(),
            payload,
            pass,
            Argon2Params::DEFAULT,
            &policy,
        )
        .unwrap();
        blobs.push(e);
    }
    let mut replies = Vec::new();
    for e in &blobs {
        let m = json!({
            "lookup_key": b64(&e.lookup_key), "burn_key": b64(&e.burn_key),
            "lifetime": "ttl", "ttl_seconds": 3600,
        });
        let r = create(&s.app, &m, &e.blob).await;
        assert_eq!(r.status, StatusCode::CREATED);
        assert!(r.body.is_empty());
        let seed = shhnote_core::fragment::Fragment::decode(&e.fragment)
            .unwrap()
            .bytes;
        replies.push(reveal(&s.app, &b64(&secret::lookup(&seed)), None).await);
    }
    for (e, r) in blobs.iter().zip(&replies) {
        assert_eq!(e.blob.len(), blobs[0].blob.len());
        // The argon fields (offset 16..28) are the defaults in every blob, so no mode marker.
        assert_eq!(e.blob[16..28], blobs[0].blob[16..28]);
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body, e.blob, "stored and served exactly as received");
        assert_eq!(header_shape(&r.headers), header_shape(&replies[0].headers));
    }
}

// ============================================================================================
// H. SPEC §6.1: an object without a row is garbage the tier collects.

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("shh-spec-adv-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    root
}

fn dir_stats(dir: &Path) -> (usize, u64) {
    match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter_map(|e| e.metadata().ok())
            .filter(|m| m.is_file())
            .fold((0, 0), |(n, b), m| (n + 1, b + m.len())),
        Err(_) => (0, 0),
    }
}

async fn local_srv(name: &str, ceiling: &str) -> (Srv, PathBuf) {
    let root = temp_root(name);
    let s = srv(
        name,
        &[
            ("SHH_STORAGE", "local"),
            ("SHH_LOCAL_PATH", root.to_str().unwrap()),
            ("SHH_LOCAL_MAX_TOTAL_BYTES", ceiling),
            ("SHH_INLINE_MAX", "65536"),
        ],
        NO_LIMITS,
    )
    .await;
    (s, root)
}

// A client that disconnects right after its upload completes cancels the handler between the
// object write and the row write. The object is removed as soon as the write has settled, so
// at every moment the tier holds only what the rows account for, and the ceiling (room for two
// objects here) still bounds what an honest create can add; no restart is needed (R-1).
#[tokio::test]
async fn spec_disconnect_after_upload_leaves_no_uncounted_object() {
    let ceiling = 300_000u64;
    let (s, root) = local_srv("h-zombie", &ceiling.to_string()).await;
    let blobs = s.blobs.clone().unwrap();
    let blobs_dir = root.join("blobs");
    let bucket = 131_072u64;
    for _ in 0..10 {
        let before = dir_stats(&blobs_dir).0;
        let body = multipart(&meta(&keys(), "ttl", 3600), &raw_blob(bucket));
        let app = s.app.clone();
        let task = tokio::spawn(async move { send(&app, create_req_sized(body)).await });
        // The moment the object lands, the client is gone (hyper drops the handler future).
        loop {
            if dir_stats(&blobs_dir).0 > before || task.is_finished() {
                task.abort();
                break;
            }
            tokio::task::yield_now().await;
        }
        let _ = task.await;
        // The cleanup runs as its own task; give it a moment, then nothing may be uncounted.
        let settled = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let on_disk = dir_stats(&blobs_dir).1;
                let counted = s.store.external_bytes().await.unwrap();
                if on_disk == counted {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let on_disk = dir_stats(&blobs_dir);
        let counted = s.store.external_bytes().await.unwrap();
        assert!(
            settled.is_ok(),
            "{} objects ({} bytes) on disk, rows account for {counted}",
            on_disk.0,
            on_disk.1
        );
    }
    // The ledger agrees with the disk: exactly the free room can still be reserved.
    let counted = s.store.external_bytes().await.unwrap();
    let free = ceiling - counted;
    assert!(blobs.reserve(&s.store, free + 1).await.unwrap().is_none());
    let room = blobs.reserve(&s.store, free).await.unwrap();
    assert!(room.is_some(), "the ledger holds bytes no object backs");
    drop(room);
    // And honest creates fill exactly the room that is left, then get 507.
    let fits = (free / object_bytes(bucket)) as usize;
    for _ in 0..fits {
        let r = create(&s.app, &meta(&keys(), "ttl", 3600), &raw_blob(bucket)).await;
        assert_eq!(r.status, StatusCode::CREATED);
    }
    let r = create(&s.app, &meta(&keys(), "ttl", 3600), &raw_blob(bucket)).await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    let on_disk = dir_stats(&blobs_dir);
    assert!(
        on_disk.1 <= ceiling,
        "{} bytes on disk over the ceiling",
        on_disk.1
    );
    assert_eq!(on_disk.1, s.store.external_bytes().await.unwrap());
}

// ============================================================================================
// Admin API helper (the panic, rejection, timeout and leak attacks live in the other spec files).

async fn admin(app: &Router, method: &str, path: &str, token: &str, body: Option<Value>) -> Reply {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        req = req.header(header::CONTENT_TYPE, "application/json");
    }
    send(
        app,
        req.body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
            .unwrap(),
    )
    .await
}

// ============================================================================================
// J. SPEC §4: rate-limit identity cannot be chosen by the client.

async fn reveal_from(app: &Router, ip: &str, extra: &[(&str, &str)]) -> StatusCode {
    let mut req = json_req(
        "/api/v1/secrets/reveal",
        &json!({ "lookup": b64(&random32()) }),
    );
    for (k, v) in extra {
        req.headers_mut().append(
            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    send(app, with_peer(req, ip)).await.status
}

#[tokio::test]
async fn spec_ipv6_neighbours_xff_and_garbage_bearer_share_the_limit() {
    let s = srv("j-holds", &[], &[("rate_reveal_per_hour", "2")]).await;
    // Anywhere inside one /64 is one client.
    let mut statuses = Vec::new();
    for host in [
        "2001:db8:7:7::1",
        "2001:db8:7:7::2",
        "2001:db8:7:7:ffff:ffff:ffff:ffff",
    ] {
        statuses.push(reveal_from(&s.app, host, &[]).await);
    }
    assert_eq!(statuses[2], StatusCode::TOO_MANY_REQUESTS, "{statuses:?}");

    // A direct (untrusted) peer cannot pick its own address with X-Forwarded-For.
    let mut statuses = Vec::new();
    for n in 0..4 {
        let xff = format!("198.51.100.{n}");
        statuses.push(reveal_from(&s.app, "203.0.113.50", &[("x-forwarded-for", &xff)]).await);
    }
    assert_eq!(statuses[2], StatusCode::TOO_MANY_REQUESTS, "{statuses:?}");

    // Garbage bearers of every shape, and an admin key, are all the same anonymous client.
    let admin_key = ADMIN_KEY.to_string();
    let mut statuses = Vec::new();
    for bearer in [
        format!("Bearer {}", b64(&random32())),
        format!("Bearer {}", b64(&random32())),
        format!("Bearer {}", "A".repeat(500)),
        "Basic Zm9vOmJhcg==".to_string(),
        format!("Bearer {admin_key}"),
    ] {
        statuses.push(reveal_from(&s.app, "192.0.2.77", &[("authorization", &bearer)]).await);
    }
    assert_eq!(
        &statuses[2..],
        &[StatusCode::TOO_MANY_REQUESTS; 3],
        "{statuses:?}"
    );
}

async fn proxied_srv(name: &str) -> Srv {
    srv(
        name,
        &[("SHH_TRUSTED_PROXIES", "10.0.0.1")],
        &[("rate_reveal_per_hour", "2")],
    )
    .await
}

// Behind a trusted proxy that appends its own X-Forwarded-For line (HAProxy's
// `option forwardfor`, or any proxy that adds rather than merges), every line is joined
// before the walk from the right, so the client's own line never wins.
#[tokio::test]
async fn spec_all_xff_lines_are_joined_behind_a_proxy() {
    let s = proxied_srv("j-xff-lines").await;
    // Control: one merged header is handled right; the proxy's hop is used and limited.
    let mut merged = Vec::new();
    for n in 0..4 {
        let xff = format!("198.51.100.{n}, 203.0.113.9");
        merged.push(reveal_from(&s.app, "10.0.0.1", &[("x-forwarded-for", &xff)]).await);
    }
    assert_eq!(merged[2], StatusCode::TOO_MANY_REQUESTS, "{merged:?}");
    // The real client is still 203.0.113.9 (the proxy's line) and stays limited.
    let mut split = Vec::new();
    for n in 0..20 {
        let spoof = format!("198.51.100.{}", 100 + n);
        split.push(
            reveal_from(
                &s.app,
                "10.0.0.1",
                &[
                    ("x-forwarded-for", &spoof),
                    ("x-forwarded-for", "203.0.113.9"),
                ],
            )
            .await,
        );
    }
    assert!(
        split.iter().all(|s| *s == StatusCode::TOO_MANY_REQUESTS),
        "{split:?}"
    );
}

// ============================================================================================
// L. SPEC §11: the locale redirect stays on site and adds nothing.

#[tokio::test]
async fn spec_locale_redirect_stays_on_site_and_adds_nothing() {
    let s = srv("l-redirect", &[], &[]).await;
    let mut redirects = 0;
    for (path, lang) in [
        ("/s", "de"),
        ("/s?x=1", "en"),
        ("//evil.com", "en"),
        ("///evil.com", "en"),
        ("/\\evil.com", "en"),
        ("/%2F%2Fevil.com", "en"),
        ("/%5C%5Cevil.com", "en"),
        ("/../evil.com", "en"),
        ("/burn", "evil.com"),
        ("/s", "de-DE;q=abc, //evil.com;q=2"),
        ("/en//evil.com", "en"),
        ("//evil.com/", "en"),
        ("/\\/evil.com/", "en"),
        ("/./\\evil.com/", "en"),
        ("/s/", "en"),
    ] {
        let req = Request::get(path)
            .header(header::HOST, "evil.example")
            .header(header::ACCEPT_LANGUAGE, lang)
            .body(Body::empty())
            .unwrap();
        let r = send(&s.app, req).await;
        if !r.status.is_redirection() {
            continue;
        }
        redirects += 1;
        let loc = r.headers[header::LOCATION].to_str().unwrap().to_string();
        assert!(loc.starts_with('/'), "{path}: {loc}");
        let second = loc.as_bytes().get(1).copied().unwrap_or(b'x');
        assert!(second != b'/' && second != b'\\', "{path}: {loc}");
        assert!(!loc.contains('#') && !loc.contains("://"), "{path}: {loc}");
        // Nothing beyond the input path and query is added.
        let q = path.split_once('?').map(|(_, q)| q);
        assert_eq!(loc.split_once('?').map(|(_, q)| q), q, "{path}: {loc}");
        // A browser resolves it on the same origin.
        assert!(resolve_same_origin(&loc), "{path}: {loc}");
    }
    assert!(redirects >= 10, "{redirects}");
}

// The WHATWG rule that matters: only "//" or "\\" (in either order) at the start of a
// path-absolute reference changes the host.
fn resolve_same_origin(location: &str) -> bool {
    let b = location.as_bytes();
    !(b.len() >= 2 && matches!(b[0], b'/' | b'\\') && matches!(b[1], b'/' | b'\\'))
}

// ============================================================================================
// M. SPEC §8: the admin panel cannot be driven without a valid session.

async fn form(app: &Router, path: &str, cookie: &str, fields: &[(&str, &str)]) -> Reply {
    let body = fields
        .iter()
        .map(|(k, v)| {
            let enc: String = v
                .bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect();
            format!("{k}={enc}")
        })
        .collect::<Vec<_>>()
        .join("&");
    let req = Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    send(app, req).await
}

async fn page(app: &Router, path: &str, cookie: &str) -> Reply {
    send(
        app,
        Request::get(path)
            .header(header::HOST, "localhost")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

fn cookie_of(r: &Reply) -> String {
    r.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn csrf_of(r: &Reply) -> String {
    let t = r.text();
    let from = t.find("name=\"csrf\" value=\"").unwrap() + 19;
    t[from..from + t[from..].find('"').unwrap()].to_string()
}

fn logged_in(r: &Reply) -> bool {
    r.status == StatusCode::OK
}

#[tokio::test]
async fn spec_admin_needs_session_csrf_and_retires_bootstrap() {
    let s = srv_unconfigured("m-admin", &[], &[]).await;
    let boot = form(&s.app, "/en/admin/login", "", &[("credential", BOOTSTRAP)]).await;
    let boot_cookie = cookie_of(&boot);
    let settings = page(&s.app, "/en/admin/settings", &boot_cookie).await;
    assert!(logged_in(&settings));
    let csrf = csrf_of(&settings);

    // Forged or tampered cookies.
    let value = boot_cookie.strip_prefix("shh_admin=").unwrap();
    let (payload, tag) = value.split_once('.').unwrap();
    let mut raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
    raw[33..41].copy_from_slice(&i64::MAX.to_be_bytes()); // stretch the expiry
    let stretched = format!("shh_admin={}.{tag}", b64(&raw));
    let mut raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
    raw[1..33].copy_from_slice(&random32());
    let other_key = format!("shh_admin={}.{tag}", b64(&raw));
    for bad in [
        String::new(),
        "shh_admin=".to_string(),
        stretched,
        other_key,
        format!("shh_admin={payload}.{}", b64(&random32())),
        format!("shh_admin={payload}"),
        format!("x=1; shh_admin={payload}.{tag}x"),
    ] {
        let r = page(&s.app, "/en/admin/settings", &bad).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{bad}");
        let r = form(
            &s.app,
            "/en/admin/keys",
            &bad,
            &[("csrf", &csrf), ("name", "x"), ("scope", "admin")],
        )
        .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{bad}");
    }

    // A valid session without, or with someone else's, CSRF token.
    let other = cookie_of(&form(&s.app, "/en/admin/login", "", &[("credential", BOOTSTRAP)]).await);
    let other_csrf = csrf_of(&page(&s.app, "/en/admin/settings", &other).await);
    assert_ne!(other_csrf, csrf);
    for token in [None, Some(""), Some(other_csrf.as_str()), Some("AAAA")] {
        let mut fields = vec![("name", "x"), ("scope", "admin")];
        if let Some(t) = token {
            fields.push(("csrf", t));
        }
        assert_eq!(
            form(&s.app, "/en/admin/keys", &boot_cookie, &fields)
                .await
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            form(
                &s.app,
                "/en/admin/keys/delete",
                &boot_cookie,
                &[("key_hash", "00")]
            )
            .await
            .status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(s.store.list_api_keys().await.unwrap().len(), 0);

    // The first admin key retires the token everywhere, including live bootstrap sessions.
    let admin_key = admin(
        &s.app,
        "POST",
        "/api/v1/admin/keys",
        BOOTSTRAP,
        Some(json!({"name": "first", "scope": "admin"})),
    )
    .await
    .json()["key"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        page(&s.app, "/en/admin", &boot_cookie).await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        page(&s.app, "/en/admin", &other).await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        form(&s.app, "/en/admin/login", "", &[("credential", BOOTSTRAP)])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        admin(&s.app, "GET", "/api/v1/admin/stats", BOOTSTRAP, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // A user key never opens the panel or the admin API.
    let user_key = admin(
        &s.app,
        "POST",
        "/api/v1/admin/keys",
        &admin_key,
        Some(json!({"name": "u", "scope": "user"})),
    )
    .await
    .json()["key"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        form(&s.app, "/en/admin/login", "", &[("credential", &user_key)])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        admin(&s.app, "GET", "/api/v1/admin/stats", &user_key, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // Deleting the admin key ends its sessions.
    let session =
        cookie_of(&form(&s.app, "/en/admin/login", "", &[("credential", &admin_key)]).await);
    assert!(logged_in(&page(&s.app, "/en/admin", &session).await));
    let id = hex::encode(credential_hash(admin_key.as_bytes()));
    assert_eq!(
        admin(
            &s.app,
            "POST",
            "/api/v1/admin/keys/delete",
            &admin_key,
            Some(json!({"id": id}))
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        page(&s.app, "/en/admin", &session).await.status,
        StatusCode::SEE_OTHER
    );
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ============================================================================================
// N. D-7 / §6.2: no PATCH lifts the 14-day cap or accepts an invalid padded size.

async fn patch(s: &Srv, body: Value) -> Reply {
    admin(
        &s.app,
        "PATCH",
        "/api/v1/admin/settings",
        ADMIN_KEY,
        Some(body),
    )
    .await
}

#[tokio::test]
async fn spec_ttl_is_capped_at_14_days_whatever_is_patched() {
    let s = srv("n-ttl", &[], NO_LIMITS).await;
    // Refused outright (SPEC §7.2) or, until S-10 lands, clamped: never stored above 14 days.
    let r = patch(&s, json!({"max_ttl_secs": 30 * 86_400})).await;
    assert!(
        r.status == StatusCode::UNPROCESSABLE_ENTITY
            || r.json()["values"]["max_ttl_secs"] == "1209600",
        "{}",
        r.text()
    );
    assert_eq!(
        patch(&s, json!({"min_ttl_secs": 15 * 86_400})).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        patch(&s, json!({"default_ttl_secs": 15 * 86_400}))
            .await
            .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    for ttl in [14 * 86_400 + 1, i64::MAX] {
        let r = create(&s.app, &meta(&keys(), "ttl", ttl), &raw_blob(65536)).await;
        assert_eq!(r.json()["error"]["code"], "invalid_ttl", "{ttl}");
    }
    let ok = create(&s.app, &meta(&keys(), "ttl", 14 * 86_400), &raw_blob(65536)).await;
    assert_eq!(ok.status, StatusCode::CREATED);
    // Padding: an invalid size under the live policy is refused, before and after a switch.
    assert_eq!(
        patch(
            &s,
            json!({"padding_mode": "buckets", "padding_ladder": [131072, 1048576]})
        )
        .await
        .status,
        StatusCode::OK
    );
    let r = create(&s.app, &meta(&keys(), "ttl", 3600), &raw_blob(65536)).await;
    assert_eq!(r.json()["error"]["code"], "invalid_blob_length");
    let r = create(&s.app, &meta(&keys(), "ttl", 3600), &raw_blob(131072)).await;
    assert_eq!(r.status, StatusCode::CREATED);
    // Buckets mode without a ladder is refused as a whole.
    assert_eq!(
        patch(&s, json!({"padding_ladder": ""})).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

// ============================================================================================
// O. SPEC §5 / §6.1: pending_delete rows are never served and every counter moves once.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spec_pending_delete_is_never_served_and_counts_once() {
    let (s, root) = local_srv("o-sched", "100000000").await;
    let blobs = s.blobs.clone().unwrap();
    const LARGE: u64 = 131_072;
    // A claimed external secret whose window lapses.
    let k = keys();
    make(&s.app, &k, "single_view", LARGE).await;
    let first = reveal(&s.app, &b64(&k.lookup), None).await;
    let token = claim_token(&first);
    let later = now() + 16 * 60;
    let mut sweeps = Vec::new();
    for _ in 0..4 {
        let store = s.store.clone();
        sweeps.push(tokio::spawn(
            async move { store.sweep(later).await.unwrap() },
        ));
    }
    let consumed: u64 = futures_util::future::join_all(sweeps)
        .await
        .into_iter()
        .map(|r| r.unwrap().consumed)
        .sum();
    assert_eq!(consumed, 1);
    assert_eq!(stats(&s.store).await.viewed, 1);
    // Parked: not served by any path, not confirmable, not countable again.
    assert!(uniform(&reveal(&s.app, &b64(&k.lookup), None).await));
    assert!(uniform(
        &reveal(&s.app, &b64(&k.lookup), Some(&token)).await
    ));
    assert!(uniform(
        &post(
            &s.app,
            "/api/v1/secrets/confirm",
            json!({"lookup": b64(&k.lookup), "claim_token": token})
        )
        .await
    ));
    assert!(uniform(
        &post(
            &s.app,
            "/api/v1/secrets/burn",
            json!({"burn_token": b64(&k.burn)})
        )
        .await
    ));
    post(&s.app, "/api/v1/reports", json!({"lookup": b64(&k.lookup)})).await;
    s.store.sweep(later + 86_400 * 30).await.unwrap();
    let st = stats(&s.store).await;
    assert_eq!((st.viewed, st.burned, st.removed, st.expired), (1, 0, 0, 0));
    assert!(!s.store.pending_deletes().await.unwrap().is_empty());

    // Confirm racing the sweep that would lapse the same claim: one destroy, one count.
    for _ in 0..10 {
        let k = keys();
        make(&s.app, &k, "single_view", LARGE).await;
        let token = claim_token(&reveal(&s.app, &b64(&k.lookup), None).await);
        let before = stats(&s.store).await.viewed;
        let app = s.app.clone();
        let lookup = b64(&k.lookup);
        let c = tokio::spawn(async move {
            post(
                &app,
                "/api/v1/secrets/confirm",
                json!({"lookup": lookup, "claim_token": token}),
            )
            .await
        });
        let store = s.store.clone();
        let w = tokio::spawn(async move { store.sweep(now() + 961).await.unwrap() });
        let (c, w) = (c.await.unwrap(), w.await.unwrap());
        assert_eq!(
            stats(&s.store).await.viewed - before,
            1,
            "confirm {} sweep {:?}",
            c.status,
            w
        );
    }
    // The scrubber deletes objects first, then rows; afterwards nothing is left on disk.
    scheduler::scrub(&s.store, Some(&blobs)).await;
    assert!(s.store.pending_deletes().await.unwrap().is_empty());
    assert_eq!(dir_stats(&root.join("blobs")).0, 0);
}

// ============================================================================================
// P. SPEC §5: a link scanner that follows the share link (without JavaScript) consumes nothing.

#[tokio::test]
async fn spec_following_the_link_and_its_assets_consumes_nothing() {
    let s = srv("p-scanner", &[], NO_LIMITS).await;
    let k = keys();
    make(&s.app, &k, "single_view", 65536).await;
    let fragment = "AQ".to_string() + &"A".repeat(42);
    let mut urls = vec![format!("/s#{fragment}"), "/s".to_string(), "/burn".into()];
    let mut seen = std::collections::HashSet::new();
    while let Some(url) = urls.pop() {
        if !seen.insert(url.clone()) || seen.len() > 60 {
            continue;
        }
        let path = url.split('#').next().unwrap().to_string();
        for method in ["GET", "HEAD", "OPTIONS"] {
            let r = send(
                &s.app,
                Request::builder()
                    .method(method)
                    .uri(&path)
                    .header(header::HOST, "localhost")
                    .header(header::USER_AGENT, "Mozilla/5.0 (compatible; LinkScanner)")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            if let Some(loc) = r.headers.get(header::LOCATION) {
                urls.push(loc.to_str().unwrap().to_string());
            }
            // Follow every same-origin src/href in the page, as a crawler would.
            let html = r.text();
            for attr in ["src=\"", "href=\""] {
                for part in html.split(attr).skip(1) {
                    let link = part.split('"').next().unwrap();
                    if link.starts_with('/') && !link.starts_with("//") {
                        urls.push(link.replace("&amp;", "&"));
                    }
                }
            }
        }
    }
    assert!(seen.len() > 5, "{seen:?}");
    // After all of that the recipient still gets the secret.
    assert_eq!(
        reveal(&s.app, &b64(&k.lookup), None).await.status,
        StatusCode::OK
    );
    assert_eq!(stats(&s.store).await.viewed, 0);
}
