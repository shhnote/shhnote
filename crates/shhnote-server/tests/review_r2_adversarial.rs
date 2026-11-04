// Round 2, pass 7 (adversarial, fresh eyes): each test attacks one property of SPEC.md on the
// current code. A test that fails here is a finding in docs/security-review/round-2/pass7.md;
// the ones that pass are its "checked and clean" evidence.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
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
use shhnote_store::{Lifetime, NewSecret, Scope, Store, sqlite_path_for_tests};
use tokio::net::TcpListener;
use tower::ServiceExt;

const ADMIN_KEY: &str = "r2-admin-key-of-at-least-32-characters-okay";
const BOOTSTRAP: &str = "r2-adversarial-bootstrap-token-0123456789";
const BOUNDARY: &str = "----r2-adversarial";
const NO_LIMITS: &[(&str, &str)] = &[
    ("rate_create_per_hour", "0"),
    ("rate_reveal_per_hour", "0"),
    ("rate_confirm_per_hour", "0"),
    ("rate_burn_per_hour", "0"),
    ("rate_report_per_hour", "0"),
];

// --- harness (the same shape as spec_adversarial.rs, so results are comparable)

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

fn base_vars(env: &[(&str, &str)]) -> HashMap<String, String> {
    let mut vars = map(&[
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
        ("SHH_ADMIN_TOKEN", BOOTSTRAP),
    ]);
    vars.extend(map(env));
    vars
}

async fn srv(name: &str, env: &[(&str, &str)], overrides: &[(&str, &str)]) -> Srv {
    srv_with(name, env, overrides, true).await
}

async fn srv_unconfigured(name: &str, env: &[(&str, &str)], overrides: &[(&str, &str)]) -> Srv {
    srv_with(name, env, overrides, false).await
}

async fn srv_with(
    name: &str,
    env: &[(&str, &str)],
    overrides: &[(&str, &str)],
    configured: bool,
) -> Srv {
    let config = Config::from_vars(&base_vars(env)).unwrap();
    let blobs = match &config.storage.external {
        Some(external) => Some(Arc::new(Blobs::open(external).await.unwrap())),
        None => None,
    };
    let db = sqlite_path_for_tests(&format!("r2-adv-{name}"));
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

async fn get(app: &Router, host: &str, path: &str) -> Reply {
    send(
        app,
        Request::get(path)
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

fn multipart(meta: &Value, blob: &[u8]) -> Vec<u8> {
    let mut body = multipart_head(meta).into_bytes();
    body.extend_from_slice(blob);
    body.extend_from_slice(multipart_tail().as_bytes());
    body
}

fn multipart_head(meta: &Value) -> String {
    format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"meta\"\r\n\r\n{meta}\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
}

fn multipart_tail() -> String {
    format!("\r\n--{BOUNDARY}--\r\n")
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

const UNIFORM: &[u8] = br#"{"error":{"code":"not_found","message":"No secret matches."}}"#;

fn uniform(r: &Reply) -> bool {
    r.status == StatusCode::NOT_FOUND && r.body == UNIFORM
}

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

async fn admin(app: &Router, method: &str, path: &str, token: &str, body: Option<Value>) -> Reply {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = match body {
        Some(v) => {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    send(app, req.body(body).unwrap()).await
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shhnote-r2-pass7-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

// ============================================================================================
// A. SPEC §5.1 / §5.3 / principle 6: one single-view secret, many concurrent takers of every
// kind (reveal, burn, report). At most one of them gets anything.

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn r2_a_mixed_concurrent_takers_at_most_one_wins() {
    for tier in ["inline", "local"] {
        let root = scratch(&format!("a-{tier}"));
        let env: Vec<(&str, &str)> = if tier == "local" {
            vec![
                ("SHH_STORAGE", "local"),
                ("SHH_LOCAL_PATH", root.to_str().unwrap()),
                ("SHH_LOCAL_MAX_TOTAL_BYTES", "100000000"),
                ("SHH_INLINE_MAX", "65536"),
            ]
        } else {
            vec![]
        };
        let s = srv(&format!("a-race-{tier}"), &env, NO_LIMITS).await;
        let bucket = if tier == "local" { 131_072 } else { 65_536 };
        for round in 0..6 {
            let k = keys();
            make(&s.app, &k, "single_view", bucket).await;
            let removed_before = stats(&s.store).await.removed;
            let mut tasks = Vec::new();
            for i in 0..24 {
                let app = s.app.clone();
                tasks.push(tokio::spawn(async move {
                    let r = match i % 3 {
                        0 => reveal(&app, &b64(&k.lookup), None).await,
                        1 => post(&app, "/api/v1/secrets/burn", json!({"burn_token": b64(&k.burn)})).await,
                        _ => post(&app, "/api/v1/reports", json!({"lookup": b64(&k.lookup)})).await,
                    };
                    (i % 3, r)
                }));
            }
            let mut blobs = 0;
            let mut burns = 0;
            for t in tasks {
                let (kind, r) = t.await.unwrap();
                match kind {
                    0 if r.status == StatusCode::OK => {
                        blobs += 1;
                        assert_eq!(r.body.len() as u64, blob_len(bucket));
                    }
                    0 => assert!(uniform(&r), "{r:?}"),
                    1 if r.status == StatusCode::NO_CONTENT => burns += 1,
                    1 => assert!(uniform(&r), "{r:?}"),
                    _ => assert_eq!(r.status, StatusCode::OK),
                }
            }
            let st = stats(&s.store).await;
            assert!(blobs <= 1, "round {round}: {blobs} reveals served the blob");
            assert!(burns <= 1, "round {round}: {burns} burns succeeded");
            let removed = (st.removed - removed_before) as usize;
            assert!(
                blobs + burns + removed == 1,
                "round {round}: blobs {blobs} burns {burns} removed {removed}"
            );
            // Whatever won, the secret is gone for every later non-claimant.
            assert!(uniform(&reveal(&s.app, &b64(&k.lookup), None).await));
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}

// ============================================================================================
// B. SPEC §5.1 step 2: only the exact claim token re-downloads. Tokens of a sibling secret,
// the hashes a dump holds, and a token after confirm all get the uniform negative.

#[tokio::test]
async fn r2_b_redownload_refuses_every_token_but_its_own() {
    let s = srv("b-tokens", &[], NO_LIMITS).await;
    let (k1, k2) = (keys(), keys());
    make(&s.app, &k1, "single_view", 65536).await;
    make(&s.app, &k2, "single_view", 65536).await;
    let r1 = reveal(&s.app, &b64(&k1.lookup), None).await;
    let r2 = reveal(&s.app, &b64(&k2.lookup), None).await;
    let (t1, t2) = (claim_token(&r1), claim_token(&r2));
    assert_ne!(t1, t2);

    let wrong: Vec<String> = vec![
        t2.clone(),                                   // the sibling's token
        b64(&credential_hash(&k1.lookup)),            // the lookup hash (dump column)
        b64(&credential_hash(t1.as_bytes())),         // SHA-256 of the token as text
        b64(&credential_hash(&URL_SAFE_NO_PAD.decode(&t1).unwrap())), // claim_key column
        b64(&k1.burn),                                // the burn token
        t1[..42].to_string() + if t1.ends_with('A') { "B" } else { "A" }, // one char off
        String::new(),
        "A".repeat(43),
    ];
    for w in &wrong {
        let r = reveal(&s.app, &b64(&k1.lookup), Some(w)).await;
        assert!(uniform(&r), "token {w:?} answered {:?}", r.status);
        let c = post(&s.app, "/api/v1/secrets/confirm", json!({"lookup": b64(&k1.lookup), "claim_token": w})).await;
        assert!(uniform(&c), "confirm with {w:?} answered {:?}", c.status);
    }
    // The real one still works, the sibling's lookup with this token does not.
    assert_eq!(reveal(&s.app, &b64(&k1.lookup), Some(&t1)).await.status, StatusCode::OK);
    assert!(uniform(&reveal(&s.app, &b64(&k2.lookup), Some(&t1)).await));
    // After confirm nothing is left, for anyone.
    let c = post(&s.app, "/api/v1/secrets/confirm", json!({"lookup": b64(&k1.lookup), "claim_token": t1})).await;
    assert_eq!(c.status, StatusCode::NO_CONTENT);
    assert!(uniform(&reveal(&s.app, &b64(&k1.lookup), Some(&t1)).await));
    assert!(uniform(&reveal(&s.app, &b64(&k1.lookup), None).await));
    let st = stats(&s.store).await;
    assert_eq!((st.viewed, st.active), (1, 1));
}

// ============================================================================================
// C. SPEC §4: a reporter learns nothing from the answer. Status, body and headers are
// identical for every target; timing is measured and reported, not asserted (see pass7.md).

#[tokio::test]
async fn r2_c_report_answer_identical_for_every_target() {
    let s = srv("c-report", &[], NO_LIMITS).await;
    let live = keys();
    make(&s.app, &live, "ttl", 65536).await;
    let claimed = keys();
    make(&s.app, &claimed, "single_view", 65536).await;
    reveal(&s.app, &b64(&claimed.lookup), None).await;
    let burned = keys();
    make(&s.app, &burned, "ttl", 65536).await;
    post(&s.app, "/api/v1/secrets/burn", json!({"burn_token": b64(&burned.burn)})).await;
    let targets: Vec<Value> = vec![
        json!({"lookup": b64(&live.lookup)}),
        json!({"lookup": b64(&random32())}),
        json!({"lookup": b64(&claimed.lookup)}),
        json!({"lookup": b64(&burned.lookup)}),
        json!({"lookup": b64(&live.lookup)}), // second report of the same (now gone)
        json!({"lookup": "nope"}),
        json!({}),
        json!([1, 2]),
        Value::Null,
    ];
    let mut shapes = Vec::new();
    for t in &targets {
        let r = post(&s.app, "/api/v1/reports", t.clone()).await;
        shapes.push((r.status, header_shape(&r.headers), r.body.clone()));
    }
    // A body that is not JSON at all, and no content type.
    let r = send(
        &s.app,
        Request::post("/api/v1/reports")
            .header(header::HOST, "localhost")
            .body(Body::from("<xml/>"))
            .unwrap(),
    )
    .await;
    shapes.push((r.status, header_shape(&r.headers), r.body.clone()));
    for sh in &shapes {
        assert_eq!(sh, &shapes[0]);
    }
    let st = stats(&s.store).await;
    assert_eq!(st.reports, shapes.len() as i64, "every report counts, malformed ones too");
    assert_eq!(st.removed, 1, "only the live secret was removed");
    assert!(uniform(&reveal(&s.app, &b64(&live.lookup), None).await));
}

// Timing side: a report that removes a large inline row does more database work than one
// that removes nothing. Prints the medians; the write-up decides.
#[tokio::test]
async fn r2_c_report_timing_live_vs_missing_measured() {
    let s = srv("c-timing", &[], NO_LIMITS).await;
    let bucket = 1 << 20;
    let mut live = Vec::new();
    let mut missing = Vec::new();
    for _ in 0..12 {
        let k = keys();
        make(&s.app, &k, "ttl", bucket).await;
        let t = Instant::now();
        post(&s.app, "/api/v1/reports", json!({"lookup": b64(&k.lookup)})).await;
        live.push(t.elapsed());
        let t = Instant::now();
        post(&s.app, "/api/v1/reports", json!({"lookup": b64(&random32())})).await;
        missing.push(t.elapsed());
    }
    live.sort();
    missing.sort();
    eprintln!(
        "r2_c timing (1 MiB inline rows): live median {:?}, missing median {:?}",
        live[live.len() / 2],
        missing[missing.len() / 2]
    );
}

// ============================================================================================
// D. SPEC §2.11 / §5.3: a wrong burn token learns nothing and changes nothing, including on a
// claimed secret (whose claimant keeps re-downloading) and with the share seed as the token.

#[tokio::test]
async fn r2_d_wrong_burn_learns_and_changes_nothing() {
    let s = srv("d-burn", &[], NO_LIMITS).await;
    let k = keys();
    make(&s.app, &k, "single_view", 65536).await;
    let claimed = reveal(&s.app, &b64(&k.lookup), None).await;
    let token = claim_token(&claimed);
    let before = stats(&s.store).await;
    let bad: Vec<String> = vec![
        b64(&k.lookup),                       // the share secret as a burn token
        b64(&credential_hash(&k.burn)),       // the stored hash
        b64(&credential_hash(&k.lookup)),     // the lookup hash
        b64(&k.burn),                         // the right token, but the secret is claimed
        b64(&random32()),
        "".into(),
        "x".repeat(43),
        "A".repeat(44),
    ];
    let mut shapes = Vec::new();
    for b in &bad {
        let r = post(&s.app, "/api/v1/secrets/burn", json!({"burn_token": b})).await;
        assert!(uniform(&r), "{b:?} -> {:?}", r.status);
        shapes.push(header_shape(&r.headers));
    }
    for sh in &shapes {
        assert_eq!(sh, &shapes[0]);
    }
    assert_eq!(stats(&s.store).await, before, "a failed burn moved a counter");
    // The claimant is unaffected.
    assert_eq!(reveal(&s.app, &b64(&k.lookup), Some(&token)).await.status, StatusCode::OK);
}

// ============================================================================================
// E. D-3 / §2.12 / §13: a dump of the database. Every credential column is a hash, and no hash
// in the dump opens, consumes, destroys, reports or administers anything.

#[tokio::test]
async fn r2_e_dump_contents_open_nothing_including_admin() {
    let s = srv("e-dump", &[], NO_LIMITS).await;
    let k = keys();
    make(&s.app, &k, "single_view", 65536).await;
    let t = keys();
    make(&s.app, &t, "ttl", 65536).await;
    let r = reveal(&s.app, &b64(&k.lookup), None).await;
    let token = claim_token(&r);
    let token_raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
    s.store.checkpoint().await.unwrap();
    let dump = std::fs::read(&s.db).unwrap();
    let contains = |needle: &[u8]| dump.windows(needle.len()).any(|w| w == needle);
    // What is there, and what is not.
    for (name, raw, hashed) in [
        ("lookup", k.lookup.to_vec(), credential_hash(&k.lookup).to_vec()),
        ("burn", k.burn.to_vec(), credential_hash(&k.burn).to_vec()),
        ("claim", token_raw.clone(), credential_hash(&token_raw).to_vec()),
        ("admin key", ADMIN_KEY.as_bytes().to_vec(), credential_hash(ADMIN_KEY.as_bytes()).to_vec()),
    ] {
        assert!(contains(&hashed), "{name}: hash missing from the dump");
        assert!(!contains(&raw), "{name}: raw credential in the dump");
    }
    assert!(!contains(BOOTSTRAP.as_bytes()) && !contains(&credential_hash(BOOTSTRAP.as_bytes())));

    // Every hash in the dump, presented as a credential everywhere a credential goes.
    let hashes: Vec<String> = [
        credential_hash(&k.lookup),
        credential_hash(&k.burn),
        credential_hash(&token_raw),
        credential_hash(&t.lookup),
        credential_hash(&t.burn),
        credential_hash(ADMIN_KEY.as_bytes()),
    ]
    .iter()
    .flat_map(|h| [b64(h), h.iter().map(|b| format!("{b:02x}")).collect::<String>()])
    .collect();
    for h in &hashes {
        assert!(uniform(&reveal(&s.app, h, None).await), "{h}");
        assert!(uniform(&reveal(&s.app, &b64(&k.lookup), Some(h)).await), "{h}");
        assert!(uniform(&post(&s.app, "/api/v1/secrets/confirm", json!({"lookup": b64(&k.lookup), "claim_token": h})).await));
        assert!(uniform(&post(&s.app, "/api/v1/secrets/burn", json!({"burn_token": h})).await));
        let a = admin(&s.app, "GET", "/api/v1/admin/stats", h, None).await;
        assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{h}");
        let page = send(
            &s.app,
            Request::get("/en/admin")
                .header(header::HOST, "localhost")
                .header(header::COOKIE, format!("shh_admin={h}.{h}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(page.status, StatusCode::SEE_OTHER, "{h}");
    }
    // Reports with hashes removed nothing: the TTL secret is still readable.
    for h in &hashes {
        post(&s.app, "/api/v1/reports", json!({"lookup": h})).await;
    }
    assert_eq!(reveal(&s.app, &b64(&t.lookup), None).await.status, StatusCode::OK);
    assert_eq!(reveal(&s.app, &b64(&k.lookup), Some(&token)).await.status, StatusCode::OK);
    assert_eq!(stats(&s.store).await.removed, 0);
}

// ============================================================================================
// F/G. §2.8 / §6.1 / D-22: blobs of one bucket are the same on the wire whatever is inside,
// and the only header that differs between lifetimes is the claim token. The server does not
// get a passphrase signal from anything it sees.

#[tokio::test]
async fn r2_fg_wire_shape_same_for_every_content_and_mode() {
    let s = srv("fg-wire", &[], NO_LIMITS).await;
    let policy = PaddingPolicy::Padme { min: 65536 };
    let text = Payload { text: Some("x".repeat(3000)), files: vec![] };
    let file = Payload {
        text: None,
        files: vec![File { name: "a.bin".into(), mime: "image/png".into(), bytes: vec![7; 3000] }],
    };
    let mut made = Vec::new();
    for (payload, pass, lifetime) in [
        (&text, None, "ttl"),
        (&file, None, "ttl"),
        (&text, Some("pass phrase"), "ttl"),
        (&file, Some("pass phrase"), "ttl"),
        (&text, None, "single_view"),
        (&file, Some("pass phrase"), "single_view"),
    ] {
        let e = secret::encrypt(&Randomness::generate().unwrap(), payload, pass, Argon2Params::DEFAULT, &policy).unwrap();
        let m = json!({"lookup_key": b64(&e.lookup_key), "burn_key": b64(&e.burn_key), "lifetime": lifetime, "ttl_seconds": 3600});
        let body = multipart(&m, &e.blob);
        let r = send(&s.app, create_req_sized(body)).await;
        assert_eq!(r.status, StatusCode::CREATED);
        assert_eq!((r.body.len(), header_shape(&r.headers)), (0, header_shape(&r.headers)));
        let seed = shhnote_core::fragment::Fragment::decode(&e.fragment).unwrap().bytes;
        let rv = reveal(&s.app, &b64(&secret::lookup(&seed)), None).await;
        assert_eq!(rv.status, StatusCode::OK);
        assert_eq!(rv.body, e.blob);
        made.push((lifetime, e, rv));
    }
    let create_shape = header_shape(&made[0].2.headers);
    let _ = create_shape;
    let strip = |h: &HeaderMap| {
        let mut h = h.clone();
        h.remove(CLAIM_TOKEN_HEADER);
        header_shape(&h)
    };
    for (lifetime, e, rv) in &made {
        assert_eq!(e.blob.len(), made[0].1.blob.len());
        assert_eq!(e.blob[16..28], made[0].1.blob[16..28], "argon fields differ");
        assert_eq!(strip(&rv.headers), strip(&made[0].2.headers));
        assert_eq!(rv.headers.contains_key(CLAIM_TOKEN_HEADER), *lifetime == "single_view");
    }
}

// ============================================================================================
// H. D-20 / §6.1 / principle 7: an object the tier holds must count against the ceiling. A
// request dropped after the object store committed the PUT but before the row is written
// leaves an object nobody counts; the ceiling is then exceeded by the next honest create.

#[derive(Default)]
struct SlowBucket {
    objects: Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    put_delay: Mutex<Duration>,
}

const FAKE_BUCKET: &str = "fake";

async fn slow_bucket(put_delay: Duration) -> (Arc<SlowBucket>, SocketAddr) {
    let state = Arc::new(SlowBucket { objects: Mutex::default(), put_delay: Mutex::new(put_delay) });
    let app = Router::new().fallback(slow_bucket_request).with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (state, addr)
}

async fn slow_bucket_request(
    axum::extract::State(s3): axum::extract::State<Arc<SlowBucket>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
    body: Bytes,
) -> axum::response::Response {
    use axum::{http::Method, response::IntoResponse};
    let Some(key) = uri.path().strip_prefix(&format!("/{FAKE_BUCKET}/")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match (method, key) {
        (Method::GET, "") if query.contains_key("versioning") => {
            "<VersioningConfiguration></VersioningConfiguration>".into_response()
        }
        (Method::GET, "") => {
            let objects = s3.objects.lock().unwrap();
            let mut xml = String::from("<ListBucketResult>");
            for key in objects.keys() {
                xml.push_str(&format!("<Contents><Key>{key}</Key></Contents>"));
            }
            xml.push_str("<IsTruncated>false</IsTruncated></ListBucketResult>");
            xml.into_response()
        }
        (Method::PUT, key) => {
            // Like S3: the object exists the moment the body is in; the 200 follows later.
            s3.objects.lock().unwrap().insert(key.to_string(), body.to_vec());
            let delay = *s3.put_delay.lock().unwrap();
            tokio::time::sleep(delay).await;
            StatusCode::OK.into_response()
        }
        (Method::GET, key) => match s3.objects.lock().unwrap().get(key) {
            Some(bytes) => bytes.clone().into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        (Method::DELETE, key) => {
            s3.objects.lock().unwrap().remove(key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::BAD_REQUEST.into_response(),
    }
}

#[tokio::test]
async fn r2_h_request_dropped_during_put_leaves_uncounted_object_and_breaks_ceiling() {
    let (s3, addr) = slow_bucket(Duration::from_millis(400)).await;
    let spool = scratch("h-spool");
    let endpoint = format!("http://{addr}");
    let bucket = 131_072u64;
    let ceiling = object_bytes(bucket).to_string();
    let s = srv(
        "h-zombie-s3",
        &[
            ("SHH_STORAGE", "s3"),
            ("SHH_S3_BUCKET", FAKE_BUCKET),
            ("SHH_S3_REGION", "us-east-1"),
            ("SHH_S3_ENDPOINT", &endpoint),
            ("SHH_S3_ACCESS_KEY_ID", "k"),
            ("SHH_S3_SECRET_ACCESS_KEY", "s"),
            ("SHH_S3_MAX_TOTAL_BYTES", &ceiling),
            ("SHH_SPOOL_PATH", spool.to_str().unwrap()),
            ("SHH_INLINE_MAX", "65536"),
        ],
        NO_LIMITS,
    )
    .await;
    let blobs = s.blobs.clone().unwrap();

    // The attack: upload a full-size blob and go away while the object store is acknowledging.
    let body = multipart(&meta(&keys(), "ttl", 3600), &raw_blob(bucket));
    let app = s.app.clone();
    let task = tokio::spawn(async move { send(&app, create_req_sized(body)).await });
    let started = Instant::now();
    while s3.objects.lock().unwrap().is_empty() {
        assert!(started.elapsed() < Duration::from_secs(10), "the PUT never happened");
        assert!(!task.is_finished(), "the create finished before the object landed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    task.abort();
    let _ = task.await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    let held: u64 = s3.objects.lock().unwrap().values().map(|v| v.len() as u64).sum();
    let counted = s.store.external_bytes().await.unwrap();
    assert_eq!(dir_entries(&spool), Vec::<String>::new(), "spool left behind");
    eprintln!("r2_h: tier holds {held} bytes, rows account for {counted}");

    // What the spec promises: the tier holds nothing the rows do not account for, and the
    // ceiling bounds what it holds. An honest create of one more object must therefore fail.
    let honest = create(&s.app, &meta(&keys(), "ttl", 3600), &raw_blob(bucket)).await;
    let held_after: u64 = s3.objects.lock().unwrap().values().map(|v| v.len() as u64).sum();
    let reservation = blobs.reserve(&s.store, 1).await.unwrap();
    assert!(
        held_after <= object_bytes(bucket) && reservation.is_none(),
        "ceiling {ceiling}: tier holds {held_after} bytes after an honest create answered {:?}; \
         the dropped request left {} uncounted byte(s) and the ledger still has room",
        honest.status,
        held - counted
    );
    let _ = std::fs::remove_dir_all(&spool);
}

// ============================================================================================
// H/I. §7.1 / principle 7: the concurrent-upload cap. A client that sends one byte every few
// seconds keeps a slot for the whole upload deadline (max_blob / 32 KiB per second), so a
// handful of trickling connections hold every slot and every other create gets 503.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_h_trickle_uploads_hold_every_slot() {
    let s = srv("h-trickle", &[("SHH_MAX_UPLOADS", "2")], NO_LIMITS).await;
    let bucket = 65_536u64;
    let total = multipart(&meta(&keys(), "ttl", 3600), &raw_blob(bucket)).len();
    let mut holders = Vec::new();
    let mut taps = Vec::new();
    for _ in 0..2 {
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
        let stream = futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|b| (Ok::<Bytes, std::io::Error>(b), rx))
        });
        let mut req = create_req(Body::from_stream(stream));
        req.headers_mut().insert(header::CONTENT_LENGTH, total.into());
        let app = s.app.clone();
        holders.push(tokio::spawn(async move { send(&app, req).await }));
        let head = multipart_head(&meta(&keys(), "ttl", 3600));
        tx.send(Bytes::from(head)).await.unwrap();
        taps.push(tx);
    }
    // Both slots are now taken by uploads that send a byte now and then.
    for _ in 0..5 {
        for tx in &taps {
            tx.send(Bytes::from_static(b"\0")).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    let honest = create(&s.app, &meta(&keys(), "ttl", 3600), &raw_blob(bucket)).await;
    let blocked = honest.status == StatusCode::SERVICE_UNAVAILABLE
        && honest.json()["error"]["code"] == "too_busy";
    drop(taps);
    for h in holders {
        let _ = h.await;
    }
    assert!(
        !blocked,
        "two trickling uploads (a byte every 40 ms, well under the 30 s idle timeout) hold \
         both upload slots; the honest create got 503 too_busy. Each slot stays held for \
         max(60 s, max_blob/32 KiB) = 36 h at the 4 GiB maximum"
    );
}

// ============================================================================================
// I. No request may panic the server, answer 500 with a non-uniform body, or hang.

#[tokio::test]
async fn r2_i_malformed_requests_never_500_or_hang() {
    let s = srv("i-fuzz", &[], NO_LIMITS).await;
    let deep = "[".repeat(100_000) + &"]".repeat(100_000);
    let mut reqs: Vec<Request<Body>> = Vec::new();
    let paths = ["/api/v1/secrets/reveal", "/api/v1/secrets/confirm", "/api/v1/secrets/burn", "/api/v1/reports"];
    for p in paths {
        for body in [
            deep.clone(),
            "{\"lookup\": 1e400}".into(),
            "{\"lookup\": \"\\ud800\"}".into(),
            "\u{feff}{}".into(),
            "{\"lookup\": \"".to_string() + &"A".repeat(1_000_000) + "\"}",
            String::from_utf8_lossy(&[0xff, 0xfe, 0x00, 0x7b]).into_owned(),
        ] {
            reqs.push(Request::post(p).header(header::HOST, "localhost").header(header::CONTENT_TYPE, "application/json").body(Body::from(body)).unwrap());
        }
        reqs.push(Request::post(p).header(header::HOST, "localhost").header(header::CONTENT_TYPE, "text/plain").header(header::CONTENT_LENGTH, "5").body(Body::from("ab")).unwrap());
        reqs.push(Request::builder().method("PUT").uri(p).header(header::HOST, "localhost").body(Body::empty()).unwrap());
    }
    // Create: broken multipart of every kind.
    let m = meta(&keys(), "ttl", 3600);
    let good = multipart(&m, &raw_blob(65536));
    let variants: Vec<(Option<usize>, Vec<u8>, &str)> = vec![
        (None, b"--x\r\n\r\n".to_vec(), "multipart/form-data; boundary=x"),
        (None, Vec::new(), "multipart/form-data"),
        (None, good.clone(), "application/json"),
        (Some(10), good.clone(), "multipart/form-data; boundary=----r2-adversarial"),
        (Some(good.len() * 2), good.clone(), "multipart/form-data; boundary=----r2-adversarial"),
        (Some(0), Vec::new(), "multipart/form-data; boundary=----r2-adversarial"),
        (None, multipart(&json!({"lookup_key": b64(&random32()), "burn_key": b64(&random32()), "lifetime": "ttl", "ttl_seconds": 1e300}), &raw_blob(65536)), "multipart/form-data; boundary=----r2-adversarial"),
        (None, multipart(&json!({"lookup_key": b64(&random32()), "burn_key": b64(&random32()), "lifetime": "ttl", "ttl_seconds": i64::MAX}), &raw_blob(65536)), "multipart/form-data; boundary=----r2-adversarial"),
        (None, multipart(&json!({"lookup_key": b64(&random32()), "burn_key": b64(&random32()), "lifetime": "ttl", "ttl_seconds": -9223372036854775808i64}), &raw_blob(65536)), "multipart/form-data; boundary=----r2-adversarial"),
        (None, multipart(&json!({"lookup_key": "A".repeat(43), "burn_key": b64(&random32()), "lifetime": "ttl", "ttl_seconds": 60}), &[]), "multipart/form-data; boundary=----r2-adversarial"),
        (None, multipart(&json!({"lookup_key": "=".repeat(43), "burn_key": b64(&random32()), "lifetime": "ttl", "ttl_seconds": 60}), &raw_blob(65536)), "multipart/form-data; boundary=----r2-adversarial"),
        (None, { let mut b = multipart_head(&m).into_bytes(); b.extend_from_slice(&vec![0u8; 95]); b.extend_from_slice(multipart_tail().as_bytes()); b }, "multipart/form-data; boundary=----r2-adversarial"),
        (None, { let mut b = multipart_head(&json!({"lookup_key": b64(&random32()), "burn_key": b64(&random32()), "lifetime": "ttl", "ttl_seconds": 60})).into_bytes(); b.extend_from_slice(&[0u8; 0]); b.extend_from_slice(multipart_tail().as_bytes()); b }, "multipart/form-data; boundary=----r2-adversarial"),
        (None, { let mut b = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"blob\"\r\n\r\n").into_bytes(); b.extend_from_slice(&raw_blob(65536)); b.extend_from_slice(multipart_tail().as_bytes()); b }, "multipart/form-data; boundary=----r2-adversarial"),
        (None, format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"meta\"\r\n\r\n{}\r\n--{BOUNDARY}--\r\n", "{".repeat(5000)).into_bytes(), "multipart/form-data; boundary=----r2-adversarial"),
    ];
    for (len, body, ct) in variants {
        let mut req = Request::post("/api/v1/secrets").header(header::HOST, "localhost").header(header::CONTENT_TYPE, ct).body(Body::from(body)).unwrap();
        if let Some(len) = len {
            req.headers_mut().insert(header::CONTENT_LENGTH, len.into());
        }
        reqs.push(req);
    }
    // Pages and odd URIs.
    for p in [
        "/en/s?%00", "/en/%ff", "/en/../../etc/passwd", "/s?x=%0d%0aSet-Cookie:a=b", "/en/admin/login?new=%ff%fe",
        "/en/admin/settings?saved=" , "/api/v1/admin/stats?days=-9223372036854775808", "/api/v1/admin/stats?days=abc",
        "/static/../Cargo.toml", "/en/s/", "/%2e%2e/", "/en/admin/keys?new=" ,
    ] {
        reqs.push(Request::get(p).header(header::HOST, "localhost").header(header::ACCEPT_LANGUAGE, "x".repeat(100_000)).body(Body::empty()).unwrap());
        reqs.push(Request::get(p).header(header::HOST, "evil.com:99999").header(header::AUTHORIZATION, "Bearer ".to_string() + &"%".repeat(43)).body(Body::empty()).unwrap());
    }
    // Admin API with the real key and hostile bodies.
    for body in ["{\"days\": 1}", &deep, "{\"name\": \"\u{0}\", \"scope\": \"admin\"}", "{\"id\": \"zz\"}", "[]"] {
        for (m, p) in [("POST", "/api/v1/admin/keys"), ("PATCH", "/api/v1/admin/settings"), ("POST", "/api/v1/admin/keys/delete")] {
            reqs.push(Request::builder().method(m).uri(p).header(header::HOST, "localhost").header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}")).header(header::CONTENT_TYPE, "application/json").body(Body::from(body.to_string())).unwrap());
        }
    }
    let mut n = 0;
    for req in reqs {
        n += 1;
        let desc = format!("{} {}", req.method(), req.uri());
        let r = tokio::time::timeout(Duration::from_secs(20), send(&s.app, req)).await.unwrap_or_else(|_| panic!("hang: {desc}"));
        assert!(r.status.as_u16() < 500 || r.status == StatusCode::SERVICE_UNAVAILABLE, "{desc}: {:?} {}", r.status, r.text());
        if desc.starts_with("POST /api/v1/secrets/") || desc.starts_with("POST /api/v1/reports") {
            assert!(r.status == StatusCode::OK || uniform(&r), "{desc}: {:?} {}", r.status, r.text());
        }
    }
    assert!(n > 60);
    // Still alive and consistent.
    assert_eq!(get(&s.app, "localhost", "/api/v1/config").await.status, StatusCode::OK);
}

// ============================================================================================
// J. §4: the anonymous limit cannot be escaped by IPv6 spread, mapped forms, bogus
// X-Forwarded-For, rotating garbage bearer tokens or an admin key on the public API.

#[tokio::test]
async fn r2_j_anonymous_limit_holds_against_every_disguise() {
    let s = srv("j-limit", &[], &[("rate_reveal_per_hour", "5")]).await;
    let user = {
        let r = admin(&s.app, "POST", "/api/v1/admin/keys", ADMIN_KEY, Some(json!({"name": "u", "scope": "user"}))).await;
        r.json()["key"].as_str().unwrap().to_string()
    };
    let disguises: Vec<(String, Vec<(String, String)>)> = (0..20)
        .map(|i| {
            let ip = if i % 2 == 0 { format!("2001:db8:1:2::{:x}", i + 1) } else { "203.0.113.9".to_string() };
            let mut hdr = vec![("x-forwarded-for".to_string(), format!("198.51.100.{i}"))];
            match i % 5 {
                0 => hdr.push(("authorization".into(), format!("Bearer {}", b64(&random32())))),
                1 => hdr.push(("authorization".into(), format!("Bearer {ADMIN_KEY}"))),
                2 => hdr.push(("authorization".into(), "Bearer ".to_string() + &"x".repeat(43))),
                3 => hdr.push(("forwarded".into(), format!("for=198.51.100.{i}"))),
                _ => {}
            }
            (ip, hdr)
        })
        .collect();
    let mut v6_ok = 0;
    let mut v4_ok = 0;
    for (ip, hdrs) in &disguises {
        let mut req = json_req("/api/v1/secrets/reveal", &json!({"lookup": b64(&random32())}));
        for (k, v) in hdrs {
            req.headers_mut().insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        let r = send(&s.app, with_peer(req, ip)).await;
        if r.status != StatusCode::TOO_MANY_REQUESTS {
            if ip.starts_with("2001") { v6_ok += 1 } else { v4_ok += 1 }
        } else {
            assert_eq!(r.headers[header::RETRY_AFTER], "60");
        }
    }
    assert_eq!((v6_ok, v4_ok), (5, 5), "one /64 and one IPv4 each got exactly their 5");
    // The mapped form of the IPv4 shares its bucket.
    let r = send(&s.app, with_peer(json_req("/api/v1/secrets/reveal", &json!({"lookup": b64(&random32())})), "::ffff:203.0.113.9")).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    // A real user key is its own bucket, ten times larger, and does not spend the IP's.
    for _ in 0..50 {
        let mut req = json_req("/api/v1/secrets/reveal", &json!({"lookup": b64(&random32())}));
        req.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {user}").parse().unwrap());
        assert!(uniform(&send(&s.app, with_peer(req, "203.0.113.9")).await));
    }
    let mut req = json_req("/api/v1/secrets/reveal", &json!({"lookup": b64(&random32())}));
    req.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {user}").parse().unwrap());
    assert_eq!(send(&s.app, with_peer(req, "203.0.113.9")).await.status, StatusCode::TOO_MANY_REQUESTS);
}

// ============================================================================================
// K. D-17 / D-23 / principle 8: everything the admin API and the database expose about a key
// and a secret created with it.

#[tokio::test]
async fn r2_k_nothing_links_a_user_key_to_its_secret() {
    let s = srv("k-link", &[], NO_LIMITS).await;
    let r = admin(&s.app, "POST", "/api/v1/admin/keys", ADMIN_KEY, Some(json!({"name": "integration", "scope": "user"}))).await;
    let user = r.json()["key"].as_str().unwrap().to_string();
    let k = keys();
    let mut req = create_req_sized(multipart(&meta(&k, "ttl", 7200), &raw_blob(65536)));
    req.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {user}").parse().unwrap());
    assert_eq!(send(&s.app, req).await.status, StatusCode::CREATED);
    let anon = keys();
    make(&s.app, &anon, "ttl", 65536).await;
    s.store.checkpoint().await.unwrap();

    let keys_out = admin(&s.app, "GET", "/api/v1/admin/keys", ADMIN_KEY, None).await.json();
    let st = admin(&s.app, "GET", "/api/v1/admin/stats", ADMIN_KEY, None).await.json();
    let text = format!("{keys_out}{st}");
    // Only day-granular facts about the key; no secret identifier anywhere.
    let entry = keys_out["keys"].as_array().unwrap().iter().find(|e| e["name"] == "integration").unwrap().clone();
    assert_eq!(entry["last_used_on"].as_i64().unwrap() % 86_400, 0, "last use is a day");
    for needle in [b64(&k.lookup), b64(&credential_hash(&k.lookup)), b64(&k.burn), b64(&credential_hash(&k.burn))] {
        assert!(!text.contains(&needle));
    }
    // The dump: the key's hash appears only in api_keys; no secrets column carries anything
    // but hashes, status, lifetime, bucket, blob and a grid expiry.
    let idle = admin(&s.app, "POST", "/api/v1/admin/keys", ADMIN_KEY, Some(json!({"name": "idle", "scope": "user"}))).await.json()["key"].as_str().unwrap().to_string();
    s.store.checkpoint().await.unwrap();
    let dump = std::fs::read(&s.db).unwrap();
    let count = |key: &str| {
        let h = credential_hash(key.as_bytes());
        dump.windows(32).filter(|w| *w == h).count()
    };
    assert_eq!(count(&user), count(&idle), "the creating key's hash is stored no more often than an idle key's (table and index only)");
    assert!(count(&user) >= 1);
    assert!(st["days"].as_array().unwrap().len() <= 1);
}

// ============================================================================================
// L. §2.2 / §11: the locale redirect never leaves the site and never carries a fragment.

#[tokio::test]
async fn r2_l_locale_redirect_targets_stay_relative_to_the_site() {
    let s = srv("l-redirect", &[], &[]).await;
    let s_api = srv("l-redirect-api", &[("SHH_WEB", "api")], &[]).await;
    for path in [
        "/", "/s", "/burn", "//evil.com", "//evil.com/", "/\\evil.com", "/\\\\evil.com/", "/de//evil.com", "/fr/s",
        "/en//evil.com", "/s?next=//evil.com", "/s?x=%2F%2Fevil.com", "/%5Cevil.com", "/en\\evil.com", "/..//evil.com",
        "/s%23AQAA", "/s?#x", "/xx/../s", "/./s", "/s/", "/en/", "/de/s/", "/report", "/how-it-works",
    ] {
        for al in ["de", "en-US,en;q=0.9", "", "zz, de;q=inf", "en;q=nan", "../../x"] {
            for host in ["localhost", "evil.com", "localhost:3000", "", "[::1]:3000"] {
                let r = send(
                    &s.app,
                    Request::get(path).header(header::HOST, host).header(header::ACCEPT_LANGUAGE, al).body(Body::empty()).unwrap(),
                )
                .await;
                if let Some(loc) = r.headers.get(header::LOCATION) {
                    let loc = loc.to_str().unwrap();
                    // On-site means one leading slash and nothing a browser reads as a host.
                    assert!(loc.starts_with('/') && !loc.starts_with("//") && !loc.starts_with("/\\"), "{path} -> {loc}");
                    assert!(!loc.contains('#') && !loc.contains("://"), "{path} -> {loc}");
                }
                assert!(r.status.as_u16() < 500);
            }
        }
        // api mode: no locale redirect, the spec says 404 for every public route.
        let r = get(&s_api.app, "localhost", path).await;
        assert!(r.status == StatusCode::NOT_FOUND || r.status == StatusCode::PERMANENT_REDIRECT, "{path} -> {:?}", r.status);
    }
}

// ============================================================================================
// M. §8: the panel without a valid session.

async fn form(app: &Router, path: &str, cookie: &str, fields: &[(&str, &str)]) -> Reply {
    let body: String = fields.iter().map(|(k, v)| format!("{k}={}", urlencode(v))).collect::<Vec<_>>().join("&");
    let mut req = Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if !cookie.is_empty() {
        req = req.header(header::COOKIE, format!("shh_admin={cookie}"));
    }
    send(app, req.body(Body::from(body)).unwrap()).await
}

fn urlencode(v: &str) -> String {
    let mut out = String::new();
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn page(app: &Router, path: &str, cookie: &str) -> Reply {
    let mut req = Request::get(path).header(header::HOST, "localhost");
    if !cookie.is_empty() {
        req = req.header(header::COOKIE, format!("shh_admin={cookie}"));
    }
    send(app, req.body(Body::empty()).unwrap()).await
}

fn cookie_of(r: &Reply) -> String {
    let sc = r.headers[header::SET_COOKIE].to_str().unwrap();
    sc.split(';').next().unwrap().trim_start_matches("shh_admin=").to_string()
}

fn csrf_of(r: &Reply) -> String {
    let html = r.text();
    let at = html.find("name=\"csrf\"").expect("csrf field");
    let rest = &html[at..];
    let v = rest.find("value=\"").unwrap() + 7;
    rest[v..].split('"').next().unwrap().to_string()
}

#[tokio::test]
async fn r2_m_panel_refuses_forged_stale_and_cross_scope_sessions() {
    let s = srv_unconfigured("m-panel", &[], &[]).await;
    // Bootstrap login, mint the first admin key: the bootstrap session ends with it.
    let login = form(&s.app, "/en/admin/login", "", &[("credential", BOOTSTRAP)]).await;
    assert_eq!(login.status, StatusCode::SEE_OTHER);
    let boot = cookie_of(&login);
    let dash = page(&s.app, "/en/admin", &boot).await;
    assert_eq!(dash.status, StatusCode::OK);
    let csrf = csrf_of(&dash);
    let minted = form(&s.app, "/en/admin/keys", &boot, &[("csrf", &csrf), ("name", "first"), ("scope", "admin")]).await;
    assert_eq!(minted.status, StatusCode::SEE_OTHER);
    let loc = minted.headers[header::LOCATION].to_str().unwrap().to_string();
    let nonce = loc.split("new=").nth(1).unwrap().to_string();
    // The fresh key is handed over only to the minting session's cookie, once.
    let stranger = page(&s.app, &format!("/en/admin/login?new={nonce}"), "").await;
    assert!(!stranger.text().contains("data-shh-new-key") || !stranger.text().contains(&nonce));
    let shown = page(&s.app, &format!("/en/admin/login?new={nonce}"), &boot).await;
    let html = shown.text();
    let key = html.split("<code").nth(1).and_then(|p| p.split('>').nth(1)).and_then(|p| p.split('<').next()).map(|k| k.trim().to_string()).expect("the key is shown once");
    assert_eq!(key.len(), 43, "{key}");
    let again = page(&s.app, &format!("/en/admin/login?new={nonce}"), &boot).await;
    assert!(!again.text().contains(&key), "the key was shown twice");
    // Bootstrap is retired: its cookie, the token on the form and the token on the API.
    assert_eq!(page(&s.app, "/en/admin", &boot).await.status, StatusCode::SEE_OTHER);
    assert_eq!(form(&s.app, "/en/admin/login", "", &[("credential", BOOTSTRAP)]).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(admin(&s.app, "GET", "/api/v1/admin/stats", BOOTSTRAP, None).await.status, StatusCode::UNAUTHORIZED);
    // A user-scope key cannot log in to the panel or use the admin API.
    let user = admin(&s.app, "POST", "/api/v1/admin/keys", &key, Some(json!({"name": "u", "scope": "user"}))).await.json()["key"].as_str().unwrap().to_string();
    assert_eq!(form(&s.app, "/en/admin/login", "", &[("credential", &user)]).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(admin(&s.app, "GET", "/api/v1/admin/keys", &user, None).await.status, StatusCode::UNAUTHORIZED);
    // A real session: forged variants of its cookie, forms without CSRF, logout without CSRF.
    let login = form(&s.app, "/en/admin/login", "", &[("credential", &key)]).await;
    let cookie = cookie_of(&login);
    assert!(login.headers[header::SET_COOKIE].to_str().unwrap().contains("HttpOnly"));
    assert!(!login.headers[header::SET_COOKIE].to_str().unwrap().contains("Domain="));
    let (payload, tag) = cookie.split_once('.').unwrap();
    let mut flipped = payload.to_string();
    flipped.replace_range(0..1, if payload.starts_with('A') { "B" } else { "A" });
    for forged in [format!("{flipped}.{tag}"), format!("{payload}.{}", "A".repeat(43)), format!("{payload}."), payload.to_string(), format!("{tag}.{payload}"), cookie.to_uppercase()] {
        assert_eq!(page(&s.app, "/en/admin", &forged).await.status, StatusCode::SEE_OTHER, "{forged}");
    }
    let dash = page(&s.app, "/en/admin", &cookie).await;
    assert_eq!(dash.status, StatusCode::OK);
    let csrf = csrf_of(&dash);
    for (path, fields) in [
        ("/en/admin/settings", vec![("site_name", "pwned")]),
        ("/en/admin/keys", vec![("name", "x"), ("scope", "admin")]),
        ("/en/admin/keys/delete", vec![("key_hash", &"0".repeat(64))]),
        ("/en/admin/keys/sessions", vec![("key_hash", &"0".repeat(64))]),
        ("/en/admin/logout", vec![]),
    ] {
        let mut wrong = fields.clone();
        wrong.push(("csrf", "not-the-token"));
        assert_eq!(form(&s.app, path, &cookie, &fields).await.status, StatusCode::FORBIDDEN, "{path} without csrf");
        assert_eq!(form(&s.app, path, &cookie, &wrong).await.status, StatusCode::FORBIDDEN, "{path} wrong csrf");
        assert_eq!(form(&s.app, path, "", &[("csrf", &csrf)]).await.status, StatusCode::SEE_OTHER, "{path} without cookie");
    }
    // Ending the key's sessions kills this cookie; the key itself still works on the API.
    let key_hash: String = credential_hash(key.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(form(&s.app, "/en/admin/keys/sessions", &cookie, &[("csrf", &csrf), ("key_hash", &key_hash)]).await.status, StatusCode::SEE_OTHER);
    assert_eq!(page(&s.app, "/en/admin", &cookie).await.status, StatusCode::SEE_OTHER);
    assert_eq!(admin(&s.app, "GET", "/api/v1/admin/stats", &key, None).await.status, StatusCode::OK);
}

// ============================================================================================
// N. §7.2 / D-7 / §6.2: no PATCH lets the instance accept what the policy should reject.

#[tokio::test]
async fn r2_n_settings_patch_cannot_widen_policy() {
    let s = srv("n-patch", &[], NO_LIMITS).await;
    let before = get(&s.app, "localhost", "/api/v1/config").await.json();
    let bad: Vec<Value> = vec![
        json!({"max_ttl_secs": 14 * 86400 + 1}),
        json!({"max_ttl_secs": "1209601"}),
        json!({"max_ttl_secs": 1209600.5}),
        json!({"max_ttl_secs": -1}),
        json!({"min_ttl_secs": 20 * 86400}),
        json!({"ttl_presets": [60, 15 * 86400]}),
        json!({"ttl_presets": "60,1300000"}),
        json!({"default_ttl_secs": 15 * 86400}),
        json!({"min_ttl_secs": 3600, "max_ttl_secs": 1800}),
        json!({"padding_min": 65535}),
        json!({"padding_min": 0}),
        json!({"padding_min": -65536}),
        json!({"padding_min": "65536.0"}),
        json!({"padding_mode": "buckets", "padding_ladder": [65536, 65536]}),
        json!({"padding_mode": "buckets", "padding_ladder": [32768, 65536]}),
        json!({"padding_mode": "buckets", "padding_ladder": [65536, 3 * 1024 * 1024]}),
        json!({"padding_mode": "buckets", "padding_ladder": [65536, 131072, 1048576, 2097152, 4194304]}),
        json!({"padding_mode": "buckets"}),
        json!({"padding_mode": "random"}),
        json!({"claim_window_secs": 59}),
        json!({"claim_window_secs": 86401}),
        json!({"rate_user_multiplier": 0}),
        json!({"text_max_bytes": 2 * 1024 * 1024}),
        json!({"allowed_origins": ["https://a.example/path"]}),
        json!({"allowed_origins": ["*"]}),
        json!({"allowed_origins": "https://a.example, *"}),
        json!({"site_name": ""}),
        json!({"site_name": "   "}),
        json!({"contact_email": ""}),
        json!({"contact_email": "not-an-email"}),
        json!({"unknown_setting": 1}),
        json!({"max_ttl_secs": null, "min_ttl_secs": 20 * 86400}),
        json!({"regions": [{"code": "x", "name": "y", "url": "javascript:alert(1)"}]}),
        json!({"source_url": "ftp://x"}),
    ];
    for b in &bad {
        let r = admin(&s.app, "PATCH", "/api/v1/admin/settings", ADMIN_KEY, Some(b.clone())).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{b} -> {:?} {}", r.status, r.text());
    }
    assert_eq!(get(&s.app, "localhost", "/api/v1/config").await.json(), before, "a refused patch changed the policy");
    // The ceiling itself is accepted, and a create one second over it is refused; the
    // stored expiry never exceeds 14 days plus the day grid.
    let r = admin(&s.app, "PATCH", "/api/v1/admin/settings", ADMIN_KEY, Some(json!({"max_ttl_secs": 14 * 86400, "ttl_presets": [14 * 86400]}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let k = keys();
    assert_eq!(create(&s.app, &meta(&k, "ttl", 14 * 86400 + 1), &raw_blob(65536)).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(create(&s.app, &meta(&k, "ttl", 14 * 86400), &raw_blob(65536)).await.status, StatusCode::CREATED);
    // Lowering max_ttl applies live: the next create at the old maximum is refused.
    let r = admin(&s.app, "PATCH", "/api/v1/admin/settings", ADMIN_KEY, Some(json!({"max_ttl_secs": 3600, "ttl_presets": [900], "default_ttl_secs": 900}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(create(&s.app, &meta(&keys(), "ttl", 3601), &raw_blob(65536)).await.status, StatusCode::BAD_REQUEST);
    // Padding floor raised to 128 KiB: a 64 KiB bucket is now refused, nothing below the
    // floor sneaks in.
    let r = admin(&s.app, "PATCH", "/api/v1/admin/settings", ADMIN_KEY, Some(json!({"padding_min": 131072}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(create(&s.app, &meta(&keys(), "ttl", 900), &raw_blob(65536)).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(create(&s.app, &meta(&keys(), "ttl", 900), &raw_blob(131072)).await.status, StatusCode::CREATED);
}

// ============================================================================================
// O. §5 / principle 6: pending_delete rows are never served, and two schedulers sweeping the
// same backlog count every row exactly once.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_o_two_sweepers_count_each_row_once_and_parked_rows_stay_dark() {
    let root = scratch("o-local");
    let s = srv(
        "o-sched",
        &[
            ("SHH_STORAGE", "local"),
            ("SHH_LOCAL_PATH", root.to_str().unwrap()),
            ("SHH_LOCAL_MAX_TOTAL_BYTES", "100000000"),
            ("SHH_INLINE_MAX", "65536"),
        ],
        NO_LIMITS,
    )
    .await;
    // 450 already-expired inline rows and 3 parked external ones, written straight into the
    // store (the API refuses expired TTLs, a crash-restart does not).
    let t = now();
    for _ in 0..450 {
        let k = keys();
        let created = s.store.create(&NewSecret {
            lookup_key: credential_hash(&k.lookup),
            burn_key: credential_hash(&k.burn),
            lifetime: Lifetime::Ttl,
            bucket: 65536,
            blob: Some(vec![0u8; 100]),
            external_ref: None,
            expires_at: t - 10,
        }, t - 100).await.unwrap();
        assert!(created);
    }
    let mut parked = Vec::new();
    for _ in 0..3 {
        let k = keys();
        make(&s.app, &k, "ttl", 131072).await;
        let r = post(&s.app, "/api/v1/secrets/burn", json!({"burn_token": b64(&k.burn)})).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        parked.push(k);
    }
    // One of them is single-view and was claimed before the burn attempt: still dark.
    let sv = keys();
    make(&s.app, &sv, "single_view", 131072).await;
    let token = claim_token(&reveal(&s.app, &b64(&sv.lookup), None).await);
    assert!(uniform(&post(&s.app, "/api/v1/secrets/burn", json!({"burn_token": b64(&sv.burn)})).await));
    assert_eq!(post(&s.app, "/api/v1/secrets/confirm", json!({"lookup": b64(&sv.lookup), "claim_token": token})).await.status, StatusCode::NO_CONTENT);
    for k in &parked {
        assert!(uniform(&reveal(&s.app, &b64(&k.lookup), None).await));
        assert!(uniform(&reveal(&s.app, &b64(&k.lookup), Some(&token)).await));
        assert!(uniform(&post(&s.app, "/api/v1/secrets/burn", json!({"burn_token": b64(&k.burn)})).await));
    }
    assert!(uniform(&reveal(&s.app, &b64(&sv.lookup), Some(&token)).await));
    let before = stats(&s.store).await;
    // Expired rows the sweeper has not reached yet still count as active (status is what counts).
    assert_eq!((before.burned, before.viewed, before.active), (3, 1, 450));
    // Reports on parked rows count a report and remove nothing.
    for k in &parked {
        post(&s.app, "/api/v1/reports", json!({"lookup": b64(&k.lookup)})).await;
    }
    assert_eq!(stats(&s.store).await.removed, 0);

    // Two schedulers at once (a rolling deploy): every expired row counted once.
    let (a, b) = (s.store.clone(), s.store.clone());
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move { a.sweep(now()).await.unwrap() }),
        tokio::spawn(async move { b.sweep(now()).await.unwrap() })
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    let after = stats(&s.store).await;
    assert_eq!(after.expired, 450, "sweeps reported {ra:?} and {rb:?}");
    assert_eq!(ra.expired + rb.expired, 450);
    // Two scrubbers at once: the parked rows go, each object once, counters untouched.
    let blobs = s.blobs.clone().unwrap();
    let (c, d) = (s.store.clone(), s.store.clone());
    let (b1, b2) = (blobs.clone(), blobs.clone());
    tokio::join!(
        tokio::spawn(async move { scheduler::scrub(&c, Some(&b1)).await }),
        tokio::spawn(async move { scheduler::scrub(&d, Some(&b2)).await })
    ).0.unwrap();
    let end = stats(&s.store).await;
    assert_eq!((end.burned, end.viewed, end.removed, end.expired, end.active), (3, 1, 0, 450, 0));
    assert_eq!(s.store.pending_deletes().await.unwrap().len(), 0);
    assert_eq!(dir_entries(&root.join("blobs")), Vec::<String>::new());
    assert_eq!(s.store.external_bytes().await.unwrap(), 0);
    // The ledger agrees: the whole ceiling is free again.
    assert!(blobs.reserve(&s.store, 100_000_000).await.unwrap().is_some());
    let _ = std::fs::remove_dir_all(&root);
}

// ============================================================================================
// R. D-29: the setup gate. Nothing public and no create before setup; the gate never re-arms.

#[tokio::test]
async fn r2_r_setup_gate_blocks_everything_public_and_never_rearms() {
    let s = srv_unconfigured("r-gate", &[], &[]).await;
    assert_eq!(get(&s.app, "localhost", "/api/v1/health").await.json()["configured"], false);
    for (path, expect) in [
        ("/en", 503), ("/", 503), ("/en/s", 503), ("/en/terms", 503), ("/api/v1/config", 503), ("/api/v1", 503),
        ("/en/admin", 303), ("/en/admin/login", 200), ("/static/app.js", 200), ("/api/v1/health", 200),
        ("/EN/admin", 503), ("/en/admin%2F..%2Fs", 503), ("/en/adminx", 503),
    ] {
        let r = get(&s.app, "localhost", path).await;
        assert_eq!(r.status.as_u16(), expect, "{path}: {}", r.text());
        if expect == 503 {
            assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
            assert!(r.text().contains("not_configured") || r.text().contains("<html"));
        }
    }
    assert_eq!(create(&s.app, &meta(&keys(), "ttl", 3600), &raw_blob(65536)).await.status, StatusCode::SERVICE_UNAVAILABLE);
    // Through the admin prefix: anything under /{locale}/admin/ is open, so an unknown admin
    // path (or one with dot segments nobody normalises) renders a public page.
    for path in ["/en/admin/nothing-here", "/en/admin/../s", "/en/admin/../../de/terms"] {
        let r = get(&s.app, "localhost", path).await;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{path}: {:?}, body starts {}", r.status, &r.text()[..r.text().len().min(200)]);
    }
    // Configure through the API with the bootstrap token.
    let r = admin(&s.app, "PATCH", "/api/v1/admin/settings", BOOTSTRAP, Some(json!({"site_name": "Site", "contact_email": "ops@example.test"}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(get(&s.app, "localhost", "/en").await.status, StatusCode::SERVICE_UNAVAILABLE, "still no admin key");
    let r = admin(&s.app, "POST", "/api/v1/admin/keys", BOOTSTRAP, Some(json!({"name": "first", "scope": "admin"}))).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let key = r.json()["key"].as_str().unwrap().to_string();
    let id = r.json()["id"].as_str().unwrap().to_string();
    assert_eq!(get(&s.app, "localhost", "/en").await.status, StatusCode::OK);
    assert_eq!(get(&s.app, "localhost", "/api/v1/health").await.json()["configured"], true);
    // Cannot be undone through settings...
    for b in [json!({"site_name": ""}), json!({"site_name": null}), json!({"contact_email": null}), json!({"site_name": " "})] {
        assert_eq!(admin(&s.app, "PATCH", "/api/v1/admin/settings", &key, Some(b)).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    // ...and deleting the last admin key (the operator's own lockout) does not re-arm it.
    assert_eq!(admin(&s.app, "POST", "/api/v1/admin/keys/delete", &key, Some(json!({"id": id}))).await.status, StatusCode::NO_CONTENT);
    assert_eq!(get(&s.app, "localhost", "/en").await.status, StatusCode::OK);
    assert_eq!(create(&s.app, &meta(&keys(), "ttl", 3600), &raw_blob(65536)).await.status, StatusCode::CREATED);
    assert_eq!(get(&s.app, "localhost", "/api/v1/health").await.json()["configured"], true);
}

// ============================================================================================
// S. D-24 / D-25: api mode serves nothing public; subdomain admin answers only on its host.

#[tokio::test]
async fn r2_s_api_mode_and_admin_subdomain_serve_only_their_own() {
    let api = srv("s-api", &[("SHH_WEB", "api")], &[]).await;
    for (path, expect) in [
        ("/", 404), ("/s", 404), ("/en", 404), ("/en/s", 404), ("/en/terms", 404), ("/de/how-it-works", 404), ("/en/report", 404),
        ("/static/app.js", 200), ("/static/shh.js", 200), ("/static/argon2.wasm", 200), ("/static/nope.js", 404),
        ("/en/admin/login", 200), ("/api/v1/config", 200), ("/robots.txt", 404), ("/favicon.ico", 404),
    ] {
        let r = get(&api.app, "localhost", path).await;
        assert_eq!(r.status.as_u16(), expect, "{path} answered {:?} {}", r.status, r.headers.get(header::LOCATION).map(|l| l.to_str().unwrap()).unwrap_or(""));
    }
    assert_eq!(get(&api.app, "localhost", "/api/v1/config").await.json()["web_mode"], "api");

    let sub = srv("s-sub", &[("SHH_ENV", "production"), ("SHH_URL", "https://example.com"), ("SHH_ADMIN_ROUTING", "subdomain")], &[]).await;
    for (host, path, expect) in [
        ("example.com", "/en/admin", 404), ("example.com", "/en/admin/login", 404), ("example.com", "/en", 200),
        ("admin.example.com", "/en", 303), ("admin.example.com", "/en/login", 200), ("admin.example.com", "/en/s", 404),
        ("admin.example.com", "/en/terms", 404), ("admin.example.com", "/static/app.js", 200), ("ADMIN.example.com", "/en/login", 200),
        ("admin.example.com:443", "/en/login", 200), ("admin.example.com.evil.com", "/en/login", 404), ("xadmin.example.com", "/en/login", 404),
    ] {
        let r = get(&sub.app, host, path).await;
        assert_eq!(r.status.as_u16(), expect, "{host}{path} answered {:?}", r.status);
    }
    // The cookie is host-only and Secure in production.
    let login = send(
        &sub.app,
        Request::post("/en/login").header(header::HOST, "admin.example.com").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(Body::from(format!("credential={ADMIN_KEY}"))).unwrap(),
    )
    .await;
    assert_eq!(login.status, StatusCode::SEE_OTHER);
    let sc = login.headers[header::SET_COOKIE].to_str().unwrap().to_string();
    assert!(sc.contains("; Secure") && sc.contains("HttpOnly") && sc.contains("SameSite=Strict") && !sc.to_ascii_lowercase().contains("domain="), "{sc}");
    let cookie = cookie_of(&login);
    // Presented on the main host, the panel path is a plain 404 whatever the cookie says.
    for (host, path) in [("example.com", "/en/admin"), ("example.com", "/en/admin/settings"), ("example.com", "/en/admin/login")] {
        let r = send(&sub.app, Request::get(path).header(header::HOST, host).header(header::COOKIE, format!("shh_admin={cookie}")).body(Body::empty()).unwrap()).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{host}{path}");
    }
}

// D-24 / §7.1: "every other public route is 404" in api mode. A path with a trailing slash
// is answered with a redirect instead, by the normalisation layer that runs before routing.
#[tokio::test]
async fn r2_s_api_mode_serves_no_redirect() {
    let api = srv("s-api-redirect", &[("SHH_WEB", "api")], &[]).await;
    for path in ["/en/", "/s/", "/en/s/", "/de/terms/", "/static/", "/anything/"] {
        let r = get(&api.app, "localhost", path).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path} answered {:?} Location: {}", r.status, r.headers.get(header::LOCATION).map(|l| l.to_str().unwrap()).unwrap_or(""));
    }
}

// ============================================================================================
// T. D-26 / §4: CORS only for the site and the allow-list; never credentials, never `*`.

#[tokio::test]
async fn r2_t_cors_answers_only_allowed_origins_without_credentials() {
    let s = srv("t-cors", &[], &[("allowed_origins", "https://front.example")]).await;
    let origins = [
        ("http://localhost:3000", true), ("HTTP://LOCALHOST:3000", true), ("https://front.example", true),
        ("http://localhost:3000/", false), ("http://localhost", false), ("http://localhost:3000.evil.com", false),
        ("https://front.example:443", false), ("https://evil.example", false), ("null", false), ("", false),
        ("https://front.example\t", false), ("http://localhost:3000 ", false),
    ];
    for (origin, allowed) in origins {
        for (method, path) in [("OPTIONS", "/api/v1/secrets/reveal"), ("POST", "/api/v1/secrets/reveal"), ("GET", "/api/v1/config"), ("OPTIONS", "/api/v1/admin/settings"), ("GET", "/en/s")] {
            let mut req = Request::builder().method(method).uri(path).header(header::HOST, "localhost").header(header::ORIGIN, origin).header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST").header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type, authorization, cookie, x-custom");
            if method == "POST" {
                req = req.header(header::CONTENT_TYPE, "application/json");
            }
            let r = send(&s.app, req.body(Body::from("{}")).unwrap()).await;
            let acao = r.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).map(|v| v.to_str().unwrap().to_string());
            let on_api = path.starts_with("/api/");
            assert_eq!(acao.is_some(), allowed && on_api, "{method} {path} origin {origin:?}: {acao:?}");
            if let Some(acao) = &acao {
                assert_eq!(acao, origin);
                assert_ne!(acao, "*");
            }
            assert!(r.headers.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).is_none(), "{method} {path} {origin:?}");
            if let Some(h) = r.headers.get(header::ACCESS_CONTROL_ALLOW_HEADERS) {
                assert!(!h.to_str().unwrap().to_ascii_lowercase().contains("cookie"));
            }
            if on_api {
                assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
                assert!(r.headers.get_all(header::VARY).iter().any(|v| v == "Origin"));
            }
        }
    }
}

// ============================================================================================
// U. §6.1: the startup sweep deletes only our own orphans and stops for nothing.

#[tokio::test]
async fn r2_u_orphan_sweep_keeps_referenced_and_strange_entries() {
    use std::os::unix::ffi::OsStrExt;
    let root = scratch("u-sweep");
    let s = srv(
        "u-sweep",
        &[("SHH_STORAGE", "local"), ("SHH_LOCAL_PATH", root.to_str().unwrap()), ("SHH_LOCAL_MAX_TOTAL_BYTES", "100000000"), ("SHH_INLINE_MAX", "65536")],
        NO_LIMITS,
    )
    .await;
    let live = keys();
    make(&s.app, &live, "ttl", 131072).await;
    let parked = keys();
    make(&s.app, &parked, "ttl", 131072).await;
    assert_eq!(post(&s.app, "/api/v1/secrets/burn", json!({"burn_token": b64(&parked.burn)})).await.status, StatusCode::NO_CONTENT);
    let blobs_dir = root.join("blobs");
    let before = dir_entries(&blobs_dir);
    assert_eq!(before.len(), 2);
    // Strays of every shape, plus two orphans of ours.
    let valid = |i: u8| format!("{}{}", "Q".repeat(21), (b'a' + i) as char);
    std::fs::write(blobs_dir.join(valid(0)), b"orphan").unwrap();
    std::fs::write(blobs_dir.join(valid(1)), b"").unwrap();
    std::fs::write(blobs_dir.join("short"), b"x").unwrap();
    std::fs::write(blobs_dir.join(format!("{}.x", "Q".repeat(20))), b"x").unwrap();
    std::fs::write(blobs_dir.join("Q".repeat(23)), b"x").unwrap();
    std::fs::write(blobs_dir.join(".hidden"), b"x").unwrap();
    std::fs::create_dir(blobs_dir.join(valid(2))).unwrap();
    std::fs::write(blobs_dir.join(valid(2)).join(valid(3)), b"nested").unwrap();
    std::fs::write(blobs_dir.join(std::ffi::OsStr::from_bytes(&[b'Q'; 21].iter().chain([0xffu8].iter()).copied().collect::<Vec<u8>>())), b"not utf-8").unwrap();
    std::os::unix::fs::symlink("/etc/hostname", blobs_dir.join(valid(4))).unwrap();
    std::os::unix::fs::symlink(root.join("blobs"), blobs_dir.join(valid(5))).unwrap();

    let reopened = Blobs::open(Config::from_vars(&base_vars(&[("SHH_STORAGE", "local"), ("SHH_LOCAL_PATH", root.to_str().unwrap()), ("SHH_LOCAL_MAX_TOTAL_BYTES", "100000000")])).unwrap().storage.external.as_ref().unwrap()).await.unwrap();
    let sweep = reopened.collect_orphans(&s.store).await.expect("a stray entry stopped the sweep");
    let after = dir_entries(&blobs_dir);
    for kept in ["short", &format!("{}.x", "Q".repeat(20)), &"Q".repeat(23), ".hidden", &valid(2)] {
        assert!(after.contains(&kept.to_string()), "{kept} was deleted: {after:?}");
    }
    assert!(after.iter().any(|n| n.contains('\u{fffd}')), "the non-UTF-8 entry was deleted");
    for b in &before {
        assert!(after.contains(b), "referenced object {b} was deleted");
    }
    assert_eq!(std::fs::read_dir(blobs_dir.join(valid(2))).unwrap().count(), 1, "the nested file was deleted");
    for gone in [valid(0), valid(1), valid(4), valid(5)] {
        assert!(!after.contains(&gone), "orphan {gone} survived: {after:?}");
    }
    assert_eq!((sweep.removed, sweep.ignored), (4, 6), "{sweep:?}");
    assert_eq!(reveal(&s.app, &b64(&live.lookup), None).await.status, StatusCode::OK);
    let _ = std::fs::remove_dir_all(&root);
}

// ============================================================================================
// V. §6.1 / D-20: declared lengths that are invalid are refused before a byte reaches disk;
// spool bytes stay within what was reserved.

#[tokio::test]
async fn r2_v_invalid_declared_lengths_never_touch_disk() {
    let root = scratch("v-spool");
    let s = srv(
        "v-spool",
        &[("SHH_STORAGE", "local"), ("SHH_LOCAL_PATH", root.to_str().unwrap()), ("SHH_LOCAL_MAX_TOTAL_BYTES", "100000000"), ("SHH_INLINE_MAX", "65536")],
        NO_LIMITS,
    )
    .await;
    let m = meta(&keys(), "ttl", 3600);
    let head = multipart_head(&m).len() as u64;
    let tail = multipart_tail().len() as u64;
    let valid = blob_len(131072);
    // Declared total lengths (meta + framing + blob) where no valid blob fits.
    for declared in [95, 96, blob_len(65536) + head + tail - 1 - 16 * 1024 - 1, valid + head + tail + 16 * 1024 + 1 /* too far above */, u64::MAX / 2, 0] {
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1);
        let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|b| (Ok::<Bytes, std::io::Error>(b), rx)) });
        let mut req = create_req(Body::from_stream(stream));
        req.headers_mut().insert(header::CONTENT_LENGTH, declared.into());
        let app = s.app.clone();
        let task = tokio::spawn(async move { send(&app, req).await });
        // Send the head and the first 200 KiB of blob bytes, then look at the spool directory.
        let _ = tx.send(Bytes::from(multipart_head(&m))).await;
        let _ = tx.send(Bytes::from(vec![1u8; 200 * 1024])).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let spooled = dir_entries(&root.join("tmp"));
        drop(tx);
        let r = tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
        assert!(r.status == StatusCode::BAD_REQUEST || r.status == StatusCode::PAYLOAD_TOO_LARGE, "declared {declared}: {:?} {}", r.status, r.text());
        assert_eq!(spooled, Vec::<String>::new(), "declared {declared}: bytes reached the spool");
    }
    // A plausible declared length whose body is junk: spooled, but never more than reserved,
    // and gone afterwards.
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1);
    let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|b| (Ok::<Bytes, std::io::Error>(b), rx)) });
    let mut req = create_req(Body::from_stream(stream));
    req.headers_mut().insert(header::CONTENT_LENGTH, (valid + head + tail).into());
    let app = s.app.clone();
    let task = tokio::spawn(async move { send(&app, req).await });
    let _ = tx.send(Bytes::from(multipart_head(&m))).await;
    let _ = tx.send(Bytes::from(vec![1u8; valid as usize + 4096])).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let spool_bytes: u64 = std::fs::read_dir(root.join("tmp")).unwrap().filter_map(|e| e.ok()).map(|e| e.metadata().map(|m| m.len()).unwrap_or(0)).sum();
    drop(tx);
    let r = tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());
    assert!(spool_bytes <= valid + 4096, "spool held {spool_bytes}");
    assert_eq!(dir_entries(&root.join("tmp")), Vec::<String>::new());
    assert_eq!(dir_entries(&root.join("blobs")), Vec::<String>::new());
    assert!(s.blobs.as_ref().unwrap().reserve(&s.store, 100_000_000).await.unwrap().is_some(), "reservation leaked");
    let _ = std::fs::remove_dir_all(&root);
}

// ============================================================================================
// X. §8: `shhnote init --env`.

fn shhnote(cwd: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_shhnote"));
    cmd.env_clear().current_dir(cwd);
    cmd
}

#[test]
fn r2_x_init_env_never_changes_what_the_server_reads() {
    let dir = scratch("x-init");
    // Three ways an operator writes a set value that dotenvy (the server's .env reader)
    // accepts: plain, `export`ed, and spaced around `=`. Each must survive `init --env`.
    // The set value is deliberately one the server refuses (too short), so `shhnote check`
    // shows which SHH_SECRET_KEY line the server ends up reading.
    for (i, line) in [
        "SHH_SECRET_KEY=short-set-value".to_string(),
        "export SHH_SECRET_KEY=short-set-value".to_string(),
        "SHH_SECRET_KEY = short-set-value".to_string(),
    ]
    .iter()
    .enumerate()
    {
        let cwd = dir.join(format!("case{i}"));
        std::fs::create_dir_all(&cwd).unwrap();
        let env = cwd.join(".env");
        std::fs::write(&env, format!("SHH_ENV=local\nSHH_URL=http://localhost:3000\nSHH_DB=sqlite\nSHH_SQLITE_PATH={}\n{line}\nSHH_ADMIN_TOKEN={}\n", cwd.join("db.sqlite").display(), "t".repeat(40))).unwrap();
        let before = shhnote(&cwd).arg("check").output().unwrap();
        let out = shhnote(&cwd).args(["init", "--env", env.to_str().unwrap()]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let after_text = std::fs::read_to_string(&env).unwrap();
        let after = shhnote(&cwd).arg("check").output().unwrap();
        let (b, a) = (String::from_utf8_lossy(&before.stdout).to_string(), String::from_utf8_lossy(&after.stdout).to_string());
        let occurrences = after_text.matches("SHH_SECRET_KEY").count();
        let (eb, ea) = (String::from_utf8_lossy(&before.stderr).trim().to_string(), String::from_utf8_lossy(&after.stderr).trim().to_string());
        assert!(
            occurrences == 1 && before.status.code() == after.status.code() && eb == ea,
            "case {i} ({line:?}): the server's view changed.\nfile after init:\n{after_text}\ncheck before: exit {:?} {b:?} {eb:?}\ncheck after: exit {:?} {a:?} {ea:?}",
            before.status.code(), after.status.code()
        );
        assert!(after_text.contains("short-set-value"), "case {i}: the set value was removed");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn r2_x_init_env_does_not_leave_secrets_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("x-mode");
    let env = dir.join(".env");
    std::fs::write(&env, "SHH_ENV=production\nSHH_SECRET_KEY=\n").unwrap();
    std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = shhnote(&dir).args(["init", "--env", env.to_str().unwrap()]).output().unwrap();
    assert!(out.status.success());
    let mode = std::fs::metadata(&env).unwrap().permissions().mode() & 0o777;
    let text = std::fs::read_to_string(&env).unwrap();
    assert!(text.contains("SHH_SECRET_KEY=") && text.len() > 40);
    let warned = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase().contains("readable") || String::from_utf8_lossy(&out.stdout).to_ascii_lowercase().contains("readable");
    assert!(mode & 0o044 == 0 || warned, "secrets written into a mode {mode:o} file without a word about it");
    assert_eq!(dir_entries(&dir), vec![".env".to_string()], "temp file left behind");
    let _ = std::fs::remove_dir_all(&dir);
}
