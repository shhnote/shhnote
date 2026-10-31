// Regression tests from the security review (docs/security-review/findings/SUMMARY.md): what
// the API must not let a client, a log reader or a dump holder learn about a secret. Ignored
// tests are waiting for the step that fixes their finding; un-ignore them with the fix.
use std::{collections::HashMap, net::SocketAddr, time::Instant};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use shhnote_core::{config::Config, padding::blob_len, secret, settings::Settings};
use shhnote_server::{
    api::{ApiState, now},
    app,
};
use shhnote_store::{Lifetime, NewSecret, Scope, Store, sqlite_path_for_tests};
use tower::ServiceExt;

const BOUNDARY: &str = "----spec-boundary";
const BUCKET: u64 = 65536;

const UNLIMITED: &[(&str, &str)] = &[
    ("rate_create_per_hour", "0"),
    ("rate_reveal_per_hour", "0"),
    ("rate_confirm_per_hour", "0"),
    ("rate_burn_per_hour", "0"),
    ("rate_report_per_hour", "0"),
];

async fn server_with(name: &str, overrides: &[(&str, &str)]) -> (Router, Store) {
    let vars: HashMap<String, String> = [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let config = Config::from_vars(&vars).unwrap();
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let overrides: HashMap<String, String> = overrides
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (settings, warnings) = Settings::with_overrides(&overrides);
    assert!(warnings.is_empty(), "{warnings:?}");
    let app = app::router(
        &config,
        ApiState::new(store.clone(), settings, &config, None),
    );
    (app, store)
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
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

fn post_raw(path: &str, body: &str, ip: &str, auth: Option<&str>) -> Request<Body> {
    let mut b = Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(key) = auth {
        b = b.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    let mut req = b.body(Body::from(body.to_string())).unwrap();
    let addr: SocketAddr = format!("{ip}:40000").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

async fn post(app: &Router, path: &str, body: Value) -> Reply {
    send(app, post_raw(path, &body.to_string(), "198.51.100.1", None)).await
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn raw_blob() -> Vec<u8> {
    let mut blob = vec![0u8; blob_len(BUCKET) as usize];
    getrandom::fill(&mut blob).unwrap();
    blob
}

fn multipart(meta: &Value, blob: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{meta}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(blob);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn create(app: &Router, meta: Value, auth: Option<&str>) -> Reply {
    let mut b = Request::post("/api/v1/secrets")
        .header(header::HOST, "localhost")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        );
    if let Some(key) = auth {
        b = b.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    send(
        app,
        b.body(Body::from(multipart(&meta, &raw_blob()))).unwrap(),
    )
    .await
}

// Plants a row straight into the store (faster than the API for timing runs).
async fn plant(store: &Store, lifetime: Lifetime, expires_at: i64) -> ([u8; 32], [u8; 32]) {
    let lookup = random32();
    let burn = random32();
    let ok = store
        .create(
            &NewSecret {
                lookup_key: secret::credential_hash(&lookup),
                burn_key: secret::credential_hash(&burn),
                lifetime,
                bucket: BUCKET,
                blob: Some(raw_blob()),
                external_ref: None,
                expires_at,
            },
            now(),
        )
        .await
        .unwrap();
    assert!(ok);
    (lookup, burn)
}

fn header_names(h: &HeaderMap) -> Vec<String> {
    let mut v: Vec<String> = h
        .iter()
        .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("?")))
        .collect();
    v.sort();
    v
}

fn assert_same_reply(name: &str, r: &Reply, base: &Reply) {
    assert_eq!(r.status, base.status, "{name}");
    assert_eq!(r.body, base.body, "{name}");
    assert_eq!(
        header_names(&r.headers),
        header_names(&base.headers),
        "{name}"
    );
    assert!(r.headers.get(header::RETRY_AFTER).is_none(), "{name}");
}

// SPEC §4: every negative outcome on reveal, confirm and burn is byte-identical, headers included.
#[tokio::test]
async fn spec_negatives_are_byte_identical() {
    let (app, store) = server_with("spec-privacy-uniform", UNLIMITED).await;
    let t = now();
    let mut replies: Vec<(&str, Reply)> = Vec::new();

    replies.push((
        "reveal never-existed",
        post(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&random32())}),
        )
        .await,
    ));
    replies.push((
        "reveal malformed",
        post(&app, "/api/v1/secrets/reveal", json!({"lookup": "short"})).await,
    ));
    let (expired, _) = plant(&store, Lifetime::Ttl, t - 10).await;
    replies.push((
        "reveal expired (row present)",
        post(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&expired)}),
        )
        .await,
    ));
    let (claimed, _) = plant(&store, Lifetime::SingleView, t + 3600).await;
    let first = post(
        &app,
        "/api/v1/secrets/reveal",
        json!({"lookup": b64(&claimed)}),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    let token = first.headers["x-shh-claim-token"]
        .to_str()
        .unwrap()
        .to_string();
    replies.push((
        "reveal claimed-by-someone-else",
        post(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&claimed)}),
        )
        .await,
    ));
    replies.push((
        "reveal claimed wrong token",
        post(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&claimed), "claim_token": b64(&random32())}),
        )
        .await,
    ));
    let (burned, burn_tok) = plant(&store, Lifetime::Ttl, t + 3600).await;
    assert_eq!(
        post(
            &app,
            "/api/v1/secrets/burn",
            json!({"burn_token": b64(&burn_tok)})
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    replies.push((
        "reveal burned",
        post(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&burned)}),
        )
        .await,
    ));
    let (reported, _) = plant(&store, Lifetime::Ttl, t + 3600).await;
    post(&app, "/api/v1/reports", json!({"lookup": b64(&reported)})).await;
    replies.push((
        "reveal reported",
        post(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&reported)}),
        )
        .await,
    ));
    replies.push((
        "confirm wrong token",
        post(
            &app,
            "/api/v1/secrets/confirm",
            json!({"lookup": b64(&claimed), "claim_token": b64(&random32())}),
        )
        .await,
    ));
    assert_eq!(
        post(
            &app,
            "/api/v1/secrets/confirm",
            json!({"lookup": b64(&claimed), "claim_token": token}),
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    replies.push((
        "confirm consumed",
        post(
            &app,
            "/api/v1/secrets/confirm",
            json!({"lookup": b64(&claimed), "claim_token": token}),
        )
        .await,
    ));
    replies.push((
        "reveal consumed",
        post(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&claimed)}),
        )
        .await,
    ));
    replies.push((
        "burn already burned",
        post(
            &app,
            "/api/v1/secrets/burn",
            json!({"burn_token": b64(&burn_tok)}),
        )
        .await,
    ));
    replies.push((
        "burn malformed",
        post(&app, "/api/v1/secrets/burn", json!({"burn_token": "!!"})).await,
    ));

    let (_, base) = &replies[0];
    assert_eq!(base.status, StatusCode::NOT_FOUND);
    for (name, r) in &replies {
        assert_same_reply(name, r, base);
    }
}

// SPEC §4: a body the framework would reject (wrong type, missing field, bad JSON, no
// Content-Type) gets the same uniform negative as a malformed credential, and `/reports`
// always answers its fixed 200.
#[tokio::test]
#[ignore = "S-26"]
async fn spec_framework_rejections_are_the_uniform_negative() {
    let (app, _) = server_with("spec-privacy-rejections", UNLIMITED).await;
    let base = post(
        &app,
        "/api/v1/secrets/reveal",
        json!({"lookup": b64(&random32())}),
    )
    .await;
    let report_base = post(&app, "/api/v1/reports", json!({"lookup": b64(&random32())})).await;
    assert_eq!(report_base.status, StatusCode::OK);
    for (path, body) in [
        ("/api/v1/secrets/reveal", r#"{"lookup": 12345}"#),
        ("/api/v1/secrets/reveal", r#"{}"#),
        ("/api/v1/secrets/reveal", "not json"),
        ("/api/v1/secrets/burn", r#"{"burn_token": ["x"]}"#),
        ("/api/v1/secrets/confirm", r#"{"lookup": "a"}"#),
    ] {
        let r = send(&app, post_raw(path, body, "198.51.100.2", None)).await;
        assert_same_reply(&format!("{path} {body}"), &r, &base);
    }
    for body in [r#"{"lookup": false}"#, "not json", ""] {
        let r = send(
            &app,
            post_raw("/api/v1/reports", body, "198.51.100.2", None),
        )
        .await;
        assert_same_reply(&format!("/reports {body}"), &r, &report_base);
    }
    let mut req = post_raw(
        "/api/v1/secrets/reveal",
        r#"{"lookup":"x"}"#,
        "198.51.100.2",
        None,
    );
    req.headers_mut().remove(header::CONTENT_TYPE);
    assert_same_reply("no content-type", &send(&app, req).await, &base);
}

// D-21: a create with a known hash answers like a success and writes nothing, so a hash
// holder learns neither that the secret exists nor when it is gone, and cannot plant a row
// behind a consumed link.
#[tokio::test]
#[ignore = "S-9"]
async fn spec_duplicate_create_is_indistinguishable_and_writes_nothing() {
    let (app, store) = server_with("spec-privacy-duplicate", UNLIMITED).await;
    let (lookup, burn) = plant(&store, Lifetime::SingleView, now() + 3600).await;
    let lookup_key = b64(&secret::credential_hash(&lookup));
    let burn_key = b64(&secret::credential_hash(&burn));

    let probe_lookup = |lk: &str| json!({"lookup_key": lk, "burn_key": b64(&random32()), "lifetime": "ttl", "ttl_seconds": 60});
    let fresh = create(
        &app,
        json!({"lookup_key": b64(&random32()), "burn_key": b64(&random32()), "lifetime": "ttl", "ttl_seconds": 60}),
        None,
    )
    .await;
    assert_eq!(fresh.status, StatusCode::CREATED);
    for probe in [
        probe_lookup(&lookup_key),
        json!({"lookup_key": b64(&random32()), "burn_key": burn_key, "lifetime": "ttl", "ttl_seconds": 60}),
    ] {
        let r = create(&app, probe, None).await;
        assert_same_reply("probe while active", &r, &fresh);
    }
    // The row is untouched: the recipient still gets the original single-view secret.
    let rv = post(
        &app,
        "/api/v1/secrets/reveal",
        json!({"lookup": b64(&lookup)}),
    )
    .await;
    assert_eq!(rv.status, StatusCode::OK);
    assert_eq!(rv.body.len(), blob_len(BUCKET) as usize);
    let token = rv.headers["x-shh-claim-token"]
        .to_str()
        .unwrap()
        .to_string();
    post(
        &app,
        "/api/v1/secrets/confirm",
        json!({"lookup": b64(&lookup), "claim_token": token}),
    )
    .await;
    // After consumption the probe looks exactly the same, and nothing is planted behind the link.
    let r = create(&app, probe_lookup(&lookup_key), None).await;
    assert_same_reply("probe after consumption", &r, &fresh);
    let r = post(
        &app,
        "/api/v1/secrets/reveal",
        json!({"lookup": b64(&lookup)}),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "the consumed link stays consumed"
    );
}

// D-18: `expires_at` sits on the expiry grid, so subtracting a preset never lands on the
// creation second.
#[tokio::test]
async fn spec_expires_at_does_not_reveal_creation_second() {
    const PRESETS: [i64; 9] = [
        900, 1800, 3600, 21600, 43200, 86400, 259200, 604800, 1209600,
    ];
    let (app, store) = server_with("spec-privacy-grid", UNLIMITED).await;
    let lookup = random32();
    let before = now();
    let r = create(
        &app,
        json!({
            "lookup_key": b64(&secret::credential_hash(&lookup)),
            "burn_key": b64(&random32()),
            "lifetime": "ttl",
            "ttl_seconds": 3 * 86_400,
        }),
        None,
    )
    .await;
    let after = now();
    assert_eq!(r.status, StatusCode::CREATED);
    let e = store
        .read_ttl(&secret::credential_hash(&lookup), after)
        .await
        .unwrap()
        .unwrap()
        .expires_at;
    // A three-day TTL rounds up to the next whole day.
    assert_eq!(e % 86_400, 0, "expires_at={e} is not on the grid");
    assert!(
        e >= before + 3 * 86_400,
        "expires_at={e} is below the TTL asked for"
    );
    assert!(
        !PRESETS.iter().any(|p| (before..=after).contains(&(e - p))),
        "expires_at={e} minus a preset gives the creation second"
    );
}

// D-23: a keyed request records the UTC day of use, never the second.
#[tokio::test]
async fn spec_keyed_requests_record_only_the_day() {
    let (app, store) = server_with("spec-privacy-userkey", UNLIMITED).await;
    let key = b64(&random32());
    store
        .create_api_key(
            &secret::credential_hash(key.as_bytes()),
            "integrator",
            Scope::User,
            1,
        )
        .await
        .unwrap();
    let lookup = random32();
    let before = now();
    let r = create(
        &app,
        json!({
            "lookup_key": b64(&secret::credential_hash(&lookup)),
            "burn_key": b64(&random32()),
            "lifetime": "ttl",
            "ttl_seconds": 86400,
        }),
        Some(&key),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let used = store.list_api_keys().await.unwrap()[0]
        .last_used_on
        .unwrap();
    assert_eq!(used % 86_400, 0, "last_used_on={used} is not a UTC day");
    assert_eq!(used, before - before.rem_euclid(86_400));
    let r = send(
        &app,
        post_raw(
            "/api/v1/secrets/reveal",
            &json!({"lookup": b64(&lookup)}).to_string(),
            "198.51.100.3",
            Some(&key),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let used2 = store.list_api_keys().await.unwrap()[0]
        .last_used_on
        .unwrap();
    assert_eq!(used2, used, "a second use on the same day changes nothing");
}

// SPEC §4: `Retry-After` is a constant that does not depend on the threshold.
#[tokio::test]
#[ignore = "S-27"]
async fn spec_retry_after_does_not_reveal_the_threshold() {
    let mut seen = Vec::new();
    for per_hour in [10u32, 37, 60] {
        let ph = per_hour.to_string();
        let (app, _) = server_with(
            &format!("spec-privacy-retry-{per_hour}"),
            &[("rate_report_per_hour", ph.as_str())],
        )
        .await;
        let mut retry = None;
        for _ in 0..=per_hour {
            let r = post(&app, "/api/v1/reports", json!({"lookup": "x"})).await;
            if r.status == StatusCode::TOO_MANY_REQUESTS {
                retry = Some(
                    r.headers[header::RETRY_AFTER]
                        .to_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap(),
                );
                break;
            }
        }
        seen.push(retry.expect("limit reached"));
    }
    assert!(
        seen.iter().all(|r| r == &seen[0]),
        "Retry-After varies with the threshold: {seen:?}"
    );
}

fn percentile(v: &mut [u128], q: f64) -> u128 {
    v.sort_unstable();
    v[((v.len() - 1) as f64 * q) as usize]
}

async fn timed(app: &Router, path: &str, body: Value) -> (u128, StatusCode) {
    let req = post_raw(path, &body.to_string(), "198.51.100.9", None);
    let start = Instant::now();
    let r = send(app, req).await;
    (start.elapsed().as_micros(), r.status)
}

// SPEC §4: `/reports` performs the same statement sequence whatever happened, so a matched,
// an unmatched and a malformed report take the same time. The reveal negatives are the
// control: they were already flat. Loose bounds, since this measures wall time.
#[tokio::test]
async fn spec_report_does_the_same_work_on_every_path() {
    const N: usize = 200;
    let (app, store) = server_with("spec-privacy-timing", UNLIMITED).await;
    let t = now();
    let mut report_hits = Vec::new();
    for _ in 0..N {
        report_hits.push(plant(&store, Lifetime::Ttl, t + 3600).await.0);
    }
    for _ in 0..50 {
        timed(&app, "/api/v1/reports", json!({"lookup": b64(&random32())})).await;
    }
    let mut unmatched = Vec::new();
    let mut malformed = Vec::new();
    let mut matched = Vec::new();
    let mut reveal = Vec::new();
    for hit in &report_hits {
        let cases = [
            (
                "/api/v1/reports",
                json!({"lookup": b64(&random32())}),
                &mut unmatched,
            ),
            (
                "/api/v1/reports",
                json!({"lookup": "malformed"}),
                &mut malformed,
            ),
            ("/api/v1/reports", json!({"lookup": b64(hit)}), &mut matched),
            (
                "/api/v1/secrets/reveal",
                json!({"lookup": b64(&random32())}),
                &mut reveal,
            ),
        ];
        for (path, body, samples) in cases {
            let (us, _) = timed(&app, path, body).await;
            samples.push(us);
        }
    }
    let base = percentile(&mut unmatched, 0.5) as f64;
    let mal = percentile(&mut malformed, 0.5) as f64;
    let hit = percentile(&mut matched, 0.5) as f64;
    println!(
        "p50: unmatched={base}us malformed={mal}us matched={hit}us reveal={}us",
        percentile(&mut reveal, 0.5)
    );
    assert!(
        mal >= 0.6 * base,
        "a malformed report skips work: {mal} vs {base}"
    );
    assert!(
        hit <= 1.4 * base,
        "a matched report does extra work: {hit} vs {base}"
    );
}

// SPEC §6.1 / CLAUDE.md: an S3 failure is logged with its status and code only; the object
// key, which `external_ref` maps to a secret, never reaches a log line.
#[tokio::test]
#[ignore = "S-11"]
async fn spec_s3_error_log_text_never_names_the_object() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut n = 0;
                while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    let m = sock.read(&mut buf[n..]).await.unwrap_or(0);
                    if m == 0 {
                        return;
                    }
                    n += m;
                }
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body) = if path.contains("versioning") {
                    ("200 OK", String::new())
                } else {
                    // What AWS and MinIO answer: the key sits early in the error document.
                    let key = path.trim_start_matches("/bucket/");
                    (
                        "404 Not Found",
                        format!(
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>{key}</Key><BucketName>bucket</BucketName><Resource>{path}</Resource><RequestId>17E0</RequestId></Error>"
                        ),
                    )
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(reply.as_bytes()).await;
            });
        }
    });
    let spool = std::env::temp_dir().join(format!("spec-privacy-spool-{}", std::process::id()));
    let vars: HashMap<String, String> = [
        ("SHH_ENV", "local".to_string()),
        ("SHH_URL", "http://localhost:3000".to_string()),
        ("SHH_SECRET_KEY", "s".repeat(44)),
        ("SHH_DB", "sqlite".to_string()),
        ("SHH_STORAGE", "s3".to_string()),
        ("SHH_S3_BUCKET", "bucket".to_string()),
        ("SHH_S3_REGION", "us-east-1".to_string()),
        ("SHH_S3_ENDPOINT", format!("http://127.0.0.1:{port}")),
        ("SHH_S3_ACCESS_KEY_ID", "id".to_string()),
        ("SHH_S3_SECRET_ACCESS_KEY", "secret".to_string()),
        ("SHH_S3_MAX_TOTAL_BYTES", "1000000000".to_string()),
        ("SHH_SPOOL_PATH", spool.display().to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let config = Config::from_vars(&vars).unwrap();
    let blobs = shhnote_server::storage::Blobs::open(config.storage.external.as_ref().unwrap())
        .await
        .unwrap();
    let key = shhnote_server::storage::Blobs::new_key().unwrap();
    let err = blobs.get(&key).await.expect_err("missing object");
    // This string is exactly what `ApiError::internal` logs as "store error: {e}".
    let logged = format!("store error: {err}");
    assert!(
        !logged.contains(&key),
        "object key reaches the log line: {logged}"
    );
    assert!(
        !logged.contains("<Key>"),
        "the S3 body reaches the log line: {logged}"
    );
    let _ = std::fs::remove_dir_all(&spool);
}
