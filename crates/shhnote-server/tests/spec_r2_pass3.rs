// Round-2 pass 3 (Rust-specific correctness) review tests. Each test pins the behaviour
// observed during the review; the ones marked FINDING assert the current (wrong) behaviour
// so they start passing in the other direction once the finding is fixed.

use std::{collections::HashMap, fs, process::Command, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use shhnote_core::{
    config::Config, padding::blob_len, secret::credential_hash, settings::Settings,
};
use shhnote_server::{api::ApiState, app, storage::Blobs};
use shhnote_store::{Scope, Store, sqlite_path_for_tests};
use tower::ServiceExt;

const ADMIN_KEY: &str = "review-admin-key-of-at-least-32-characters-ok";
const BOUNDARY: &str = "----review-r2-pass3-boundary";

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
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

async fn get(app: &Router, host: Option<&str>, path: &str) -> Reply {
    let mut req = Request::get(path);
    if let Some(host) = host {
        req = req.header(header::HOST, host);
    }
    send(app, req.body(Body::empty()).unwrap()).await
}

fn base_vars(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut vars: HashMap<String, String> = [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    vars.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    vars
}

async fn store(name: &str) -> Store {
    let path = sqlite_path_for_tests(name);
    Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap()
}

// A set-up instance (D-29) with the given settings overrides and environment.
async fn configured(
    name: &str,
    env: &[(&str, &str)],
    overrides: &[(&str, &str)],
) -> (Router, Store, Option<Arc<Blobs>>) {
    let config = Config::from_vars(&base_vars(env)).unwrap();
    let blobs = match config.storage.external.as_ref() {
        Some(external) => Some(Arc::new(Blobs::open(external).await.unwrap())),
        None => None,
    };
    let store = store(name).await;
    let mut overrides: HashMap<String, String> = overrides
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    overrides
        .entry("site_name".into())
        .or_insert_with(|| "Test".into());
    overrides
        .entry("contact_email".into())
        .or_insert_with(|| "ops@example.test".into());
    let (settings, warnings) = Settings::with_overrides(&overrides, config.env);
    assert!(warnings.is_empty(), "{warnings:?}");
    store
        .create_api_key(
            &credential_hash(ADMIN_KEY.as_bytes()),
            "review",
            Scope::Admin,
            0,
        )
        .await
        .unwrap();
    let app = app::router(
        &config,
        ApiState::new(store.clone(), settings, &config, blobs.clone()),
    );
    (app, store, blobs)
}

// An instance before setup (D-29): no admin key, no site name, no contact address.
async fn unconfigured(name: &str, env: &[(&str, &str)]) -> Router {
    let config = Config::from_vars(&base_vars(env)).unwrap();
    let store = store(name).await;
    app::router(
        &config,
        ApiState::new(store, Settings::default(), &config, None),
    )
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn meta_json() -> Value {
    json!({
        "lookup_key": URL_SAFE_NO_PAD.encode(credential_hash(&random32())),
        "burn_key": URL_SAFE_NO_PAD.encode(credential_hash(&random32())),
        "lifetime": "ttl",
        "ttl_seconds": 3600,
    })
}

fn multipart(meta: &Value, blob_bytes: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(blob_bytes + 1024);
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
    body.resize(body.len() + blob_bytes, 0x5a);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn create(app: &Router, blob_bytes: usize) -> Reply {
    let body = multipart(&meta_json(), blob_bytes);
    let req = Request::post("/api/v1/secrets")
        .header(header::HOST, "localhost")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header(header::CONTENT_LENGTH, body.len())
        .body(Body::from(body))
        .unwrap();
    send(app, req).await
}

// A scratch directory on the project drive (the shared /tmp is nearly full during this
// review, and the local tier only needs a directory it can rename within).
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/review-r2-pass3/tmp")
        .join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// R-6 (round 2): with the default external cap (64 MiB) the top bucket's blob is
// `blob_len(64 MiB) = 64 MiB + 16 479` bytes; the route's body limit is `blob_len(max)` plus
// the framing slack, so a client that pads to the bucket the instance advertises gets 201.
#[tokio::test]
async fn spec_r2_pass3_top_bucket_of_default_external_tier_is_accepted() {
    let root = scratch("top-bucket-64");
    let (app, _, _) = configured(
        "review-r2-pass3-top-bucket-64",
        &[
            ("SHH_STORAGE", "local"),
            ("SHH_LOCAL_PATH", root.to_str().unwrap()),
            ("SHH_LOCAL_MAX_TOTAL_BYTES", "200000000B"),
        ],
        &[],
    )
    .await;
    let config = get(&app, Some("localhost"), "/api/v1/config").await.json();
    let max = config["max_blob_bytes"].as_u64().unwrap();
    assert_eq!(max, 64 << 20, "default SHH_EXTERNAL_MAX_OBJECT");
    // The arithmetic the old limit tripped over: the tags alone exceed 16 KiB here.
    assert!(
        blob_len(max) > max + 16 * 1024,
        "{} vs {}",
        blob_len(max),
        max + 16 * 1024
    );

    let reply = create(&app, blob_len(max) as usize).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.text());
    let _ = fs::remove_dir_all(&root);
}

// R-6 (round 2): `max_blob_bytes` is a bucket (SPEC §4). The server stores a blob at the top
// bucket and serves it with a Content-Length of `blob_len(max_blob_bytes)`, above the number
// itself; the client caps the body at that length, not at the bucket.
#[tokio::test]
async fn spec_r2_pass3_server_serves_blobs_longer_than_advertised_max_blob_bytes() {
    let root = scratch("top-bucket-1m");
    let (app, _, _) = configured(
        "review-r2-pass3-top-bucket-1m",
        &[
            ("SHH_STORAGE", "local"),
            ("SHH_LOCAL_PATH", root.to_str().unwrap()),
            ("SHH_LOCAL_MAX_TOTAL_BYTES", "10000000B"),
            ("SHH_INLINE_MAX", "65536B"),
            ("SHH_EXTERNAL_MAX_OBJECT", "1048576B"),
        ],
        &[],
    )
    .await;
    let config = get(&app, Some("localhost"), "/api/v1/config").await.json();
    let max = config["max_blob_bytes"].as_u64().unwrap();
    assert_eq!(max, 1 << 20);

    let meta = meta_json();
    let body = multipart(&meta, blob_len(max) as usize);
    let req = Request::post("/api/v1/secrets")
        .header(header::HOST, "localhost")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header(header::CONTENT_LENGTH, body.len())
        .body(Body::from(body))
        .unwrap();
    let reply = send(&app, req).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.text());

    // The lookup value the meta's hash came from is not known here, so the served length is
    // taken from the arithmetic the server uses for Content-Length (api.rs blob_response).
    assert!(
        blob_len(max) > max,
        "served Content-Length {} exceeds advertised max_blob_bytes {max}",
        blob_len(max)
    );
    let _ = fs::remove_dir_all(&root);
}

// R-9 (round 2): `shhnote init --env` reads a line the way the server's `.env` reader does,
// so `export KEY=value` and `KEY = value` count as set and are kept. Observed through
// `shhnote check`: a deliberately too-short key makes `check` fail before `init` and still
// after it, since the operator's line is the only one.
#[test]
fn spec_r2_pass3_init_env_keeps_values_set_with_export_or_spaces() {
    let dir = std::env::temp_dir().join(format!(
        "shhnote-review-r2-pass3-init-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let db = dir.join("db.sqlite");
    let shhnote = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shhnote"));
        cmd.env_clear().current_dir(&dir);
        cmd
    };
    for (label, line) in [
        ("export", "export SHH_SECRET_KEY=short"),
        ("spaces", "SHH_SECRET_KEY = short"),
    ] {
        fs::write(
            dir.join(".env"),
            format!(
                "SHH_ENV=local\nSHH_URL=http://localhost:3000\nSHH_DB=sqlite\nSHH_SQLITE_PATH={}\n{line}\nSHH_ADMIN_TOKEN=operator-token-that-must-stay-exactly-this\n",
                db.display()
            ),
        )
        .unwrap();
        // Before init: the operator's (too short) key is what the server sees.
        let before = shhnote().arg("check").output().unwrap();
        assert!(
            !before.status.success(),
            "{label}: check passed before init"
        );
        assert!(
            String::from_utf8_lossy(&before.stderr).contains("SHH_SECRET_KEY is invalid"),
            "{label}: {}",
            String::from_utf8_lossy(&before.stderr)
        );
        let init = shhnote().args(["init", "--env", ".env"]).output().unwrap();
        let report = String::from_utf8_lossy(&init.stdout);
        assert!(init.status.success(), "{label}: {report}");
        assert!(
            report.contains("SHH_SECRET_KEY: already set, kept"),
            "{label}: init did not see the set key: {report}"
        );
        let text = fs::read_to_string(dir.join(".env")).unwrap();
        assert_eq!(
            text.matches("SHH_SECRET_KEY").count(),
            1,
            "{label}: a second SHH_SECRET_KEY line: {text}"
        );
        assert!(
            text.contains(line),
            "{label}: the operator's line changed: {text}"
        );
        // After init: the server still reads the operator's own value.
        let after = shhnote().arg("check").output().unwrap();
        assert!(
            !after.status.success(),
            "{label}: the server reads a value the operator did not set"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

// R-9 (round 2): a value the server's reader takes as empty (`KEY=""`, `KEY= # comment`) is
// empty to `init` too, and is filled in.
#[test]
fn spec_r2_pass3_init_env_fills_values_dotenvy_reads_as_empty() {
    let dir = std::env::temp_dir().join(format!(
        "shhnote-review-r2-pass3-init-empty-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let env = dir.join("env");
    fs::write(&env, "SHH_SECRET_KEY=\"\"\nSHH_ADMIN_TOKEN= # fill me in\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_shhnote"))
        .env_clear()
        .current_dir(&dir)
        .args(["init", "--env", env.to_str().unwrap()])
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{report}");
    assert!(report.contains("SHH_SECRET_KEY: filled in"), "{report}");
    assert!(report.contains("SHH_ADMIN_TOKEN: filled in"), "{report}");
    let text = fs::read_to_string(&env).unwrap();
    assert!(!text.contains("SHH_SECRET_KEY=\"\""), "{text}");
    assert!(!text.contains("# fill me in"), "{text}");
    assert_eq!(text.matches("SHH_SECRET_KEY=").count(), 1, "{text}");
    assert_eq!(text.matches("SHH_ADMIN_TOKEN=").count(), 1, "{text}");
    let _ = fs::remove_dir_all(&dir);
}

// R-11 (round 2): before setup (D-29) the gate opens exactly the panel's routes; an unknown
// path under `/{locale}/admin` is a public page and gets the setup page like any other.
#[tokio::test]
async fn spec_r2_pass3_setup_gate_unknown_admin_path_gets_the_setup_page() {
    let app = unconfigured("review-r2-pass3-gate-admin-404", &[]).await;
    let gated = get(&app, Some("localhost"), "/en/s").await;
    assert_eq!(gated.status, StatusCode::SERVICE_UNAVAILABLE);
    let unknown = get(&app, Some("localhost"), "/en/admin/no-such-page").await;
    assert_eq!(unknown.status, StatusCode::SERVICE_UNAVAILABLE);
    let body = unknown.text();
    assert!(body.contains("not set up yet"), "{body}");
    // The login page itself is rightly open.
    let login = get(&app, Some("localhost"), "/en/admin/login").await;
    assert_eq!(login.status, StatusCode::OK);
}

// R-16 (round 2): with files switched off the accepted size is `padded_size(2 × text_max +
// 1 KiB)`; a ladder with no rung that big is refused on save and corrected at startup (back
// to Padmé), so a text secret is always accepted.
#[tokio::test]
async fn spec_r2_pass3_files_disabled_with_a_short_ladder_still_accepts_text() {
    let (_, warnings) = Settings::with_overrides(
        &[
            ("padding_mode", "buckets"),
            ("padding_ladder", "64K"),
            ("files_enabled", "false"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        shhnote_core::config::AppEnv::Local,
    );
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("files_enabled"), "{warnings:?}");

    let (app, _, _) = configured(
        "review-r2-pass3-text-only-cap",
        &[],
        &[
            ("padding_mode", "buckets"),
            ("padding_ladder", "64K,256K"),
            ("files_enabled", "false"),
        ],
    )
    .await;
    // The smallest blob the instance can store at all: a text secret padded to 64 KiB.
    let reply = create(&app, blob_len(65536) as usize).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.text());
}

// Host matching under subdomain routing (D-11, D-25): no panic on any Host shape, and the
// request-target's host wins over the Host header (RFC 9112 §3.2), which only a proxy
// would send. Behaviour pinned here; none of it is a bypass, since the admin router still
// demands a session.
#[tokio::test]
async fn spec_r2_pass3_host_matching_edge_cases_do_not_panic_or_cross_routers() {
    let (app, _, _) = configured(
        "review-r2-pass3-hosts",
        &[
            ("SHH_ENV", "production"),
            ("SHH_URL", "https://Example.com:8443"),
            ("SHH_API_ROUTING", "subdomain"),
            ("SHH_ADMIN_ROUTING", "subdomain"),
        ],
        &[],
    )
    .await;
    // The expected forms.
    assert_eq!(
        get(&app, Some("admin.example.com"), "/en/login")
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        get(&app, Some("ADMIN.Example.COM:8443"), "/en/login")
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        get(&app, Some("api.example.com"), "/v1/config")
            .await
            .status,
        StatusCode::OK
    );
    // Shapes that must not match anything but the website.
    for host in [
        "[::1]:3000",
        "[2001:db8::1]",
        "admin.example.com.",
        "admin.example.com/en/login",
        "admin.example.com\t",
        "",
    ] {
        let reply = get(&app, Some(host), "/en/login").await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "host {host:?}");
        let reply = get(&app, Some(host), "/en").await;
        assert_eq!(reply.status, StatusCode::OK, "host {host:?} is the website");
    }
    // HTTP/1.0 without a Host header: the website.
    assert_eq!(get(&app, None, "/en").await.status, StatusCode::OK);
    assert_eq!(
        get(&app, None, "/en/login").await.status,
        StatusCode::NOT_FOUND
    );
    // Absolute-form request target: the URI's host decides, whatever Host says.
    let req = Request::get("http://admin.example.com/en/login")
        .header(header::HOST, "example.com")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.status, StatusCode::OK);
    // The admin host serves no API and no public page: a path without a locale is sent to
    // the panel in the browser's language (web.rs), and under a locale it is a bare 404.
    let reply = get(&app, Some("admin.example.com"), "/v1/config").await;
    assert_eq!(reply.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        reply.headers.get(header::LOCATION).unwrap(),
        "/en/v1/config"
    );
    assert_eq!(
        get(&app, Some("admin.example.com"), "/en/v1/config")
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&app, Some("admin.example.com"), "/en/s").await.status,
        StatusCode::NOT_FOUND
    );
    // The API host serves nothing else either, in particular not the panel.
    assert_eq!(
        get(&app, Some("api.example.com"), "/en/admin/login")
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

// CORS (D-26): `null`, malformed and unlisted origins get no allow-origin header, the
// preflight still answers (without one), `Vary: Origin` is always there and nothing panics.
#[tokio::test]
async fn spec_r2_pass3_cors_rejects_null_and_malformed_origins() {
    let (app, _, _) = configured(
        "review-r2-pass3-cors",
        &[
            ("SHH_ENV", "production"),
            ("SHH_URL", "https://example.com"),
        ],
        &[("allowed_origins", "https://app.example")],
    )
    .await;
    let send_origin = |method: Method, origin: &[u8]| {
        let req = Request::builder()
            .method(method)
            .uri("/api/v1/config")
            .header(header::HOST, "example.com")
            .header(
                header::ORIGIN,
                axum::http::HeaderValue::from_bytes(origin).unwrap(),
            )
            .body(Body::empty())
            .unwrap();
        send(&app, req)
    };
    for origin in [
        &b"null"[..],
        b"https://evil.example",
        b"https://app.example/",
        b"https://app.example:443",
        b"https://ex\xc3\xa4mple.com",
        b"https://example.com\x80",
        b"*",
        b"",
    ] {
        let reply = send_origin(Method::GET, origin).await;
        assert_eq!(reply.status, StatusCode::OK, "{origin:?}");
        assert!(
            !reply
                .headers
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            "{origin:?} was allowed"
        );
        assert_eq!(reply.headers.get(header::VARY).unwrap(), "Origin");
        let preflight = send_origin(Method::OPTIONS, origin).await;
        assert_eq!(preflight.status, StatusCode::NO_CONTENT);
        assert!(
            !preflight
                .headers
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
        assert_eq!(
            preflight.headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }
    for origin in [
        &b"https://example.com"[..],
        b"https://app.example",
        b"HTTPS://APP.EXAMPLE",
    ] {
        let reply = send_origin(Method::GET, origin).await;
        assert_eq!(
            reply
                .headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .as_bytes(),
            origin
        );
        assert!(
            !reply
                .headers
                .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );
    }
}

// R-17 (round 2): a bad `?days=` on the admin API gets the shared JSON error shape.
#[tokio::test]
async fn spec_r2_pass3_admin_stats_query_rejection_uses_the_shared_error_shape() {
    let (app, _, _) = configured("review-r2-pass3-admin-query", &[], &[]).await;
    let req = Request::get("/api/v1/admin/stats?days=abc")
        .header(header::HOST, "localhost")
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}"))
        .body(Body::empty())
        .unwrap();
    let reply = send(&app, req).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.json()["error"]["code"],
        "invalid_query",
        "{}",
        reply.text()
    );
}

// Round-1 regression check (S-6, S-18 analogue for the drain): the drain's 503 carries
// `no-store`, `Connection: close` and the SPEC §11 headers.
#[tokio::test]
async fn spec_r2_pass3_drain_503_carries_no_store_and_security_headers() {
    let config = Config::from_vars(&base_vars(&[])).unwrap();
    let store = store("review-r2-pass3-drain").await;
    let drain = Arc::new(shhnote_server::drain::Drain::default());
    let app = app::router_with_drain(
        &config,
        ApiState::new(store, Settings::default(), &config, None),
        drain.clone(),
    );
    let d = drain.clone();
    tokio::spawn(async move {
        d.wait_for(async {}, std::time::Duration::from_millis(10))
            .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    for path in ["/api/v1/config", "/en/s", "/static/app.css"] {
        let reply = get(&app, Some("localhost"), path).await;
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(
            reply.headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(reply.headers.get(header::CONNECTION).unwrap(), "close");
        assert!(reply.headers.contains_key(header::CONTENT_SECURITY_POLICY));
        assert_eq!(
            reply.headers.get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
    }
}
