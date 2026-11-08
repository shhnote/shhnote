use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use shhnote_core::{
    config::Config,
    padding::blob_len,
    secret::credential_hash,
    settings::{RateLimits, Settings},
};
use shhnote_server::{api::ApiState, app};
use shhnote_store::{Scope, Store, sqlite_path_for_tests};
use tower::ServiceExt;

const BOUNDARY: &str = "documentedboundary";
const ADMIN_KEY: &str = "documented-admin-key-of-at-least-32-chars";
const BOOTSTRAP: &str = "documented-bootstrap-token-of-32-chars-plus";

async fn build(name: &str, configured: bool, settings: Settings) -> (Router, Store) {
    let vars: HashMap<String, String> = [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
        ("SHH_ADMIN_TOKEN", BOOTSTRAP),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let config = Config::from_vars(&vars).unwrap();
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let mut settings = settings;
    if configured {
        store
            .create_api_key(&credential_hash(ADMIN_KEY.as_bytes()), "t", Scope::Admin, 0)
            .await
            .unwrap();
        settings.site_name = "Test".into();
        settings.contact_email = "ops@example.test".into();
    }
    let state = ApiState::new(store.clone(), settings, &config, None);
    (app::router(&config, state), store)
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

async fn send(app: &Router, mut req: Request<Body>) -> Reply {
    req.extensions_mut().insert(ConnectInfo(
        "192.0.2.9:40000".parse::<SocketAddr>().unwrap(),
    ));
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

async fn get(app: &Router, path: &str, auth: Option<&str>) -> Reply {
    let mut req = Request::get(path).header(header::HOST, "localhost");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    send(app, req.body(Body::empty()).unwrap()).await
}

async fn post_raw(app: &Router, path: &str, body: &str, auth: Option<&str>) -> Reply {
    let mut req = Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    send(app, req.body(Body::from(body.to_string())).unwrap()).await
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn create(
    app: &Router,
    lookup: &[u8; 32],
    burn: &[u8; 32],
    lifetime: &str,
    auth: Option<&str>,
) -> Reply {
    let bucket = 65536u64;
    let mut blob = vec![0u8; blob_len(bucket) as usize];
    for chunk in blob.chunks_mut(32) {
        let r = random32();
        chunk.copy_from_slice(&r[..chunk.len()]);
    }
    let meta = json!({
        "lookup_key": b64(&credential_hash(lookup)),
        "burn_key": b64(&credential_hash(burn)),
        "lifetime": lifetime,
        "ttl_seconds": 3600,
    });
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{meta}\r\n").as_bytes(),
    );
    body.extend_from_slice(
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(&blob);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    let mut req = Request::post("/api/v1/secrets")
        .header(header::HOST, "localhost")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header(header::CONTENT_LENGTH, body.len());
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    send(app, req.body(Body::from(body)).unwrap()).await
}

// SPEC §4 / D-29: the API root sits behind the setup gate, /health does not and reports the state.
#[tokio::test]
async fn spec_setup_gate_closes_the_api_root_but_not_health() {
    let (app, _) = build("documented-gate", false, Settings::default()).await;
    let root = get(&app, "/api/v1", None).await;
    assert_eq!(root.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(root.json()["error"]["code"], "not_configured");
    assert_eq!(root.header("cache-control"), Some("no-store"));
    let health = get(&app, "/api/v1/health", None).await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.json()["configured"], false);
    assert_eq!(health.json()["status"], "ok");
    assert!(health.json()["version"].is_string());
    // The setup page for HTML, 503 no-store, naming the admin login.
    let page = get(&app, "/en", None).await;
    assert_eq!(page.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(page.header("cache-control"), Some("no-store"));
    assert!(page.text().contains("/en/admin/login"), "{}", page.text());
    assert!(
        !page.text().to_lowercase().contains("bootstrap token"),
        "{}",
        page.text()
    );
    // The admin API answers with the bootstrap token before setup.
    let keys = get(
        &app,
        "/api/v1/admin/keys",
        Some(&format!("Bearer {BOOTSTRAP}")),
    )
    .await;
    assert_eq!(keys.status, StatusCode::OK, "{}", keys.text());
    assert_eq!(keys.header("cache-control"), Some("no-store"));
}

// SPEC §4 table: the API root body, /config fields, /reports fixed body, unknown endpoint,
// trailing-slash redirect, Retry-After constant, api_key_required.
#[tokio::test]
async fn spec_api_answers_have_the_documented_shapes() {
    let settings = Settings {
        rate_limits: RateLimits {
            report_per_hour: 1,
            ..RateLimits::default()
        },
        ..Settings::default()
    };
    let (app, store) = build("documented-shapes", true, settings).await;
    let root = get(&app, "/api/v1", None).await;
    assert_eq!(root.status, StatusCode::OK);
    assert_eq!(root.json(), json!({"name": "shhnote", "version": "v1"}));
    assert_eq!(root.header("cache-control"), Some("no-store"));

    let config = get(&app, "/api/v1/config", None).await;
    let c = config.json();
    for key in [
        "fragment_version",
        "padding",
        "inline_max",
        "max_blob_bytes",
        "claim_window_secs",
        "min_ttl_secs",
        "max_ttl_secs",
        "default_ttl_secs",
        "ttl_presets",
        "text_max_bytes",
        "files_enabled",
        "regions",
        "server_version",
        "web_mode",
    ] {
        assert!(c.get(key).is_some(), "missing {key}");
    }
    assert_eq!(c["fragment_version"], 1);
    assert_eq!(c["web_mode"], "full");
    assert_eq!(c["padding"], json!({"mode": "padme", "min": 65536}));
    assert_eq!(c["claim_window_secs"], 900);
    assert_eq!(c["text_max_bytes"], 65536);
    assert_eq!(c["inline_max"], 2 * 1024 * 1024);
    assert_eq!(config.header("cache-control"), Some("no-store"));

    let report = post_raw(&app, "/api/v1/reports", "garbage", None).await;
    assert_eq!(report.status, StatusCode::OK);
    assert_eq!(report.text(), r#"{"status":"received"}"#);
    assert_eq!(report.header("cache-control"), Some("no-store"));
    // Even a malformed report is counted (api.rs comment / D-19).
    assert_eq!(store.stats().await.unwrap().reports, 1);
    let limited = post_raw(&app, "/api/v1/reports", "garbage", None).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.header("retry-after"), Some("60"));
    assert_eq!(limited.json()["error"]["code"], "rate_limited");

    let nope = get(&app, "/api/v1/nope", None).await;
    assert_eq!(nope.status, StatusCode::NOT_FOUND);
    assert_eq!(nope.json()["error"]["code"], "no_such_endpoint");

    let slash = get(&app, "/api/v1/config/", None).await;
    assert_eq!(slash.status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(slash.header("location"), Some("/api/v1/config"));
    assert_eq!(slash.header("cache-control"), Some("no-store"));

    // 404 pages and the JSON 404 both carry the security headers.
    for path in ["/en/nope", "/api/v1/nope"] {
        let r = get(&app, path, None).await;
        for h in [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ] {
            assert!(r.header(h).is_some(), "{path} lacks {h}");
        }
        assert!(
            r.header("strict-transport-security").is_none(),
            "HSTS only in production"
        );
    }
}

// SPEC §5: reveal responses: claim token header on single-view only, Content-Length from the
// bucket, nothing about expiry on a TTL secret; burn/report refuse a claimed row;
// require_api_key_for_create gives 401 api_key_required.
#[tokio::test]
async fn spec_reveal_burn_and_report_headers_follow_the_lifecycle() {
    let (app, store) = build("documented-life", true, Settings::default()).await;
    let (lookup, burn) = (random32(), random32());
    assert_eq!(
        create(&app, &lookup, &burn, "single_view", None)
            .await
            .status,
        StatusCode::CREATED
    );
    // D-21: the duplicate answers 201 and writes nothing.
    assert_eq!(
        create(&app, &lookup, &burn, "single_view", None)
            .await
            .status,
        StatusCode::CREATED
    );
    assert_eq!(store.stats().await.unwrap().created, 1);

    let reveal = post_raw(
        &app,
        "/api/v1/secrets/reveal",
        &json!({"lookup": b64(&lookup)}).to_string(),
        None,
    )
    .await;
    assert_eq!(reveal.status, StatusCode::OK);
    let token = reveal.header("x-shh-claim-token").unwrap().to_string();
    assert_eq!(token.len(), 43);
    assert_eq!(
        reveal.header("content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(reveal.header("cache-control"), Some("no-store"));
    assert_eq!(
        reveal.header("content-length"),
        Some(blob_len(65536).to_string().as_str())
    );
    assert_eq!(reveal.body.len() as u64, blob_len(65536));
    // The stats active count includes the claimed row (SPEC §3).
    assert_eq!(store.stats().await.unwrap().active, 1);
    // Burn and report against a claimed row: the uniform negative / fixed body, row untouched.
    let b = post_raw(
        &app,
        "/api/v1/secrets/burn",
        &json!({"burn_token": b64(&burn)}).to_string(),
        None,
    )
    .await;
    assert_eq!(b.status, StatusCode::NOT_FOUND);
    assert_eq!(
        b.json(),
        json!({"error": {"code": "not_found", "message": "No secret matches."}})
    );
    let r = post_raw(
        &app,
        "/api/v1/reports",
        &json!({"lookup": b64(&lookup)}).to_string(),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(store.stats().await.unwrap().active, 1);
    // Re-download with the token works; a second claim without it is the uniform negative.
    let again = post_raw(
        &app,
        "/api/v1/secrets/reveal",
        &json!({"lookup": b64(&lookup), "claim_token": token}).to_string(),
        None,
    )
    .await;
    assert_eq!(again.status, StatusCode::OK);
    assert!(again.header("x-shh-claim-token").is_none());
    let other = post_raw(
        &app,
        "/api/v1/secrets/reveal",
        &json!({"lookup": b64(&lookup)}).to_string(),
        None,
    )
    .await;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
    // Confirm: 204, viewed moves, active drops.
    let confirm = post_raw(
        &app,
        "/api/v1/secrets/confirm",
        &json!({"lookup": b64(&lookup), "claim_token": token}).to_string(),
        None,
    )
    .await;
    assert_eq!(confirm.status, StatusCode::NO_CONTENT);
    let stats = store.stats().await.unwrap();
    assert_eq!((stats.viewed, stats.active), (1, 0));

    // TTL: pure read, no claim header, nothing about expiry in any header.
    let (lookup2, burn2) = (random32(), random32());
    assert_eq!(
        create(&app, &lookup2, &burn2, "ttl", None).await.status,
        StatusCode::CREATED
    );
    let ttl = post_raw(
        &app,
        "/api/v1/secrets/reveal",
        &json!({"lookup": b64(&lookup2)}).to_string(),
        None,
    )
    .await;
    assert_eq!(ttl.status, StatusCode::OK);
    assert!(ttl.header("x-shh-claim-token").is_none());
    let names: Vec<String> = ttl.headers.keys().map(|k| k.as_str().to_string()).collect();
    assert!(
        !names
            .iter()
            .any(|n| n.contains("expir") || n.contains("ttl")),
        "{names:?}"
    );
    assert_eq!(
        store.stats().await.unwrap().viewed,
        1,
        "a TTL read counts nothing"
    );
    let burned = post_raw(
        &app,
        "/api/v1/secrets/burn",
        &json!({"burn_token": b64(&burn2)}).to_string(),
        None,
    )
    .await;
    assert_eq!(burned.status, StatusCode::NO_CONTENT);
    assert_eq!(store.stats().await.unwrap().burned, 1);
}

#[tokio::test]
async fn spec_api_key_required_and_admin_api_error_codes() {
    let settings = Settings {
        require_api_key_for_create: true,
        ..Settings::default()
    };
    let (app, store) = build("documented-keys", true, settings).await;
    let (lookup, burn) = (random32(), random32());
    let refused = create(&app, &lookup, &burn, "ttl", None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.json()["error"]["code"], "api_key_required");
    // A user key satisfies it and records the day only.
    let user_key = b64(&random32());
    store
        .create_api_key(&credential_hash(user_key.as_bytes()), "u", Scope::User, 0)
        .await
        .unwrap();
    let ok = create(
        &app,
        &lookup,
        &burn,
        "ttl",
        Some(&format!("Bearer {user_key}")),
    )
    .await;
    assert_eq!(ok.status, StatusCode::CREATED, "{}", ok.text());
    let key = store
        .find_api_key(&credential_hash(user_key.as_bytes()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(key.last_used_on.unwrap() % 86_400, 0);

    // Admin API: a user key is 401; invalid JSON is 400 invalid_json; a bad id is 400
    // invalid_key; a well-formed unknown id is 404 no_such_key.
    let admin = format!("Bearer {ADMIN_KEY}");
    let user = format!("Bearer {user_key}");
    let r = get(&app, "/api/v1/admin/stats", Some(&user)).await;
    assert_eq!(
        (r.status, r.json()["error"]["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("unauthorized"))
    );
    let r = post_raw(&app, "/api/v1/admin/keys", "{", Some(&admin)).await;
    assert_eq!(
        (r.status, r.json()["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_json"))
    );
    let r = post_raw(
        &app,
        "/api/v1/admin/keys/delete",
        r#"{"id":"zz"}"#,
        Some(&admin),
    )
    .await;
    assert_eq!(
        (r.status, r.json()["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_key"))
    );
    let r = post_raw(
        &app,
        "/api/v1/admin/keys/delete",
        &json!({"id": "ab".repeat(32)}).to_string(),
        Some(&admin),
    )
    .await;
    assert_eq!(
        (r.status, r.json()["error"]["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("no_such_key"))
    );
    let r = get(&app, "/api/v1/admin/stats?days=5", Some(&admin)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.json()["days"].is_array());
    assert_eq!(r.json()["active"], 1);
    // settings PATCH: unknown key → 422 with details; clearing site_name → 422.
    let r = send(
        &app,
        Request::patch("/api/v1/admin/settings")
            .header(header::HOST, "localhost")
            .header(header::AUTHORIZATION, &admin)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"site_name":""}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.text());
    assert_eq!(r.json()["error"]["code"], "invalid_settings");
    assert!(
        r.json()["details"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d.as_str().unwrap().contains("cannot be cleared"))
    );
}
