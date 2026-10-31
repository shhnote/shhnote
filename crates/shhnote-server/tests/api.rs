use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use shhnote_core::{
    config::AppEnv,
    config::Config,
    container::{File, Payload},
    kdf::Argon2Params,
    padding::{PaddingPolicy, blob_len},
    secret::{self, Randomness},
    settings::Settings,
};
use shhnote_server::{
    api::{ApiState, CLAIM_TOKEN_HEADER, now},
    app, scheduler,
    storage::Blobs,
};
use shhnote_store::{Store, sqlite_path_for_tests};
use tower::ServiceExt;

const BOUNDARY: &str = "----shhnote-test-boundary";

async fn server(name: &str) -> Router {
    server_with(name, &[]).await
}

async fn server_with(name: &str, overrides: &[(&str, &str)]) -> Router {
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
    let (settings, warnings) = Settings::with_overrides(&overrides, AppEnv::Local);
    assert!(warnings.is_empty(), "{warnings:?}");
    app::router(&config, ApiState::new(store, settings, &config, None))
}

async fn post_json_from(app: &Router, path: &str, body: Value, ip: &str) -> Reply {
    let mut req = Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let addr: SocketAddr = format!("{ip}:40000").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    send(app, req).await
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

async fn post_json(app: &Router, path: &str, body: Value) -> Reply {
    let req = Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    send(app, req).await
}

async fn create(app: &Router, meta: Value, blob: &[u8]) -> Reply {
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

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

// Opaque bytes of a valid length: the server never looks inside, so this is a complete test
// of storage and lifecycle without any encryption involved.
fn raw_blob(bucket: u64) -> Vec<u8> {
    let mut blob = vec![0u8; blob_len(bucket) as usize];
    for chunk in blob.chunks_mut(32) {
        let r = random32();
        chunk.copy_from_slice(&r[..chunk.len()]);
    }
    blob
}

struct Keys {
    lookup: [u8; 32],
    burn_token: [u8; 32],
}

fn meta(keys: &Keys, lifetime: &str, ttl: i64) -> Value {
    json!({
        "lookup_key": b64(&secret::credential_hash(&keys.lookup)),
        "burn_key": b64(&secret::credential_hash(&keys.burn_token)),
        "lifetime": lifetime,
        "ttl_seconds": ttl,
    })
}

fn keys() -> Keys {
    Keys {
        lookup: random32(),
        burn_token: random32(),
    }
}

fn assert_uniform_negative(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        reply.json(),
        json!({"error": {"code": "not_found", "message": "No secret matches."}})
    );
}

#[tokio::test]
async fn config_is_served() {
    let app = server("api-config").await;
    let reply = send(
        &app,
        Request::get("/api/v1/config")
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    assert_eq!(json["fragment_version"], 1);
    assert_eq!(json["padding"], json!({"mode": "padme", "min": 65536}));
    assert_eq!(json["max_ttl_secs"], 14 * 86400);
    assert_eq!(json["inline_max"], 2 * 1024 * 1024);
}

#[tokio::test]
async fn single_view_round_trip_with_raw_bytes() {
    let app = server("api-single").await;
    let keys = keys();
    let blob = raw_blob(65536);

    let reply = create(&app, meta(&keys, "single_view", 3600), &blob).await;
    assert_eq!(
        reply.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert!(reply.body.is_empty());

    // Same keys again (the client reused a seed): answered like a success, nothing written (D-21).
    let reply = create(&app, meta(&keys, "single_view", 3600), &blob).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert!(reply.body.is_empty());

    let reveal = post_json(
        &app,
        "/api/v1/secrets/reveal",
        json!({"lookup": b64(&keys.lookup)}),
    )
    .await;
    assert_eq!(reveal.status, StatusCode::OK);
    assert_eq!(
        reveal.body, blob,
        "stored and returned bytes must be identical"
    );
    assert_eq!(
        reveal.headers[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(reveal.headers[header::CACHE_CONTROL], "no-store");
    let token = reveal.headers[CLAIM_TOKEN_HEADER]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(token.len(), 43);

    // Consumed: a second reveal is the uniform negative, but the claimant can re-download.
    assert_uniform_negative(
        &post_json(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&keys.lookup)}),
        )
        .await,
    );
    let again = post_json(
        &app,
        "/api/v1/secrets/reveal",
        json!({"lookup": b64(&keys.lookup), "claim_token": token}),
    )
    .await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.body, blob);
    assert_uniform_negative(
        &post_json(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&keys.lookup), "claim_token": b64(&random32())}),
        )
        .await,
    );

    // Burn does not touch a claimed secret; confirm destroys it.
    assert_uniform_negative(
        &post_json(
            &app,
            "/api/v1/secrets/burn",
            json!({"burn_token": b64(&keys.burn_token)}),
        )
        .await,
    );
    let confirm = post_json(
        &app,
        "/api/v1/secrets/confirm",
        json!({"lookup": b64(&keys.lookup), "claim_token": token}),
    )
    .await;
    assert_eq!(confirm.status, StatusCode::NO_CONTENT);
    assert_uniform_negative(
        &post_json(
            &app,
            "/api/v1/secrets/confirm",
            json!({"lookup": b64(&keys.lookup), "claim_token": token}),
        )
        .await,
    );
    assert_uniform_negative(
        &post_json(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&keys.lookup), "claim_token": token}),
        )
        .await,
    );
}

#[tokio::test]
async fn ttl_round_trip_and_burn() {
    let app = server("api-ttl").await;
    let keys = keys();
    let blob = raw_blob(67584);
    assert_eq!(
        create(&app, meta(&keys, "ttl", 86400), &blob).await.status,
        StatusCode::CREATED
    );

    for _ in 0..3 {
        let reveal = post_json(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&keys.lookup)}),
        )
        .await;
        assert_eq!(reveal.status, StatusCode::OK);
        assert_eq!(reveal.body, blob);
        // A TTL read carries no claim token and nothing about remaining time (SPEC §5.2).
        assert!(reveal.headers.get(CLAIM_TOKEN_HEADER).is_none());
        assert!(
            reveal
                .headers
                .keys()
                .all(|k| !k.as_str().starts_with("x-shh-")),
            "{:?}",
            reveal.headers
        );
    }

    let burn = post_json(
        &app,
        "/api/v1/secrets/burn",
        json!({"burn_token": b64(&keys.burn_token)}),
    )
    .await;
    assert_eq!(burn.status, StatusCode::NO_CONTENT);
    assert_uniform_negative(
        &post_json(
            &app,
            "/api/v1/secrets/burn",
            json!({"burn_token": b64(&keys.burn_token)}),
        )
        .await,
    );
    assert_uniform_negative(
        &post_json(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&keys.lookup)}),
        )
        .await,
    );
}

#[tokio::test]
async fn report_is_uniform_and_removes() {
    let app = server("api-report").await;
    let keys = keys();
    assert_eq!(
        create(&app, meta(&keys, "ttl", 3600), &raw_blob(65536))
            .await
            .status,
        StatusCode::CREATED
    );

    let expected = json!({"status": "received"});
    for lookup in [
        b64(&random32()),
        "garbage".to_string(),
        b64(&keys.lookup),
        b64(&keys.lookup),
    ] {
        let reply = post_json(&app, "/api/v1/reports", json!({"lookup": lookup})).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json(), expected);
    }
    assert_uniform_negative(
        &post_json(
            &app,
            "/api/v1/secrets/reveal",
            json!({"lookup": b64(&keys.lookup)}),
        )
        .await,
    );
}

#[tokio::test]
async fn negatives_are_identical_whatever_the_cause() {
    let app = server("api-negatives").await;
    let bodies = [
        json!({"lookup": b64(&random32())}),
        json!({"lookup": "not-base64-at-all"}),
        json!({"lookup": ""}),
        json!({"lookup": b64(&random32()), "claim_token": "x"}),
    ];
    let mut seen = Vec::new();
    for body in bodies {
        let reply = post_json(&app, "/api/v1/secrets/reveal", body).await;
        assert_uniform_negative(&reply);
        seen.push(reply.body);
    }
    assert!(seen.windows(2).all(|w| w[0] == w[1]));
    assert_uniform_negative(
        &post_json(&app, "/api/v1/secrets/burn", json!({"burn_token": "nope"})).await,
    );
    assert_uniform_negative(
        &post_json(
            &app,
            "/api/v1/secrets/confirm",
            json!({"lookup": "a", "claim_token": "b"}),
        )
        .await,
    );
}

#[tokio::test]
async fn create_validates_input() {
    let app = server("api-validate").await;
    let keys = keys();

    let bad_len = create(&app, meta(&keys, "ttl", 3600), &raw_blob(65536)[..1000]).await;
    assert_eq!(bad_len.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_len.json()["error"]["code"], "invalid_blob_length");

    let bad_ttl = create(&app, meta(&keys, "ttl", 30 * 86400), &raw_blob(65536)).await;
    assert_eq!(bad_ttl.json()["error"]["code"], "invalid_ttl");

    let bad_lifetime = create(&app, meta(&keys, "forever", 3600), &raw_blob(65536)).await;
    assert_eq!(bad_lifetime.json()["error"]["code"], "invalid_lifetime");

    let mut short_key = meta(&keys, "ttl", 3600);
    short_key["lookup_key"] = json!("abc");
    assert_eq!(
        create(&app, short_key, &raw_blob(65536)).await.json()["error"]["code"],
        "invalid_lookup_key"
    );

    // Larger than the inline ceiling with no external tier configured.
    let big = create(&app, meta(&keys, "ttl", 3600), &raw_blob(4 * 1024 * 1024)).await;
    assert_eq!(big.status, StatusCode::PAYLOAD_TOO_LARGE);
}

// The full protocol end to end on the server: encrypt with the core crate, upload, reveal,
// decrypt with the seed. The server only ever handled opaque bytes.
#[tokio::test]
async fn encrypted_secret_round_trips_through_the_api() {
    let app = server("api-encrypted").await;
    let rand = Randomness::generate().unwrap();
    let payload = Payload {
        text: Some("db password: hunter2".into()),
        files: vec![File {
            name: "id_ed25519".into(),
            mime: "application/octet-stream".into(),
            bytes: vec![7; 3000],
        }],
    };
    let policy = PaddingPolicy::Padme { min: 65536 };
    let encrypted =
        secret::encrypt(&rand, &payload, Some("pw"), Argon2Params::MIN, &policy).unwrap();

    let meta = json!({
        "lookup_key": b64(&encrypted.lookup_key),
        "burn_key": b64(&encrypted.burn_key),
        "lifetime": "single_view",
        "ttl_seconds": 3600,
    });
    assert_eq!(
        create(&app, meta, &encrypted.blob).await.status,
        StatusCode::CREATED
    );

    // The receiving client derives the lookup value from the seed in the fragment.
    let seed = shhnote_core::fragment::Fragment::decode(&encrypted.fragment)
        .unwrap()
        .bytes;
    let reveal = post_json(
        &app,
        "/api/v1/secrets/reveal",
        json!({"lookup": b64(&secret::lookup(&seed))}),
    )
    .await;
    assert_eq!(reveal.status, StatusCode::OK);
    assert_eq!(
        secret::decrypt(&reveal.body, &seed, None),
        Err(shhnote_core::Error::PassphraseRequired)
    );
    assert_eq!(
        secret::decrypt(&reveal.body, &seed, Some("pw")).unwrap(),
        payload
    );

    // The burn link's token, hashed by the server, finds and destroys nothing now (claimed),
    // and the fragment shapes are what the pages will put after `#`.
    assert_eq!(encrypted.fragment.len(), 44);
    assert_eq!(encrypted.burn_fragment.len(), 44);
}

#[tokio::test]
async fn rate_limits_are_per_client_and_per_endpoint() {
    let app = server_with(
        "api-ratelimit",
        &[("rate_reveal_per_hour", "2"), ("rate_burn_per_hour", "1")],
    )
    .await;
    let body = json!({"lookup": b64(&random32())});

    // Two reveals pass, the third is refused, with a wait hint but no threshold.
    for _ in 0..2 {
        assert_uniform_negative(
            &post_json_from(&app, "/api/v1/secrets/reveal", body.clone(), "203.0.113.1").await,
        );
    }
    let limited = post_json_from(&app, "/api/v1/secrets/reveal", body.clone(), "203.0.113.1").await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.json()["error"]["code"], "rate_limited");
    assert!(limited.headers.contains_key(header::RETRY_AFTER));

    // Another client, and another endpoint for the same client, still work.
    assert_uniform_negative(
        &post_json_from(&app, "/api/v1/secrets/reveal", body.clone(), "203.0.113.2").await,
    );
    assert_uniform_negative(
        &post_json_from(
            &app,
            "/api/v1/secrets/burn",
            json!({"burn_token": b64(&random32())}),
            "203.0.113.1",
        )
        .await,
    );
    assert_eq!(
        post_json_from(
            &app,
            "/api/v1/secrets/burn",
            json!({"burn_token": b64(&random32())}),
            "203.0.113.1"
        )
        .await
        .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Config is never limited.
    let config = send(
        &app,
        Request::get("/api/v1/config")
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(config.status, StatusCode::OK);
}

// --- admin panel

const BOOTSTRAP: &str = "test-bootstrap-token-of-at-least-32-chars";

async fn admin_server(name: &str) -> (Router, Store) {
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
    let app = app::router(
        &config,
        ApiState::new(store.clone(), Settings::default(), &config, None),
    );
    (app, store)
}

async fn get_page(app: &Router, path: &str, cookie: &str) -> Reply {
    let req = Request::get(path)
        .header(header::HOST, "localhost")
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    send(app, req).await
}

async fn post_form(app: &Router, path: &str, cookie: &str, fields: &[(&str, &str)]) -> Reply {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
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

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn text(reply: &Reply) -> String {
    String::from_utf8(reply.body.clone()).unwrap()
}

fn between<'a>(haystack: &'a str, start: &str, end: &str) -> &'a str {
    let from = haystack.find(start).expect(start) + start.len();
    let to = haystack[from..].find(end).expect(end);
    &haystack[from..from + to]
}

fn location(reply: &Reply) -> &str {
    reply.headers[header::LOCATION].to_str().unwrap()
}

fn session_cookie(reply: &Reply) -> String {
    let set = reply.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Strict"),
        "{set}"
    );
    set.split(';').next().unwrap().to_string()
}

async fn login(app: &Router, credential: &str) -> Reply {
    post_form(app, "/en/admin/login", "", &[("credential", credential)]).await
}

fn csrf_of(page: &Reply) -> String {
    between(&text(page), "name=\"csrf\" value=\"", "\"").to_string()
}

// Creation redirects (SPEC §8); the key is shown once on the page the redirect points at.
async fn create_key(app: &Router, cookie: &str, csrf: &str, name: &str, scope: &str) -> String {
    let reply = post_form(
        app,
        "/en/admin/keys",
        cookie,
        &[("csrf", csrf), ("name", name), ("scope", scope)],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let page = get_page(app, location(&reply), cookie).await;
    assert_eq!(
        page.status,
        StatusCode::OK,
        "{} -> {:?}",
        location(&reply),
        page.headers.get(header::LOCATION)
    );
    between(&text(&page), "data-new-key-value>", "<").to_string()
}

#[tokio::test]
async fn admin_login_bootstrap_then_keys() {
    let (app, store) = admin_server("admin-login").await;

    // Anonymous visitors are sent to the login page; a wrong credential is refused.
    let reply = get_page(&app, "/en/admin", "").await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&reply), "/en/admin/login");
    assert_eq!(login(&app, "nope").await.status, StatusCode::UNAUTHORIZED);

    // The bootstrap token works on a fresh install.
    let reply = login(&app, BOOTSTRAP).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let cookie = session_cookie(&reply);
    let dashboard = get_page(&app, "/en/admin", &cookie).await;
    assert_eq!(dashboard.status, StatusCode::OK);
    assert!(text(&dashboard).contains("bootstrap token"));

    // Forms need the CSRF token bound to the session.
    let keys = get_page(&app, "/en/admin/keys", &cookie).await;
    let csrf = csrf_of(&keys);
    let forged = post_form(
        &app,
        "/en/admin/keys",
        &cookie,
        &[("csrf", "wrong"), ("name", "x"), ("scope", "user")],
    )
    .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);

    // Keys are shown once and stored hashed.
    let user_key = create_key(&app, &cookie, &csrf, "ci", "user").await;
    assert_eq!(user_key.len(), 43);
    let listed = store.list_api_keys().await.unwrap();
    assert_eq!(listed[0].name, "ci");
    assert_eq!(
        listed[0].key_hash,
        shhnote_core::secret::credential_hash(user_key.as_bytes())
    );
    assert!(!text(&get_page(&app, "/en/admin/keys", &cookie).await).contains(&user_key));

    // Once an admin key exists the bootstrap token and its sessions stop working.
    let admin_key = create_key(&app, &cookie, &csrf, "laptop", "admin").await;
    assert_eq!(
        get_page(&app, "/en/admin", &cookie).await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        login(&app, BOOTSTRAP).await.status,
        StatusCode::UNAUTHORIZED
    );
    let reply = login(&app, &admin_key).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let cookie = session_cookie(&reply);
    assert_eq!(
        get_page(&app, "/en/admin", &cookie).await.status,
        StatusCode::OK
    );
    // A user key cannot sign in.
    assert_eq!(
        login(&app, &user_key).await.status,
        StatusCode::UNAUTHORIZED
    );

    // Deleting the admin key ends its session.
    let csrf = csrf_of(&get_page(&app, "/en/admin/keys", &cookie).await);
    let hash_hex: String = shhnote_core::secret::credential_hash(admin_key.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let reply = post_form(
        &app,
        "/en/admin/keys/delete",
        &cookie,
        &[("csrf", &csrf), ("key_hash", &hash_hex)],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(
        get_page(&app, "/en/admin", &cookie).await.status,
        StatusCode::SEE_OTHER
    );
    // With no admin key left, the bootstrap token works again (what `reset-admin` relies on).
    assert_eq!(login(&app, BOOTSTRAP).await.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn admin_settings_apply_live_and_store_only_overrides() {
    let (app, store) = admin_server("admin-settings").await;
    let cookie = session_cookie(&login(&app, BOOTSTRAP).await);
    let csrf = csrf_of(&get_page(&app, "/en/admin/settings", &cookie).await);
    let user_key = create_key(&app, &cookie, &csrf, "ci", "user").await;

    // The form always sends every field; change two of them.
    let mut fields: Vec<(String, String)> = Settings::default()
        .as_strings()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    for (k, v) in &mut fields {
        match k.as_str() {
            "rate_reveal_per_hour" => *v = "1".to_string(),
            "site_name" => *v = "Vault".to_string(),
            _ => {}
        }
    }
    fields.push(("csrf".to_string(), csrf.clone()));
    let borrowed: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let reply = post_form(&app, "/en/admin/settings", &cookie, &borrowed).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", text(&reply));
    let page = get_page(&app, location(&reply), &cookie).await;
    assert!(text(&page).contains("Saved."));

    let overrides = store.setting_overrides().await.unwrap();
    assert_eq!(overrides.len(), 2, "{overrides:?}");
    assert_eq!(overrides["rate_reveal_per_hour"], "1");

    // The new limit applies without a restart: one reveal passes, the next is refused.
    let body = json!({"lookup": b64(&random32())});
    assert_uniform_negative(
        &post_json_from(&app, "/api/v1/secrets/reveal", body.clone(), "203.0.113.9").await,
    );
    assert_eq!(
        post_json_from(&app, "/api/v1/secrets/reveal", body.clone(), "203.0.113.9")
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // A user API key has its own, larger bucket.
    let req = Request::post("/api/v1/secrets/reveal")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {user_key}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_uniform_negative(&send(&app, req).await);
    assert!(
        store.list_api_keys().await.unwrap()[0]
            .last_used_on
            .is_some()
    );

    // The site name reaches the pages.
    assert!(text(&get_page(&app, "/en", "").await).contains("Vault"));

    // A bad value is rejected as a whole and nothing changes.
    for (k, v) in &mut fields {
        if k == "max_ttl_secs" {
            *v = "not a number".to_string();
        }
    }
    let borrowed: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let reply = post_form(&app, "/en/admin/settings", &cookie, &borrowed).await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(store.setting_overrides().await.unwrap().len(), 2);

    // Private instance: creating needs a user key, everything else stays open.
    for (k, v) in &mut fields {
        match k.as_str() {
            "max_ttl_secs" => *v = Settings::default().max_ttl_secs.to_string(),
            "require_api_key_for_create" => *v = "true".to_string(),
            _ => {}
        }
    }
    let borrowed: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        post_form(&app, "/en/admin/settings", &cookie, &borrowed)
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    let refused = create(
        &app,
        json!({"ttl_seconds": 3600, "single_view": true, "burn_token": b64(&random32())}),
        &[0u8; 16],
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.json()["error"]["code"], "api_key_required");
    assert_uniform_negative(
        &post_json_from(
            &app,
            "/api/v1/secrets/burn",
            json!({"burn_token": b64(&random32())}),
            "203.0.113.9",
        )
        .await,
    );
}

// --- external storage tier

async fn external_server(name: &str, tier: &[(&str, &str)]) -> (Router, Store, Arc<Blobs>) {
    external_server_with(name, tier, &[]).await
}

async fn external_server_with(
    name: &str,
    tier: &[(&str, &str)],
    overrides: &[(&str, &str)],
) -> (Router, Store, Arc<Blobs>) {
    let mut vars: HashMap<String, String> = [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
        // The smallest inline ceiling, so a 128 KiB bucket is external.
        ("SHH_INLINE_MAX", "65536"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    vars.extend(tier.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let config = Config::from_vars(&vars).unwrap();
    let blobs = Arc::new(
        Blobs::open(config.storage.external.as_ref().unwrap())
            .await
            .unwrap(),
    );
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let overrides: HashMap<String, String> = overrides
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (settings, warnings) = Settings::with_overrides(&overrides, AppEnv::Local);
    assert!(warnings.is_empty(), "{warnings:?}");
    let app = app::router(
        &config,
        ApiState::new(store.clone(), settings, &config, Some(blobs.clone())),
    );
    (app, store, blobs)
}

async fn reveal(app: &Router, keys: &Keys) -> Reply {
    post_json(
        app,
        "/api/v1/secrets/reveal",
        json!({"lookup": b64(&keys.lookup)}),
    )
    .await
}

async fn burn(app: &Router, keys: &Keys) -> Reply {
    post_json(
        app,
        "/api/v1/secrets/burn",
        json!({"burn_token": b64(&keys.burn_token)}),
    )
    .await
}

// The same lifecycle on every tier: store, stream back, refuse past the ceiling, park on
// burn, scrub. The ceiling in the config is 300 000 bytes, room for two 128 KiB objects.
async fn external_tier_flow(app: &Router, store: &Store, blobs: &Blobs) {
    const LARGE: u64 = 131_072;
    let first = keys();
    let blob = raw_blob(LARGE);
    assert_eq!(
        create(app, meta(&first, "ttl", 86400), &blob).await.status,
        StatusCode::CREATED
    );
    assert_eq!(store.external_bytes().await.unwrap(), blob_len(LARGE));

    let reply = reveal(app, &first).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.headers[header::CONTENT_LENGTH],
        blob.len().to_string()
    );
    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(reply.body, blob);

    // A large blob of the wrong length is refused after spooling and leaves nothing behind.
    let mut odd = raw_blob(LARGE);
    odd.push(0);
    let reply = create(app, meta(&keys(), "ttl", 86400), &odd).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"]["code"], "invalid_blob_length");
    assert_eq!(store.external_bytes().await.unwrap(), blob_len(LARGE));

    // Second one fits, third would cross the ceiling; small secrets are unaffected.
    let second = keys();
    assert_eq!(
        create(app, meta(&second, "ttl", 86400), &raw_blob(LARGE))
            .await
            .status,
        StatusCode::CREATED
    );
    let reply = create(app, meta(&keys(), "ttl", 86400), &raw_blob(LARGE)).await;
    assert_eq!(reply.status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(reply.json()["error"]["code"], "storage_full");
    let small = keys();
    assert_eq!(
        create(app, meta(&small, "ttl", 86400), &raw_blob(65536))
            .await
            .status,
        StatusCode::CREATED
    );
    assert_eq!(store.external_bytes().await.unwrap(), 2 * blob_len(LARGE));

    // Burning parks the row: the object still counts until the scrubber confirms it is gone.
    assert_eq!(burn(app, &first).await.status, StatusCode::NO_CONTENT);
    assert_uniform_negative(&reveal(app, &first).await);
    assert_eq!(store.external_bytes().await.unwrap(), 2 * blob_len(LARGE));
    scheduler::scrub(store, Some(blobs)).await;
    assert_eq!(store.external_bytes().await.unwrap(), blob_len(LARGE));
    assert!(store.pending_deletes().await.unwrap().is_empty());

    // Room again.
    assert_eq!(
        create(app, meta(&keys(), "ttl", 86400), &raw_blob(LARGE))
            .await
            .status,
        StatusCode::CREATED
    );
    assert_eq!(reveal(app, &second).await.status, StatusCode::OK);
    assert_eq!(reveal(app, &small).await.status, StatusCode::OK);

    // Leave the tier empty.
    assert_eq!(burn(app, &second).await.status, StatusCode::NO_CONTENT);
    assert_eq!(burn(app, &small).await.status, StatusCode::NO_CONTENT);
    let third_burn = store.sweep(now() + 90_000).await.unwrap();
    assert_eq!(third_burn.expired, 1);
    scheduler::scrub(store, Some(blobs)).await;
    assert_eq!(store.external_bytes().await.unwrap(), 0);
}

#[tokio::test]
async fn local_tier_round_trips_and_scrubs() {
    let root = std::env::temp_dir().join("shhnote-api-local-tier");
    let _ = tokio::fs::remove_dir_all(&root).await;
    let (app, store, blobs) = external_server(
        "api-local-tier",
        &[
            ("SHH_STORAGE", "local"),
            ("SHH_LOCAL_PATH", root.to_str().unwrap()),
            ("SHH_LOCAL_MAX_TOTAL_BYTES", "300000"),
        ],
    )
    .await;
    external_tier_flow(&app, &store, &blobs).await;
    for dir in ["blobs", "tmp"] {
        let mut entries = tokio::fs::read_dir(root.join(dir)).await.unwrap();
        assert!(
            entries.next_entry().await.unwrap().is_none(),
            "{dir} not empty"
        );
    }
    let _ = tokio::fs::remove_dir_all(&root).await;
}

// Runs only against a real bucket: set SHH_TEST_S3_ENDPOINT, _BUCKET, _REGION,
// _ACCESS_KEY_ID and _SECRET_ACCESS_KEY (MinIO or any S3-compatible service).
#[tokio::test]
async fn s3_tier_round_trips_and_scrubs() {
    let names = [
        "ENDPOINT",
        "BUCKET",
        "REGION",
        "ACCESS_KEY_ID",
        "SECRET_ACCESS_KEY",
    ];
    let values: Vec<Option<String>> = names
        .iter()
        .map(|n| std::env::var(format!("SHH_TEST_S3_{n}")).ok())
        .collect();
    if values.iter().any(Option::is_none) {
        eprintln!("skipping: SHH_TEST_S3_* not set");
        return;
    }
    let mut tier: Vec<(&str, &str)> = names
        .iter()
        .zip(&values)
        .map(|(n, v)| {
            let key: &'static str = Box::leak(format!("SHH_S3_{n}").into_boxed_str());
            (key, v.as_deref().unwrap())
        })
        .collect();
    tier.push(("SHH_STORAGE", "s3"));
    tier.push(("SHH_S3_MAX_TOTAL_BYTES", "300000"));
    let (app, store, blobs) = external_server("api-s3-tier", &tier).await;
    external_tier_flow(&app, &store, &blobs).await;
}

#[tokio::test]
async fn inline_disabled_sends_every_blob_external() {
    let root = std::env::temp_dir().join("shhnote-api-inline-off");
    let _ = tokio::fs::remove_dir_all(&root).await;
    let (app, store, blobs) = external_server_with(
        "api-inline-off",
        &[
            ("SHH_STORAGE", "local"),
            ("SHH_LOCAL_PATH", root.to_str().unwrap()),
            ("SHH_LOCAL_MAX_TOTAL_BYTES", "300000"),
        ],
        &[("inline_enabled", "false")],
    )
    .await;
    // Far below the inline ceiling, yet it lands on disk.
    let keys = keys();
    let blob = raw_blob(65536);
    assert_eq!(
        create(&app, meta(&keys, "ttl", 86400), &blob).await.status,
        StatusCode::CREATED
    );
    assert_eq!(store.external_bytes().await.unwrap(), blob_len(65536));
    let reply = reveal(&app, &keys).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, blob);
    assert_eq!(burn(&app, &keys).await.status, StatusCode::NO_CONTENT);
    scheduler::scrub(&store, Some(&blobs)).await;
    assert_eq!(store.external_bytes().await.unwrap(), 0);
    let _ = tokio::fs::remove_dir_all(&root).await;
}

#[tokio::test]
async fn files_disabled_caps_blobs_at_text_size() {
    let app = server_with("api-files-off", &[("files_enabled", "false")]).await;
    // A text-sized blob is fine; a megabyte can only be a file.
    assert_eq!(
        create(&app, meta(&keys(), "ttl", 86400), &raw_blob(65536))
            .await
            .status,
        StatusCode::CREATED
    );
    let reply = create(&app, meta(&keys(), "ttl", 86400), &raw_blob(1_048_576)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"]["code"], "files_disabled");
}

#[tokio::test]
async fn report_page_region_selector_and_settings_tabs_render() {
    let app = server_with(
        "web-report-regions",
        &[(
            "regions",
            r#"[{"code":"eu","name":"Europe","url":"http://localhost:3000"},{"code":"us","name":"United States","url":"https://us.example.test"}]"#,
        )],
    )
    .await;
    let page = get_page(&app, "/en/report", "").await;
    assert_eq!(page.status, StatusCode::OK);
    let html = text(&page);
    assert!(html.contains("data-report-page") && html.contains("data-report-form"));

    // This instance is "Europe"; the other region is a plain link to its own origin.
    let home = text(&get_page(&app, "/en", "").await);
    assert!(home.contains("region-select"));
    assert!(home.contains("<span>Europe</span>"), "{home}");
    assert!(home.contains(r#"href="https://us.example.test""#));
    assert!(
        !text(&get_page(&server("web-no-regions").await, "/en", "").await)
            .contains("region-select")
    );

    // Footer links to the report page on every page.
    assert!(home.contains(r#"href="/en/report""#));
}

#[tokio::test]
async fn settings_page_groups_every_setting_into_tabs() {
    let (app, _store) = admin_server("admin-settings-tabs").await;
    let cookie = session_cookie(&login(&app, BOOTSTRAP).await);
    let html = text(&get_page(&app, "/en/admin/settings", &cookie).await);
    for group in ["general", "secrets", "storage", "limits", "stats"] {
        assert!(html.contains(&format!(r#"id="group-{group}""#)), "{group}");
    }
    assert!(!html.contains(r#"id="group-other""#));
    for key in Settings::default().as_strings().keys() {
        assert!(html.contains(&format!(r#"name="{key}""#)), "{key} missing");
    }
}

#[tokio::test]
async fn markdown_pages_render_with_instance_urls() {
    let app = server("web-docs").await;
    for path in [
        "/en/acceptable-use",
        "/de/acceptable-use",
        "/en/docs",
        "/de/docs",
    ] {
        let page = get_page(&app, path, "").await;
        assert_eq!(page.status, StatusCode::OK, "{path}");
        let html = text(&page);
        assert!(
            !html.contains("{{") && !html.contains("%7B%7B"),
            "{path} has an unreplaced placeholder"
        );
    }
    let api = text(&get_page(&app, "/en/docs", "").await);
    assert!(api.contains("http://localhost:3000/api/v1"), "{api}");
    assert!(api.contains(r#"href="http://localhost:3000/en/how-it-works#technical""#));
}

// --- admin API

async fn admin_api(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> Reply {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        req = req.header(header::CONTENT_TYPE, "application/json");
    }
    let req = req
        .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
        .unwrap();
    send(app, req).await
}

#[tokio::test]
async fn admin_api_bootstraps_keys_settings_and_stats() {
    let (app, store) = admin_server("admin-api").await;

    // No key, wrong key: 401 and nothing else.
    let reply = send(
        &app,
        Request::get("/api/v1/admin/stats")
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"]["code"], "unauthorized");
    assert_eq!(
        admin_api(&app, "GET", "/api/v1/admin/stats", "nope", None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );

    // The bootstrap token works on a fresh install and can mint the first admin key.
    let stats = admin_api(&app, "GET", "/api/v1/admin/stats?days=7", BOOTSTRAP, None).await;
    assert_eq!(stats.status, StatusCode::OK, "{}", text(&stats));
    assert_eq!(stats.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(stats.json()["active"], 0);
    let created = admin_api(
        &app,
        "POST",
        "/api/v1/admin/keys",
        BOOTSTRAP,
        Some(json!({"name": "automation", "scope": "admin"})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", text(&created));
    let admin_key = created.json()["key"].as_str().unwrap().to_string();
    let admin_id = created.json()["id"].as_str().unwrap().to_string();
    assert_eq!(admin_key.len(), 43);

    // From now on the bootstrap token is dead; the key is live.
    assert_eq!(
        admin_api(&app, "GET", "/api/v1/admin/stats", BOOTSTRAP, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let keys = admin_api(&app, "GET", "/api/v1/admin/keys", &admin_key, None).await;
    assert_eq!(keys.status, StatusCode::OK);
    assert_eq!(keys.json()["keys"][0]["id"], admin_id);
    assert!(keys.json()["keys"][0]["last_used_on"].is_number());
    assert!(
        !text(&keys).contains(&admin_key),
        "keys are never listed in clear"
    );

    // A user key cannot administer.
    let user = admin_api(
        &app,
        "POST",
        "/api/v1/admin/keys",
        &admin_key,
        Some(json!({"name": "ci", "scope": "user"})),
    )
    .await;
    let user_key = user.json()["key"].as_str().unwrap().to_string();
    assert_eq!(
        admin_api(&app, "GET", "/api/v1/admin/keys", &user_key, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        admin_api(
            &app,
            "POST",
            "/api/v1/admin/keys",
            &admin_key,
            Some(json!({"name": "", "scope": "admin"}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );

    // Settings: partial patch, typed JSON values, live effect, overrides only.
    let before = admin_api(&app, "GET", "/api/v1/admin/settings", &admin_key, None).await;
    assert_eq!(before.json()["overridden"], json!([]));
    let patched = admin_api(
        &app,
        "PATCH",
        "/api/v1/admin/settings",
        &admin_key,
        Some(json!({"site_name": "Vault", "rate_reveal_per_hour": 1, "ttl_presets": [900, 3600], "files_enabled": false})),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", text(&patched));
    assert_eq!(patched.json()["values"]["ttl_presets"], "900,3600");
    assert_eq!(patched.json()["overridden"].as_array().unwrap().len(), 4);
    assert_eq!(store.setting_overrides().await.unwrap().len(), 4);
    let body = json!({"lookup": b64(&random32())});
    assert_uniform_negative(
        &post_json_from(&app, "/api/v1/secrets/reveal", body.clone(), "203.0.113.77").await,
    );
    assert_eq!(
        post_json_from(&app, "/api/v1/secrets/reveal", body, "203.0.113.77")
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // null resets a key; a bad value or unknown key changes nothing.
    let reset = admin_api(
        &app,
        "PATCH",
        "/api/v1/admin/settings",
        &admin_key,
        Some(json!({"site_name": null})),
    )
    .await;
    assert_eq!(reset.json()["values"]["site_name"], "shhnote");
    let bad = admin_api(
        &app,
        "PATCH",
        "/api/v1/admin/settings",
        &admin_key,
        Some(json!({"max_ttl_secs": "soon", "nonsense": 1})),
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(bad.json()["error"]["code"], "invalid_settings");
    assert_eq!(bad.json()["details"].as_array().unwrap().len(), 1);
    assert_eq!(store.setting_overrides().await.unwrap().len(), 3);

    // There is no reports ledger (D-19); reports are a daily counter in the stats.
    let stats = admin_api(&app, "GET", "/api/v1/admin/stats", &admin_key, None).await;
    assert_eq!(stats.json()["reports"], 0);
    assert!(
        admin_api(&app, "GET", "/api/v1/admin/reports", &admin_key, None)
            .await
            .status
            .is_client_error()
    );
    // Deleting the key in use ends access.
    let gone = admin_api(
        &app,
        "POST",
        "/api/v1/admin/keys/delete",
        &admin_key,
        Some(json!({"id": admin_id})),
    )
    .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT);
    assert_eq!(
        admin_api(&app, "GET", "/api/v1/admin/keys", &admin_key, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // With no admin key left, the bootstrap token works again.
    assert_eq!(
        admin_api(&app, "GET", "/api/v1/admin/keys", BOOTSTRAP, None)
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn admin_api_guessing_is_rate_limited() {
    let (app, _store) = admin_server("admin-api-guess").await;
    let limit = Settings::default().rate_limits.login_per_hour;
    for _ in 0..limit {
        assert_eq!(
            admin_api(&app, "GET", "/api/v1/admin/stats", "guess", None)
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        admin_api(&app, "GET", "/api/v1/admin/stats", "guess", None)
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

async fn locale_server(name: &str, extra: &[(&str, &str)]) -> Router {
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
    let config = Config::from_vars(&vars).unwrap();
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    app::router(
        &config,
        ApiState::new(store, Settings::default(), &config, None),
    )
}

async fn redirect_for(app: &Router, accept_language: &str) -> Reply {
    let req = Request::get("/")
        .header(header::HOST, "localhost")
        .header(header::ACCEPT_LANGUAGE, accept_language)
        .body(Body::empty())
        .unwrap();
    send(app, req).await
}

#[tokio::test]
async fn default_locale_is_where_unmatched_visitors_land() {
    let app = locale_server(
        "web-locales-default",
        &[("SHH_LOCALES", "en,de"), ("SHH_DEFAULT_LOCALE", "de")],
    )
    .await;
    let reply = redirect_for(&app, "fr-FR,fr;q=0.9").await;
    assert_eq!(reply.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(location(&reply), "/de");
    assert_eq!(location(&redirect_for(&app, "en-US").await), "/en");
    assert!(reply.headers.contains_key("permissions-policy"));
}

#[tokio::test]
async fn only_offered_locales_exist_and_old_links_redirect() {
    let app = locale_server("web-locales-de-only", &[("SHH_LOCALES", "de")]).await;
    let home = get_page(&app, "/de", "").await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(
        !text(&home).contains(r#"href="/en""#),
        "menu offers a language that is not there"
    );
    assert_eq!(location(&redirect_for(&app, "en-US").await), "/de");
    // A link made under a language this instance does not offer keeps working.
    let reply = get_page(&app, "/en/terms", "").await;
    assert_eq!(reply.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(location(&reply), "/de/terms");
}

#[tokio::test]
async fn health_reports_the_database() {
    let app = server("api-health").await;
    let reply = send(
        &app,
        Request::get("/api/v1/health")
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json(), json!({"status": "ok"}));
    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
}
