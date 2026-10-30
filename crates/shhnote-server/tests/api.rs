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
    container::{File, Payload},
    kdf::Argon2Params,
    padding::{PaddingPolicy, blob_len},
    secret::{self, Randomness},
    settings::Settings,
};
use shhnote_server::{
    api::{ApiState, CLAIM_TOKEN_HEADER, EXPIRES_IN_HEADER},
    app,
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
    let (settings, warnings) = Settings::with_overrides(&overrides);
    assert!(warnings.is_empty(), "{warnings:?}");
    app::router(&config, ApiState::new(store, settings, &config))
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

    // Same keys again: refused, the client reused a seed.
    let reply = create(&app, meta(&keys, "single_view", 3600), &blob).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

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
    assert!(reveal.headers.get(EXPIRES_IN_HEADER).is_none());
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
        assert_eq!(reveal.headers[EXPIRES_IN_HEADER], "24");
        assert!(reveal.headers.get(CLAIM_TOKEN_HEADER).is_none());
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
