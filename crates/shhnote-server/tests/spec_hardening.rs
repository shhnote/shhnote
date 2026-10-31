// Regression tests from the security review (docs/security-review/findings/SUMMARY.md) for
// the rate limiter's keying, the proxy configuration, credential decoding and file modes on
// the local tier. Ignored tests are waiting for the step that fixes their finding; un-ignore
// them with the fix.

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use shhnote_core::{
    config::Config,
    padding::blob_len,
    secret,
    settings::{RateLimits, Settings, SettingsCell},
};
use shhnote_server::{
    api::ApiState,
    app,
    ratelimit::{Endpoint, RateLimiter},
    storage::Blobs,
};
use shhnote_store::{Store, sqlite_path_for_tests};
use tower::ServiceExt;

const BOUNDARY: &str = "----spec-hardening";
const BOOTSTRAP: &str = "spec-hardening-bootstrap-token-0123456789";

fn vars(extra: &[(&str, &str)]) -> HashMap<String, String> {
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

async fn server(name: &str) -> Router {
    let config = Config::from_vars(&vars(&[])).unwrap();
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    app::router(
        &config,
        ApiState::new(store, Settings::default(), &config, None),
    )
}

async fn status(app: &Router, req: Request<Body>) -> StatusCode {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let _ = axum::body::to_bytes(res.into_body(), usize::MAX).await;
    status
}

fn json_req(path: &str, body: &str) -> Request<Body> {
    Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn multipart(meta: &str, blob: &[u8]) -> Request<Body> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"meta\"\r\n\r\n{meta}\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"blob\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(blob);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    Request::post("/api/v1/secrets")
        .header(header::HOST, "localhost")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(body))
        .unwrap()
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn limiter(per_hour: u32, proxies: &[&str]) -> RateLimiter {
    let settings = Settings {
        rate_limits: RateLimits {
            create_per_hour: per_hour,
            ..RateLimits::default()
        },
        ..Settings::default()
    };
    RateLimiter::new(
        Arc::new(SettingsCell::new(settings)),
        proxies.iter().map(|p| p.parse().unwrap()).collect(),
    )
}

// SPEC §4: peers are canonicalised, so IPv4 clients behind a dual-stack listener keep their
// own buckets and a trusted IPv4 proxy is recognised in mapped form.
#[test]
#[ignore = "S-13"]
fn spec_ipv4_mapped_peers_are_canonicalised() {
    let limiter = limiter(1, &["10.0.0.1"]);
    let a: IpAddr = "::ffff:198.51.100.1".parse().unwrap();
    let b: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
    assert_eq!(limiter.check(Endpoint::Create, a), Ok(()));
    assert_eq!(
        limiter.check(Endpoint::Create, b),
        Ok(()),
        "an unrelated IPv4 client shares no bucket with the first"
    );
    assert!(limiter.check(Endpoint::Create, a).is_err());

    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
    let mapped_proxy: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    let client: IpAddr = "198.51.100.7".parse().unwrap();
    assert_eq!(
        limiter.client_ip(mapped_proxy, &headers),
        client,
        "the trusted proxy is recognised in mapped form"
    );
}

// SPEC §4: a full bucket table evicts individual subjects; it is never cleared by load.
#[test]
#[ignore = "S-28"]
fn spec_bucket_flood_does_not_reset_other_limits() {
    let limiter = limiter(1, &[]);
    let victim: IpAddr = "203.0.113.5".parse().unwrap();
    assert_eq!(limiter.check(Endpoint::Create, victim), Ok(()));
    assert!(limiter.check(Endpoint::Create, victim).is_err());
    // 200 002 distinct /64s inside 2001:db8::/32.
    for i in 0u32..=200_001 {
        let ip = std::net::Ipv6Addr::new(
            0x2001,
            0x0db8,
            u16::try_from(i >> 16).unwrap(),
            u16::try_from(i & 0xffff).unwrap(),
            0,
            0,
            0,
            1,
        );
        let _ = limiter.check(Endpoint::Create, IpAddr::V6(ip));
    }
    assert!(
        limiter.check(Endpoint::Create, victim).is_err(),
        "the exhausted client is fresh again"
    );
}

// SPEC §7.1: proxy ranges that together trust everyone are refused like `/0` is.
#[test]
#[ignore = "S-34"]
fn spec_trusted_proxies_refuse_trust_everyone_equivalents() {
    for list in [
        "1.0.0.0/1,128.0.0.0/1",
        "::ffff:0:0/96",
        "::1/1,8000::/1",
        "0.0.0.1/1,128.0.0.0/1",
        "0.0.0.0",
        "::",
        "10.0.0.0/0",
        "0.0.0.0/8",
    ] {
        assert!(
            Config::from_vars(&vars(&[("SHH_TRUSTED_PROXIES", list)])).is_err(),
            "{list} is accepted"
        );
    }
    for list in [
        "10.0.0.1",
        "10.0.0.0/8",
        "fd00::/32",
        "192.0.2.0/24,2001:db8::/48",
    ] {
        assert!(
            Config::from_vars(&vars(&[("SHH_TRUSTED_PROXIES", list)])).is_ok(),
            "{list} is refused"
        );
    }
}

// SPEC §6.1: spool files are 0600 in a 0700 directory, and the blob keeps that mode.
#[cfg(unix)]
#[tokio::test]
#[ignore = "S-33"]
async fn spec_blob_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("spec-hardening-perms-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let config = Config::from_vars(&vars(&[
        ("SHH_INLINE_MAX", "65536"),
        ("SHH_STORAGE", "local"),
        ("SHH_LOCAL_PATH", root.to_str().unwrap()),
        ("SHH_LOCAL_MAX_TOTAL_BYTES", "100000000"),
    ]))
    .unwrap();
    let blobs = Blobs::open(config.storage.external.as_ref().unwrap())
        .await
        .unwrap();
    let mut spool = blobs.spool().await.unwrap();
    spool.write(b"ciphertext").await.unwrap();
    let key = Blobs::new_key().unwrap();
    blobs
        .put(&key, spool.finish().await.unwrap())
        .await
        .unwrap();
    let mode = std::fs::metadata(root.join(&key))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let dir_mode = std::fs::metadata(root.join("blobs"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "blob file mode {mode:o}");
    assert_eq!(dir_mode, 0o700, "blobs dir mode {dir_mode:o}");
    let _ = std::fs::remove_dir_all(&root);
}

// SPEC §2.12: credentials are exactly 43 canonical base64url characters. A non-canonical
// spelling of a real burn token (non-zero trailing bits), padding or whitespace never matches.
#[tokio::test]
async fn spec_credential_decoding_is_strict() {
    let app = server("spec-hardening-b64").await;
    let (lookup, burn) = (random32(), random32());
    let meta = json!({
        "lookup_key": b64(&secret::credential_hash(&lookup)),
        "burn_key": b64(&secret::credential_hash(&burn)),
        "lifetime": "ttl",
        "ttl_seconds": 3600,
    })
    .to_string();
    let blob = vec![7u8; usize::try_from(blob_len(65536)).unwrap()];
    assert_eq!(
        status(&app, multipart(&meta, &blob)).await,
        StatusCode::CREATED
    );

    let canonical = b64(&burn);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = canonical.as_bytes()[42];
    let index = alphabet.iter().position(|&c| c == last).unwrap();
    let non_canonical = format!("{}{}", &canonical[..42], char::from(alphabet[index | 0b01]));
    assert_ne!(non_canonical, canonical);
    for token in [
        non_canonical,
        format!("{canonical}="),
        format!(" {}", &canonical[..42]),
        format!("{}\n", &canonical[..42]),
        canonical.replace(['-', '_'], "+"),
    ] {
        if token == canonical {
            continue;
        }
        let body = json!({ "burn_token": token }).to_string();
        assert_eq!(
            status(&app, json_req("/api/v1/secrets/burn", &body)).await,
            StatusCode::NOT_FOUND,
            "{token:?}"
        );
    }
    let body = json!({ "burn_token": canonical }).to_string();
    assert_eq!(
        status(&app, json_req("/api/v1/secrets/burn", &body)).await,
        StatusCode::NO_CONTENT,
        "the canonical token still works"
    );
}

// SPEC §7.1: the environment rules.
#[test]
fn spec_config_rules_hold() {
    let reject = |extra: &[(&str, &str)]| Config::from_vars(&vars(extra)).is_err();
    assert!(reject(&[("SHH_TYPO", "1")]));
    assert!(reject(&[("SHH_ENV", "production"), ("SHH_DEBUG", "true")]));
    assert!(reject(&[("SHH_LOCAL_PATH", "x")]));
    assert!(reject(&[("SHH_S3_BUCKET", "x")]));
    assert!(reject(&[("SHH_EXTERNAL_MAX_OBJECT", "99999999")]));
    assert!(reject(&[
        ("SHH_STORAGE", "local"),
        ("SHH_LOCAL_MAX_TOTAL_BYTES", "1"),
        ("SHH_S3_REGION", "x"),
    ]));
    assert!(reject(&[("SHH_SECRET_KEY", "short")]));
    // Debug output of the config never shows credentials.
    let config = Config::from_vars(&vars(&[("SHH_ADMIN_TOKEN", BOOTSTRAP)])).unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains(BOOTSTRAP) && !debug.contains(&"s".repeat(44)));
}
