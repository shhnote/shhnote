// Security review, round 2, pass 1 (metadata and PII leakage): checks on the surfaces added
// since round 1 (docs/security-review/round-2/pass1.md). A test named `..._reproduces_...`
// passes while its finding is present and should be inverted or removed with the fix; every
// other test asserts a property that holds today.
use std::{collections::HashMap, net::SocketAddr, time::Instant};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use shhnote_core::{
    config::{AppEnv, Config},
    expiry,
    padding::blob_len,
    secret::credential_hash,
    settings::Settings,
};
use shhnote_server::{
    api::{ApiState, now},
    app,
};
use shhnote_store::{Lifetime, NewSecret, Scope, Store, sqlite_path_for_tests, sqlite_test_dir};
use tower::ServiceExt;

const ADMIN_KEY: &str = "r2p1-admin-key-of-at-least-32-characters-ok";
const BOOTSTRAP: &str = "r2p1-bootstrap-token-of-at-least-32-chars-x";
const BUCKET: u64 = 65_536;

const UNLIMITED: &[(&str, &str)] = &[
    ("rate_create_per_hour", "0"),
    ("rate_reveal_per_hour", "0"),
    ("rate_confirm_per_hour", "0"),
    ("rate_burn_per_hour", "0"),
    ("rate_report_per_hour", "0"),
];

struct Srv {
    app: Router,
    store: Store,
}

// `configured`: an admin key, a site name and a contact address (D-29); otherwise none.
async fn server(
    name: &str,
    env: &[(&str, &str)],
    overrides: &[(&str, &str)],
    configured: bool,
) -> Srv {
    let mut vars: HashMap<String, String> = [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in env {
        vars.insert(k.to_string(), v.to_string());
    }
    let config = Config::from_vars(&vars).unwrap();
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let mut overrides: HashMap<String, String> = overrides
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
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
        ApiState::new(store.clone(), settings, &config, None),
    );
    Srv { app, store }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
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
    let addr: SocketAddr = format!("{ip}:40000").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

fn get_req(host: &str, path: &str) -> Request<Body> {
    with_peer(
        Request::get(path)
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap(),
        "198.51.100.7",
    )
}

fn post_json(path: &str, body: &Value, auth: Option<&str>) -> Request<Body> {
    let mut b = Request::post(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(key) = auth {
        b = b.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    with_peer(
        b.body(Body::from(body.to_string())).unwrap(),
        "198.51.100.8",
    )
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

async fn plant(store: &Store, lifetime: Lifetime, expires_at: i64) -> [u8; 32] {
    let lookup = random32();
    let ok = store
        .create(
            &NewSecret {
                lookup_key: credential_hash(&lookup),
                burn_key: credential_hash(&random32()),
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
    lookup
}

fn header_lines(h: &HeaderMap) -> Vec<String> {
    let mut v: Vec<String> = h
        .iter()
        .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("?")))
        .collect();
    v.sort();
    v
}

fn assert_same(name: &str, a: &Reply, b: &Reply) {
    assert_eq!(a.status, b.status, "{name}: status");
    assert_eq!(a.body, b.body, "{name}: body");
    assert_eq!(
        header_lines(&a.headers),
        header_lines(&b.headers),
        "{name}: headers"
    );
}

fn percentile(v: &mut [u128], q: f64) -> u128 {
    v.sort_unstable();
    v[((v.len() - 1) as f64 * q) as usize]
}

fn describe(name: &str, v: &mut [u128]) -> String {
    format!(
        "{name:<34} p10={}us p50={}us p90={}us",
        percentile(v, 0.1),
        percentile(v, 0.5),
        percentile(v, 0.9)
    )
}

// D-29 / SPEC §4: while setup is unmet the gate answers before any route, so a request for a
// secret that exists and one for a secret that never existed get byte-identical 503s, the
// row is not touched, and the setup page is the same whether or not a bootstrap token is
// configured. `/health` says only `configured: false`.
#[tokio::test]
async fn spec_r2_pass1_setup_gate_is_uniform_and_touches_no_row() {
    let with_token = server(
        "r2p1-gate-token",
        &[("SHH_ADMIN_TOKEN", BOOTSTRAP)],
        &[],
        false,
    )
    .await;
    let without_token = server("r2p1-gate-notoken", &[], &[], false).await;

    // A row planted straight into the store, as a dump holder might find one.
    let t = now();
    let lookup = plant(&with_token.store, Lifetime::SingleView, t + 3600).await;
    let planted = send(
        &with_token.app,
        post_json(
            "/api/v1/secrets/reveal",
            &json!({"lookup": b64(&lookup)}),
            None,
        ),
    )
    .await;
    let unknown = send(
        &with_token.app,
        post_json(
            "/api/v1/secrets/reveal",
            &json!({"lookup": b64(&random32())}),
            None,
        ),
    )
    .await;
    assert_eq!(planted.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_same("reveal planted vs unknown", &planted, &unknown);
    assert!(planted.text().contains(r#""code":"not_configured""#));
    for (path, body) in [
        (
            "/api/v1/secrets/confirm",
            json!({"lookup": b64(&lookup), "claim_token": "x"}),
        ),
        (
            "/api/v1/secrets/burn",
            json!({"burn_token": b64(&random32())}),
        ),
        ("/api/v1/reports", json!({"lookup": b64(&lookup)})),
        ("/api/v1/secrets", json!({})),
    ] {
        let r = send(&with_token.app, post_json(path, &body, None)).await;
        assert_same(path, &r, &unknown);
    }
    // GET endpoints alike. (The gate runs inside axum's routing, so a request whose method
    // does not match the route gets the route's `Allow` header on its 503: route shapes are
    // public, nothing about a secret or the instance's state.)
    let config = send(&with_token.app, get_req("localhost", "/api/v1/config")).await;
    let info = send(&with_token.app, get_req("localhost", "/api/v1")).await;
    assert_same("GET /config vs GET /", &config, &info);
    assert_eq!(config.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(config.body, unknown.body);
    // The row is exactly as planted: still claimable once the gate lifts.
    let served = with_token
        .store
        .claim(&credential_hash(&lookup), &random32(), t, 900)
        .await
        .unwrap();
    assert!(served.is_some(), "the gate touched the row");

    // The setup page says the same thing with and without a token in the environment.
    let page_a = send(&with_token.app, get_req("localhost", "/en/s")).await;
    let page_b = send(&without_token.app, get_req("localhost", "/en/s")).await;
    assert_eq!(page_a.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_same(
        "setup page with vs without SHH_ADMIN_TOKEN",
        &page_a,
        &page_b,
    );
    let text = page_a.text();
    for forbidden in ["SHH_ADMIN_TOKEN", BOOTSTRAP, "bootstrap token"] {
        assert!(
            !text.contains(forbidden),
            "setup page mentions {forbidden:?}"
        );
    }
    assert_eq!(page_a.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(page_a.headers[header::REFERRER_POLICY], "no-referrer");
    // Every public page gets that same page: the path says nothing about which exist.
    let other = send(&with_token.app, get_req("localhost", "/en/no-such-page")).await;
    assert_same("setup page for an unknown path", &other, &page_a);

    // `/health` reports the state and nothing about why.
    let health = send(&with_token.app, get_req("localhost", "/api/v1/health")).await;
    assert_eq!(health.status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&health.body).unwrap();
    assert_eq!(v["configured"], json!(false));
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 3, "{v}");
}

// SPEC §4 (round 1 S-16 and the reveal control): the negative paths on reveal do the same
// work whether the row never existed, exists but is claimed by someone else, exists but
// expired, is a TTL row with a bogus claim token, or the input is malformed.
#[tokio::test]
async fn spec_r2_pass1_reveal_negatives_take_the_same_time() {
    const N: usize = 150;
    let srv = server("r2p1-reveal-timing", &[], UNLIMITED, true).await;
    let t = now();
    let mut claimed = Vec::new();
    let mut expired = Vec::new();
    let mut ttl_rows = Vec::new();
    for _ in 0..N {
        let l = plant(&srv.store, Lifetime::SingleView, t + 3600).await;
        srv.store
            .claim(&credential_hash(&l), &random32(), t, 900)
            .await
            .unwrap()
            .unwrap();
        claimed.push(l);
        expired.push(plant(&srv.store, Lifetime::Ttl, t - 10).await);
        ttl_rows.push(plant(&srv.store, Lifetime::Ttl, t + 3600).await);
    }
    for _ in 0..30 {
        send(
            &srv.app,
            post_json(
                "/api/v1/secrets/reveal",
                &json!({"lookup": b64(&random32())}),
                None,
            ),
        )
        .await;
    }
    let mut never = Vec::new();
    let mut other = Vec::new();
    let mut gone = Vec::new();
    let mut malformed = Vec::new();
    let mut bogus_token = Vec::new();
    let mut never_token = Vec::new();
    let mut baseline: Option<Reply> = None;
    for i in 0..N {
        let cases: [(&str, Value, &mut Vec<u128>); 6] = [
            ("never", json!({"lookup": b64(&random32())}), &mut never),
            (
                "claimed by other",
                json!({"lookup": b64(&claimed[i])}),
                &mut other,
            ),
            ("expired", json!({"lookup": b64(&expired[i])}), &mut gone),
            (
                "malformed",
                json!({"lookup": "nope", "claim_token": 7}),
                &mut malformed,
            ),
            (
                "ttl row + bogus token",
                json!({"lookup": b64(&ttl_rows[i]), "claim_token": b64(&random32())}),
                &mut bogus_token,
            ),
            (
                "never + bogus token",
                json!({"lookup": b64(&random32()), "claim_token": b64(&random32())}),
                &mut never_token,
            ),
        ];
        for (name, body, samples) in cases {
            let start = Instant::now();
            let r = send(&srv.app, post_json("/api/v1/secrets/reveal", &body, None)).await;
            samples.push(start.elapsed().as_micros());
            assert_eq!(r.status, StatusCode::NOT_FOUND, "{name}");
            match &baseline {
                Some(base) => assert_same(name, &r, base),
                None => baseline = Some(r),
            }
        }
    }
    println!("{}", describe("reveal never-existed", &mut never));
    println!("{}", describe("reveal claimed-by-other", &mut other));
    println!("{}", describe("reveal expired row", &mut gone));
    println!("{}", describe("reveal malformed", &mut malformed));
    println!(
        "{}",
        describe("reveal ttl row + bogus token", &mut bogus_token)
    );
    println!(
        "{}",
        describe("reveal never + bogus token", &mut never_token)
    );
    let base = percentile(&mut never, 0.5) as f64;
    for (name, v) in [
        ("claimed by other", &mut other),
        ("expired", &mut gone),
        ("malformed", &mut malformed),
    ] {
        let p50 = percentile(v, 0.5) as f64;
        assert!(
            (0.6 * base..=1.4 * base).contains(&p50),
            "{name}: {p50}us vs never-existed {base}us"
        );
    }
    // The re-download shape (a token present) is one SELECT instead of the claim UPDATE
    // plus the TTL SELECT, so it is faster; what matters is that within that shape a row
    // that exists and one that does not cost the same.
    let with_row = percentile(&mut bogus_token, 0.5) as f64;
    let without_row = percentile(&mut never_token, 0.5) as f64;
    assert!(
        (0.6 * without_row..=1.4 * without_row).contains(&with_row),
        "token shape: row {with_row}us vs no row {without_row}us"
    );
}

// D-18 at the grid boundaries: the stored expiry is a grid point and the same for every
// creation second inside a grid step, so a row holds at most the step, never the second.
#[test]
fn spec_r2_pass1_expiry_grid_hides_the_creation_second_at_every_boundary() {
    for (ttl, step) in [
        (60, 300),
        (3599, 300),
        (3600, 3600),
        (259_199, 3600),
        (259_200, 86_400),
        (1_209_600, 86_400),
    ] {
        assert_eq!(expiry::grid(ttl), step, "ttl {ttl}");
        // Every `now` in one aligned window maps to the same point.
        let base = 1_800_000_000 - (1_800_000_000 + ttl) % step;
        let first = expiry::expires_at(base + 1, ttl);
        for now in (base + 1)..=(base + step) {
            assert_eq!(expiry::expires_at(now, ttl), first, "ttl {ttl} now {now}");
            assert!(first >= now + ttl);
        }
        assert_ne!(expiry::expires_at(base + step + 1, ttl), first);
    }
    for window in [60, 900, 86_400] {
        let first = expiry::claim_expires_at(1, window);
        for now in 1..=60 {
            assert_eq!(expiry::claim_expires_at(now, window), first);
        }
    }
}

// D-25: on the main host the path form of the panel answers like any unknown page, byte
// for byte, and while unconfigured it gets the same setup page as everything else.
#[tokio::test]
async fn spec_r2_pass1_admin_path_form_is_an_ordinary_404_in_subdomain_mode() {
    let env: &[(&str, &str)] = &[
        ("SHH_ENV", "production"),
        ("SHH_URL", "https://example.com"),
        ("SHH_ADMIN_ROUTING", "domain"),
    ];
    let srv = server("r2p1-admin-sub", env, &[], true).await;
    for path in ["/en/admin", "/en/admin/login", "/en/admin/keys"] {
        let admin = send(&srv.app, get_req("example.com", path)).await;
        let plain = send(&srv.app, get_req("example.com", "/en/no-such-page")).await;
        assert_eq!(admin.status, StatusCode::NOT_FOUND, "{path}");
        assert_same(path, &admin, &plain);
    }
    // On the panel's host an unknown path is a bare 404 with the full header set.
    let bare = send(&srv.app, get_req("admin.example.com", "/en/s")).await;
    assert_eq!(bare.status, StatusCode::NOT_FOUND);
    assert_eq!(bare.headers[header::REFERRER_POLICY], "no-referrer");
    assert!(bare.headers.contains_key(header::STRICT_TRANSPORT_SECURITY));

    let gated = server("r2p1-admin-sub-gate", env, &[], false).await;
    let admin = send(&gated.app, get_req("example.com", "/en/admin/login")).await;
    let plain = send(&gated.app, get_req("example.com", "/en/privacy")).await;
    assert_eq!(admin.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_same("gated path-form admin", &admin, &plain);
    let panel = send(&gated.app, get_req("admin.example.com", "/en/login")).await;
    assert_eq!(panel.status, StatusCode::OK);
    // Noticed (not a leak): the setup page's "open the admin panel" link is host-relative,
    // so on the main host it points at `/en/login`, which that host does not serve.
    let link = plain
        .text()
        .split("href=\"")
        .find_map(|rest| {
            let href = rest.split('"').next()?;
            href.ends_with("/login").then(|| href.to_string())
        })
        .expect("the setup page links to the login");
    println!("setup page login link under subdomain routing: {link}");
    let followed = send(&gated.app, get_req("example.com", &link)).await;
    println!("following it on the main host answers {}", followed.status);
}

// D-26: a probing origin learns nothing but whether it is itself allowed: the answer to a
// stranger is the answer to a request without `Origin`, plus `Vary: Origin`.
#[tokio::test]
async fn spec_r2_pass1_cors_tells_a_stranger_nothing_about_the_list() {
    let srv = server(
        "r2p1-cors",
        &[],
        &[("allowed_origins", "http://app.example:5173")],
        true,
    )
    .await;
    let plain = send(&srv.app, get_req("localhost", "/api/v1/config")).await;
    let mut stranger_req = get_req("localhost", "/api/v1/config");
    stranger_req
        .headers_mut()
        .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    let stranger = send(&srv.app, stranger_req).await;
    assert_eq!(stranger.status, StatusCode::OK);
    assert_eq!(stranger.body, plain.body);
    assert_eq!(
        header_lines(&stranger.headers),
        header_lines(&plain.headers)
    );
    assert!(
        stranger
            .headers
            .get_all(header::VARY)
            .iter()
            .any(|v| v == "Origin")
    );
    let mut allowed_req = get_req("localhost", "/api/v1/config");
    allowed_req
        .headers_mut()
        .insert(header::ORIGIN, "http://APP.example:5173".parse().unwrap());
    let allowed = send(&srv.app, allowed_req).await;
    assert_eq!(
        allowed.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "http://APP.example:5173"
    );
    assert!(
        allowed
            .headers
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none()
    );
}

// D-23: admin API use, panel login and keyed API use all record the day only, once per day;
// the admin API and the panel show no finer value.
#[tokio::test]
async fn spec_r2_pass1_last_used_on_is_a_day_on_every_path() {
    let srv = server("r2p1-last-used", &[], UNLIMITED, true).await;
    let user_key = b64(&random32());
    srv.store
        .create_api_key(
            &credential_hash(user_key.as_bytes()),
            "integrator",
            Scope::User,
            5,
        )
        .await
        .unwrap();
    // Admin API call with the admin key, keyed report with the user key.
    let mut req = get_req("localhost", "/api/v1/admin/keys");
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {ADMIN_KEY}").parse().unwrap(),
    );
    assert_eq!(send(&srv.app, req).await.status, StatusCode::OK);
    let r = send(
        &srv.app,
        post_json(
            "/api/v1/reports",
            &json!({"lookup": b64(&random32())}),
            Some(&user_key),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let today = now() - now().rem_euclid(86_400);
    for key in srv.store.list_api_keys().await.unwrap() {
        assert_eq!(key.last_used_on, Some(today), "{}", key.name);
    }
    let mut req = get_req("localhost", "/api/v1/admin/keys");
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {ADMIN_KEY}").parse().unwrap(),
    );
    let listed = send(&srv.app, req).await;
    let v: Value = serde_json::from_slice(&listed.body).unwrap();
    for key in v["keys"].as_array().unwrap() {
        assert_eq!(key["last_used_on"], json!(today), "{key}");
    }
}

// SPEC §4: the report answer and work are the same for a secret that exists, one that is
// claimed, one that is gone and garbage; the daily counters move, nothing else is written.
#[tokio::test]
async fn spec_r2_pass1_report_counts_per_day_and_keeps_no_row() {
    let srv = server("r2p1-report", &[], UNLIMITED, true).await;
    let t = now();
    let active = plant(&srv.store, Lifetime::Ttl, t + 3600).await;
    let claimed = plant(&srv.store, Lifetime::SingleView, t + 3600).await;
    srv.store
        .claim(&credential_hash(&claimed), &random32(), t, 900)
        .await
        .unwrap()
        .unwrap();
    let mut replies = Vec::new();
    for body in [
        json!({"lookup": b64(&active)}),
        json!({"lookup": b64(&claimed)}),
        json!({"lookup": b64(&random32())}),
        json!({"lookup": "garbage"}),
        json!(null),
    ] {
        replies.push(send(&srv.app, post_json("/api/v1/reports", &body, None)).await);
    }
    for r in &replies[1..] {
        assert_same("report", r, &replies[0]);
    }
    assert_eq!(replies[0].status, StatusCode::OK);
    let stats = srv.store.stats().await.unwrap();
    assert_eq!((stats.reports, stats.removed), (5, 1));
    assert_eq!(stats.active, 1, "the claimed row stays for its claimant");
    // The database holds the counters and nothing keyed by the reported secret.
    let dump = std::fs::read(sqlite_path_for_tests_existing("r2p1-report")).unwrap();
    assert!(!contains(&dump, &credential_hash(&active)));
}

fn sqlite_path_for_tests_existing(name: &str) -> std::path::PathBuf {
    sqlite_test_dir().join(format!("{name}.db"))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// Nothing in the public answers identifies the build beyond the release version: `/config`,
// `/health` and the footer carry the crate version only, and no other header names it.
#[tokio::test]
async fn spec_r2_pass1_version_is_the_release_tag_only() {
    let srv = server("r2p1-version", &[], &[], true).await;
    let version = env!("CARGO_PKG_VERSION");
    let config = send(&srv.app, get_req("localhost", "/api/v1/config")).await;
    let v: Value = serde_json::from_slice(&config.body).unwrap();
    assert_eq!(v["server_version"], json!(version));
    let health = send(&srv.app, get_req("localhost", "/api/v1/health")).await;
    let h: Value = serde_json::from_slice(&health.body).unwrap();
    assert_eq!(h["version"], json!(version));
    for r in [&config, &health] {
        for name in ["server", "x-powered-by", "date", "x-request-id"] {
            assert!(r.headers.get(name).is_none(), "{name} header present");
        }
    }
    let page = send(&srv.app, get_req("localhost", "/en/about"))
        .await
        .text();
    assert!(page.contains(&format!("shhnote {version}")));
    // Not a git hash, not a build date: the version string is the tag's digits and labels.
    assert!(
        version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
        "{version}"
    );
}
