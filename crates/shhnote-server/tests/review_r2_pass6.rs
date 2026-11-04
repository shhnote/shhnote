// Security review, round 2, pass 6 (supply chain, build and deployment). These pin the
// deployment-facing properties the pass checked by hand: CORS reaches the API only and
// matches origins exactly, the setup gate under subdomain routing, the version string, and
// what `shhnote init --env` does to an existing file's mode.
//
// Run with: cargo test -p shhnote-server --test review_r2_pass6

use std::{collections::HashMap, fs, net::SocketAddr, process::Command};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use shhnote_core::secret::credential_hash;
use shhnote_core::{config::Config, settings::Settings};
use shhnote_server::{api::ApiState, app};
use shhnote_store::{Scope, Store, sqlite_path_for_tests};
use tower::ServiceExt;

const BOOTSTRAP: &str = "review-r2-pass6-bootstrap-token-of-32-chars-plus";

async fn build(name: &str, extra: &[(&str, &str)], configured: bool) -> Router {
    let mut vars: HashMap<String, String> = [
        ("SHH_ENV", "production"),
        ("SHH_URL", "https://example.com"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
        ("SHH_ADMIN_TOKEN", BOOTSTRAP),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in extra {
        vars.insert(k.to_string(), v.to_string());
    }
    let config = Config::from_vars(&vars).unwrap();
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let mut settings = Settings::default();
    if configured {
        store
            .create_api_key(&credential_hash(b"review-admin-key"), "r", Scope::Admin, 0)
            .await
            .unwrap();
        settings.site_name = "Review".into();
        settings.contact_email = "ops@example.test".into();
        settings.allowed_origins = vec!["https://app.example".into()];
    }
    app::router(&config, ApiState::new(store, settings, &config, None))
}

struct Seen {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

async fn send(
    app: &Router,
    method: Method,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Seen {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, host);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut req = req.body(Body::empty()).unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "192.0.2.9:40000".parse::<SocketAddr>().unwrap(),
    ));
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    Seen {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn allow_origin(seen: &Seen) -> Option<String> {
    seen.headers
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .map(|v| v.to_str().unwrap().to_string())
}

// SPEC §4 / D-26 and docs/deploy/own-frontend.md: CORS headers exist on the API only (never
// on `/static/*` or a page, so the served bundles are same-origin only), an origin matches
// exactly (scheme, host, port; no trailing slash, no `null`, no look-alike host), and no
// response ever allows credentials.
#[tokio::test]
async fn review_r2_pass6_cors_is_api_only_and_exact() {
    let app = build(
        "review-r2-pass6-cors",
        &[("SHH_API_ROUTING", "subdomain")],
        true,
    )
    .await;
    let api = "api.example.com";
    let site = "example.com";

    for origin in [
        "https://example.com",
        "https://app.example",
        "HTTPS://APP.EXAMPLE",
    ] {
        let r = send(&app, Method::GET, api, "/v1/config", &[("origin", origin)]).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(
            allow_origin(&r).as_deref(),
            Some(origin),
            "{origin} should be echoed"
        );
        assert!(
            r.headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }
    for origin in [
        "null",
        "https://example.com/",
        "https://example.com:443",
        "http://example.com",
        "https://example.com.evil.test",
        "https://evil.test#https://example.com",
        "https://app.example/",
        "https://sub.app.example",
    ] {
        for method in [Method::GET, Method::OPTIONS] {
            let r = send(
                &app,
                method.clone(),
                api,
                "/v1/config",
                &[
                    ("origin", origin),
                    ("access-control-request-method", "POST"),
                ],
            )
            .await;
            assert_eq!(allow_origin(&r), None, "{method} with Origin {origin}");
            assert!(
                r.headers
                    .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                    .is_none()
            );
        }
    }

    // Assets and pages on the site host: no CORS header for anyone, even the site origin.
    for path in ["/static/shh.js", "/static/argon2.wasm", "/en", "/en/s"] {
        for origin in ["https://example.com", "https://app.example"] {
            let r = send(&app, Method::GET, site, path, &[("origin", origin)]).await;
            assert_eq!(r.status, StatusCode::OK, "{path}");
            assert_eq!(allow_origin(&r), None, "{path} with Origin {origin}");
        }
    }
}

// D-29 with D-25/D-11: while setup is unmet and the panel and API have their own hosts, the
// gate opens the admin host and the API's health and admin routes only; the path form of
// the panel on the main host is refused (503, never the panel), `/static/*` stays, and in
// `api` mode the root is the gate's 503 rather than the mode's 404.
#[tokio::test]
async fn review_r2_pass6_setup_gate_under_subdomain_routing() {
    let app = build(
        "review-r2-pass6-gate",
        &[
            ("SHH_API_ROUTING", "subdomain"),
            ("SHH_ADMIN_ROUTING", "subdomain"),
            ("SHH_WEB", "api"),
        ],
        false,
    )
    .await;
    let site = "example.com";
    let api = "api.example.com";
    let admin = "admin.example.com";

    let r = send(&app, Method::GET, site, "/en/admin/login", &[]).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !r.body.contains("<form"),
        "the panel leaked onto the main host"
    );
    for path in ["/", "/en", "/s", "/en/s"] {
        let r = send(&app, Method::GET, site, path, &[]).await;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(r.headers[header::CACHE_CONTROL], "no-store", "{path}");
        assert!(r.headers.contains_key("content-security-policy"), "{path}");
        assert!(
            !r.body.contains("SHH_ADMIN_TOKEN") && !r.body.contains(BOOTSTRAP),
            "{path}: the setup page says something about the token"
        );
    }
    assert_eq!(
        send(&app, Method::GET, site, "/static/shh.js", &[])
            .await
            .status,
        StatusCode::OK
    );

    let login = send(&app, Method::GET, admin, "/en/login", &[]).await;
    assert_eq!(login.status, StatusCode::OK);
    assert!(login.body.contains("<form"));
    assert_eq!(
        send(&app, Method::GET, admin, "/", &[]).await.status,
        StatusCode::TEMPORARY_REDIRECT
    );

    let health = send(&app, Method::GET, api, "/v1/health", &[]).await;
    assert_eq!(health.status, StatusCode::OK);
    assert!(health.body.contains(r#""configured":false"#));
    let config = send(&app, Method::GET, api, "/v1/config", &[]).await;
    assert_eq!(config.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(config.body.contains(r#""code":"not_configured""#));
    assert_eq!(config.headers[header::CACHE_CONTROL], "no-store");
    // A preflight is gated too: the CORS layer sits inside the gate.
    let preflight = send(
        &app,
        Method::OPTIONS,
        api,
        "/v1/secrets",
        &[
            ("origin", "https://example.com"),
            ("access-control-request-method", "POST"),
        ],
    )
    .await;
    assert_eq!(preflight.status, StatusCode::SERVICE_UNAVAILABLE);
    let keys = send(
        &app,
        Method::GET,
        api,
        "/v1/admin/keys",
        &[("authorization", &format!("Bearer {BOOTSTRAP}"))],
    )
    .await;
    assert_eq!(keys.status, StatusCode::OK, "{}", keys.body);
}

// D-27: the public version is the crate version and nothing else: no git hash, no build
// metadata, no dirty marker, the same string on /config, /health and the footer.
#[tokio::test]
async fn review_r2_pass6_version_is_the_crate_version_only() {
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        !version.contains('+') && version.split('.').count() >= 3,
        "{version}"
    );
    let app = build("review-r2-pass6-version", &[], true).await;
    let config = send(&app, Method::GET, "example.com", "/api/v1/config", &[]).await;
    let health = send(&app, Method::GET, "example.com", "/api/v1/health", &[]).await;
    let home = send(&app, Method::GET, "example.com", "/en", &[]).await;
    assert!(
        config
            .body
            .contains(&format!(r#""server_version":"{version}""#)),
        "{}",
        config.body
    );
    assert!(
        health.body.contains(&format!(r#""version":"{version}""#)),
        "{}",
        health.body
    );
    assert!(home.body.contains(&format!("shhnote {version} ")));
    // Nothing that looks like a commit hash anywhere in the three.
    for body in [&config.body, &health.body] {
        let hex_run = body
            .split(|c: char| !c.is_ascii_hexdigit())
            .filter(|s| s.len() >= 7 && s.chars().any(|c| c.is_ascii_alphabetic()))
            .count();
        assert_eq!(hex_run, 0, "{body}");
    }
}

// SPEC §8: `init --env` keeps an existing file's mode (so a world-readable `.env` stays
// world-readable: the docs have to set the mode, the tool does not), creates a new file
// owner-only, and the printing form writes the two lines to stdout and nothing to stderr.
#[cfg(unix)]
#[test]
fn review_r2_pass6_init_env_modes() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("review-r2-pass6-init-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let shhnote = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shhnote"));
        cmd.env_clear().current_dir(&dir);
        cmd
    };

    let out = shhnote().arg("init").output().unwrap();
    assert!(out.status.success());
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 2);

    let world = dir.join("world.env");
    fs::write(&world, "SHH_DB=sqlite\n").unwrap();
    fs::set_permissions(&world, fs::Permissions::from_mode(0o644)).unwrap();
    let out = shhnote()
        .args(["init", "--env", world.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let mode = fs::metadata(&world).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o644,
        "an existing file keeps its mode, as SPEC §8 says"
    );
    assert!(
        fs::read_to_string(&world)
            .unwrap()
            .contains("SHH_SECRET_KEY=")
    );

    let fresh = dir.join("fresh.env");
    let out = shhnote()
        .args(["init", "--env", fresh.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let mode = fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "a new file is owner-only");

    let names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().all(|n| !n.ends_with(".tmp")),
        "temp file left behind: {names:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}
