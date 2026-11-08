use std::{collections::HashMap, net::SocketAddr};

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

const ADMIN_KEY: &str = "test-admin-key-of-at-least-32-characters";
const BOOTSTRAP: &str = "test-bootstrap-token-of-at-least-32-chars";

async fn parts(name: &str, extra: &[(&str, &str)], configured: bool) -> (Config, ApiState, Store) {
    let mut vars: HashMap<String, String> = [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
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
            .create_api_key(
                &credential_hash(ADMIN_KEY.as_bytes()),
                "test",
                Scope::Admin,
                0,
            )
            .await
            .unwrap();
        settings.site_name = "Test".into();
        settings.contact_email = "ops@example.test".into();
    }
    let state = ApiState::new(store.clone(), settings, &config, None);
    (config, state, store)
}

async fn build(name: &str, extra: &[(&str, &str)], configured: bool) -> Router {
    let (config, state, _) = parts(name, extra, configured).await;
    app::router(&config, state)
}

struct Seen {
    label: String,
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

struct Req<'a> {
    host: &'a str,
    method: Method,
    path: &'a str,
    headers: &'a [(&'a str, &'a str)],
    body: &'a str,
}

async fn send(app: &Router, r: Req<'_>) -> Seen {
    let mut req = Request::builder()
        .method(r.method.clone())
        .uri(r.path)
        .header(header::HOST, r.host);
    for (k, v) in r.headers {
        req = req.header(*k, *v);
    }
    let mut req = req.body(Body::from(r.body.to_string())).unwrap();
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
        label: format!("{} {}{}", r.method, r.host, r.path),
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn get(app: &Router, host: &str, path: &str) -> Seen {
    send(
        app,
        Req {
            host,
            method: Method::GET,
            path,
            headers: &[],
            body: "",
        },
    )
    .await
}

fn flags(s: &Seen, hsts_expected: bool) -> String {
    let has = |n: &str| if s.headers.contains_key(n) { "y" } else { "-" };
    let cc = s
        .headers
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap_or("?").to_string())
        .unwrap_or_else(|| "-".into());
    let hsts = if hsts_expected {
        has("strict-transport-security")
    } else {
        "n/a"
    };
    format!(
        "{} | {} | {} | {} | {} | {} | {} | {}",
        s.status.as_u16(),
        has("content-security-policy"),
        hsts,
        has("x-frame-options"),
        has("x-content-type-options"),
        has("referrer-policy"),
        has("permissions-policy"),
        cc
    )
}

const REQUIRED: &[&str] = &[
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
];

// Every route a mode can answer, as (method, path, content-type, body). `api` is the API
// prefix on the main host ("/api/v1") or "" on the API host.
fn routes(api: &str) -> Vec<(Method, String, Option<&'static str>, &'static str)> {
    let mut out: Vec<(Method, String, Option<&'static str>, &'static str)> = Vec::new();
    for locale in ["en", "de"] {
        for page in [
            "",
            "/s",
            "/burn",
            "/report",
            "/how-it-works",
            "/about",
            "/contact",
            "/terms",
            "/privacy",
            "/security",
            "/acceptable-use",
            "/docs",
            "/admin",
            "/admin/login",
            "/admin/settings",
            "/admin/keys",
            "/nope",
        ] {
            out.push((Method::GET, format!("/{locale}{page}"), None, ""));
        }
    }
    for p in [
        "/",
        "/s",
        "/burn",
        "/report",
        "/en/",
        "/static/app.css?v=x",
        "/static/app.js",
        "/static/shh.js",
        "/static/shh-ui.js",
        "/static/argon2.wasm",
        "/static/fonts/geist.woff2",
        "/static/nope.js",
        "/static/../Cargo.toml",
        "/fr/s",
    ] {
        out.push((Method::GET, p.to_string(), None, ""));
    }
    out.push((Method::HEAD, "/en/s".into(), None, ""));
    out.push((Method::OPTIONS, "/en/s".into(), None, ""));
    out.push((Method::POST, "/en/terms".into(), None, ""));
    out.push((
        Method::POST,
        "/en/admin/logout".into(),
        Some("application/x-www-form-urlencoded"),
        "",
    ));
    out.push((
        Method::POST,
        "/en/admin/login".into(),
        Some("application/x-www-form-urlencoded"),
        "credential=wrong",
    ));
    let json = Some("application/json");
    for (m, p, ct, b) in [
        (Method::GET, "", None, ""),
        (Method::GET, "/config", None, ""),
        (Method::GET, "/health", None, ""),
        (Method::GET, "/secrets", None, ""),
        (Method::POST, "/secrets", None, ""),
        (Method::POST, "/secrets/reveal", json, r#"{"lookup":"x"}"#),
        (Method::POST, "/secrets/reveal", json, "not json"),
        (Method::OPTIONS, "/secrets/reveal", None, ""),
        (
            Method::POST,
            "/secrets/confirm",
            json,
            r#"{"lookup":"x","claim_token":"y"}"#,
        ),
        (Method::POST, "/secrets/burn", json, r#"{"burn_token":"x"}"#),
        (Method::POST, "/reports", json, r#"{"lookup":"x"}"#),
        (Method::GET, "/admin/stats", None, ""),
        (Method::GET, "/admin/settings", None, ""),
        (Method::PATCH, "/admin/settings", json, "{}"),
        (Method::GET, "/nope", None, ""),
        (Method::GET, "/", None, ""),
    ] {
        out.push((m, format!("{api}/v1{p}"), ct, b));
    }
    out.push((Method::GET, format!("{api}/v2/config"), None, ""));
    if !api.is_empty() {
        out.push((Method::GET, api.to_string(), None, ""));
    }
    out
}

async fn walk(app: &Router, host: &str, api: &str) -> Vec<Seen> {
    let mut seen = Vec::new();
    for (method, path, ct, body) in routes(api) {
        let headers: Vec<(&str, &str)> = ct.map(|c| ("content-type", c)).into_iter().collect();
        seen.push(
            send(
                app,
                Req {
                    host,
                    method,
                    path: &path,
                    headers: &headers,
                    body,
                },
            )
            .await,
        );
    }
    seen
}

fn missing(seen: &[Seen], hsts: bool) -> Vec<String> {
    seen.iter()
        .flat_map(|s| {
            let mut m: Vec<String> = REQUIRED
                .iter()
                .filter(|n| !s.headers.contains_key(**n))
                .map(|n| format!("{} ({}) lacks {n}", s.label, s.status))
                .collect();
            if hsts && !s.headers.contains_key("strict-transport-security") {
                m.push(format!("{} ({}) lacks hsts", s.label, s.status));
            }
            m
        })
        .collect()
}

// SPEC §11: every route, in every mode, configured and not, carries the full header set.
// Prints a table of what each response sent (run with --nocapture).
#[tokio::test]
async fn spec_security_headers_on_every_route_in_every_mode() {
    #[allow(clippy::type_complexity)]
    let modes: Vec<(&str, Vec<(&str, &str)>, &str, &str, bool)> = vec![
        ("full/path/local", vec![], "localhost", "/api", false),
        (
            "full/path/production",
            vec![
                ("SHH_ENV", "production"),
                ("SHH_URL", "https://example.com"),
            ],
            "example.com",
            "/api",
            true,
        ),
        (
            "full/admin-subdomain (main host)",
            vec![
                ("SHH_ENV", "production"),
                ("SHH_URL", "https://example.com"),
                ("SHH_ADMIN_ROUTING", "domain"),
            ],
            "example.com",
            "/api",
            true,
        ),
        (
            "full/admin-subdomain (admin host)",
            vec![
                ("SHH_ENV", "production"),
                ("SHH_URL", "https://example.com"),
                ("SHH_ADMIN_ROUTING", "domain"),
            ],
            "admin.example.com",
            "/api",
            true,
        ),
        (
            "full/api-subdomain (api host)",
            vec![
                ("SHH_ENV", "production"),
                ("SHH_URL", "https://example.com"),
                ("SHH_API_ROUTING", "domain"),
            ],
            "api.example.com",
            "",
            true,
        ),
        (
            "api/path/local",
            vec![("SHH_WEB", "api")],
            "localhost",
            "/api",
            false,
        ),
        (
            "api/admin-subdomain (main host)",
            vec![
                ("SHH_ENV", "production"),
                ("SHH_URL", "https://example.com"),
                ("SHH_WEB", "api"),
                ("SHH_ADMIN_ROUTING", "domain"),
            ],
            "example.com",
            "/api",
            true,
        ),
        (
            "api/admin-subdomain (admin host)",
            vec![
                ("SHH_ENV", "production"),
                ("SHH_URL", "https://example.com"),
                ("SHH_WEB", "api"),
                ("SHH_ADMIN_ROUTING", "domain"),
            ],
            "admin.example.com",
            "/api",
            true,
        ),
    ];
    let mut all_missing = Vec::new();
    for configured in [true, false] {
        for (i, (name, extra, host, api, hsts)) in modes.iter().enumerate() {
            let app = build(
                &format!("routing-walk-{i}-{}", u8::from(configured)),
                extra,
                configured,
            )
            .await;
            let seen = walk(&app, host, api).await;
            println!(
                "\n### mode: {name}, configured={configured}\n\n| request | status | CSP | HSTS | XFO | XCTO | RP | PP | Cache-Control |\n|---|---|---|---|---|---|---|---|---|"
            );
            for s in &seen {
                println!("| `{}` | {} |", s.label, flags(s, *hsts));
            }
            all_missing.extend(missing(&seen, *hsts));
        }
    }
    assert!(all_missing.is_empty(), "{}", all_missing.join("\n"));
}

// D-29: while setup is unmet, exactly `/health`, the admin panel, the admin API and
// `/static/*` answer; everything else is 503 with `no-store`, the setup page for pages and
// `not_configured` for the API, whatever the method. Both web modes, both admin routings.
#[tokio::test]
async fn spec_setup_gate_closes_all_but_open_routes_in_every_mode() {
    #[allow(clippy::type_complexity)]
    let modes: Vec<(&str, Vec<(&str, &str)>, &str, &str, &str)> = vec![
        ("full/path", vec![], "localhost", "localhost", "/api"),
        (
            "api/path",
            vec![("SHH_WEB", "api")],
            "localhost",
            "localhost",
            "/api",
        ),
        (
            "full/admin-subdomain",
            vec![
                ("SHH_ENV", "production"),
                ("SHH_URL", "https://example.com"),
                ("SHH_ADMIN_ROUTING", "domain"),
            ],
            "example.com",
            "admin.example.com",
            "/api",
        ),
        (
            "api/admin-subdomain+api-subdomain",
            vec![
                ("SHH_ENV", "production"),
                ("SHH_URL", "https://example.com"),
                ("SHH_WEB", "api"),
                ("SHH_ADMIN_ROUTING", "domain"),
                ("SHH_API_ROUTING", "domain"),
            ],
            "example.com",
            "admin.example.com",
            "",
        ),
    ];
    for (i, (name, extra, host, admin_host, api)) in modes.iter().enumerate() {
        let app = build(&format!("routing-gate-{i}"), extra, false).await;
        let api_host = if api.is_empty() {
            "api.example.com"
        } else {
            *host
        };
        let api_prefix = if api.is_empty() { "" } else { "/api" };
        for method in [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::OPTIONS,
            Method::PUT,
        ] {
            for path in [
                "/",
                "/s",
                "/en",
                "/en/s",
                "/en/burn",
                "/en/report",
                "/en/docs",
                "/en/privacy",
                "/nope",
                "/en/",
                "/fr/s",
                "/API/v1/config",
            ] {
                let s = send(
                    &app,
                    Req {
                        host,
                        method: method.clone(),
                        path,
                        headers: &[],
                        body: "",
                    },
                )
                .await;
                assert_eq!(
                    s.status,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "{name}: {}",
                    s.label
                );
                assert_eq!(
                    s.headers.get(header::CACHE_CONTROL).map(|v| v.as_bytes()),
                    Some(&b"no-store"[..]),
                    "{name}: {}",
                    s.label
                );
                for h in REQUIRED {
                    assert!(s.headers.contains_key(*h), "{name}: {} lacks {h}", s.label);
                }
                assert!(
                    !s.body.contains(BOOTSTRAP)
                        && !s.body.to_ascii_lowercase().contains("shh_admin_token"),
                    "{name}: {} names the token",
                    s.label
                );
                assert!(
                    !s.body.contains("<form"),
                    "{name}: {} renders a form on the setup page",
                    s.label
                );
            }
            for path in [
                "/v1",
                "/v1/",
                "/v1/config",
                "/v1/secrets/reveal",
                "/v1/nope",
                "/",
                "/v2/x",
                "/v1/health/x",
                "/health",
            ] {
                let full = format!("{api_prefix}{path}");
                let s = send(
                    &app,
                    Req {
                        host: api_host,
                        method: method.clone(),
                        path: &full,
                        headers: &[("content-type", "application/json")],
                        body: r#"{"lookup":"x"}"#,
                    },
                )
                .await;
                assert_eq!(
                    s.status,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "{name}: {}",
                    s.label
                );
                assert_eq!(
                    s.headers.get(header::CACHE_CONTROL).map(|v| v.as_bytes()),
                    Some(&b"no-store"[..]),
                    "{name}: {}",
                    s.label
                );
                for h in REQUIRED {
                    assert!(s.headers.contains_key(*h), "{name}: {} lacks {h}", s.label);
                }
                if method != Method::HEAD {
                    assert!(
                        s.body.contains(r#""code":"not_configured""#),
                        "{name}: {}: {}",
                        s.label,
                        s.body
                    );
                }
            }
        }
        // Paths under an open prefix that match no route: what answers? (Prefix checks in
        // the gate; axum never normalises `..`.)
        for path in [
            "/en/admin/../s",
            "/en/admin/nope",
            "/static/../Cargo.toml",
            "/static/../en/s",
        ] {
            let s = get(&app, host, path).await;
            println!(
                "{name}: unconfigured {path} -> {} ({} bytes, html={})",
                s.status,
                s.body.len(),
                s.body.contains("<html")
            );
            assert!(
                s.status == StatusCode::NOT_FOUND || s.status == StatusCode::SERVICE_UNAVAILABLE,
                "{name}: {}",
                s.label
            );
        }
        // Open: health, admin panel (its host), admin API, static.
        let health = get(&app, api_host, &format!("{api_prefix}/v1/health")).await;
        assert_eq!(health.status, StatusCode::OK, "{name}");
        assert!(health.body.contains(r#""configured":false"#));
        let health_slash = get(&app, api_host, &format!("{api_prefix}/v1/health/")).await;
        assert_eq!(
            health_slash.status,
            StatusCode::PERMANENT_REDIRECT,
            "{name}: trailing-slash health is open (308)"
        );
        let admin_login_path = if admin_host == host {
            "/en/admin/login"
        } else {
            "/en/login"
        };
        let login = get(&app, admin_host, admin_login_path).await;
        assert_eq!(login.status, StatusCode::OK, "{name}: {}", login.label);
        assert!(!login.body.contains(BOOTSTRAP));
        let stats = get(&app, api_host, &format!("{api_prefix}/v1/admin/stats")).await;
        assert_eq!(
            stats.status,
            StatusCode::UNAUTHORIZED,
            "{name}: {}",
            stats.label
        );
        for h in ["/static/app.css?v=x", "/static/shh.js"] {
            assert_eq!(
                get(&app, host, h).await.status,
                StatusCode::OK,
                "{name}: {h}"
            );
            assert_eq!(
                get(&app, admin_host, h).await.status,
                StatusCode::OK,
                "{name}: admin host {h}"
            );
        }
        // The admin host (subdomain mode) is entirely open while unconfigured: what does it show?
        if admin_host != host {
            for p in ["/", "/en", "/en/s", "/nope", "/api/v1/config", "/en/admin"] {
                let s = get(&app, admin_host, p).await;
                println!(
                    "{name}: unconfigured admin host {p} -> {} {:?}",
                    s.status,
                    s.headers.get(header::LOCATION)
                );
                assert!(
                    s.status == StatusCode::NOT_FOUND || s.status.is_redirection(),
                    "{name}: {}",
                    s.label
                );
            }
        }
    }
}

// D-29: the setup page links the admin login. With the panel on its own host, that link must
// point at the admin host, since `/{locale}/login` does not exist on the main host.
#[tokio::test]
async fn spec_setup_page_login_link_reaches_the_panel_under_admin_domain_routing() {
    let app = build(
        "routing-setup-link",
        &[
            ("SHH_ENV", "production"),
            ("SHH_URL", "https://example.com"),
            ("SHH_ADMIN_ROUTING", "domain"),
        ],
        false,
    )
    .await;
    let setup = get(&app, "example.com", "/en/s").await;
    assert_eq!(setup.status, StatusCode::SERVICE_UNAVAILABLE);
    let href = setup
        .body
        .split("href=\"")
        .find(|s| s.contains("login"))
        .map(|s| s.split('"').next().unwrap().to_string())
        .expect("a login link on the setup page");
    println!("setup page login href on the main host: {href}");
    // Follow it on the main host: it must reach the panel, not another setup page / 404.
    let followed = get(&app, "example.com", &href).await;
    println!("following it on example.com -> {}", followed.status);
    assert!(
        href.starts_with("https://admin.example.com/") || followed.status == StatusCode::OK,
        "the setup page's login link ({href}) is dead on the host that serves the page: {}",
        followed.status
    );
}

// D-29: the gate is derived while unmet and remembered once met. Within a process it never
// re-arms; a restart (a fresh router over the same database) derives it again, so after
// `reset-admin` or deleting the last admin key the whole site is 503 on the next start.
#[tokio::test]
async fn spec_setup_gate_rearms_only_after_restart() {
    let (config, state, store) = parts("routing-rearm", &[], true).await;
    let app = app::router(&config, state.clone());
    assert_eq!(get(&app, "localhost", "/en").await.status, StatusCode::OK);
    store
        .delete_admin_keys(shhnote_server::clock::now())
        .await
        .unwrap();
    assert_eq!(
        get(&app, "localhost", "/en").await.status,
        StatusCode::OK,
        "sticky within the process"
    );
    let health = get(&app, "localhost", "/api/v1/health").await;
    println!(
        "after deleting the last admin key, same process: {}",
        health.body
    );
    // A restart: same database, no admin key, settings loaded from the (empty) overrides
    // table the way main.rs does.
    let overrides = store.setting_overrides().await.unwrap();
    let (settings, _) = Settings::with_overrides(&overrides, config.env);
    let restarted = app::router(
        &config,
        ApiState::new(store.clone(), settings, &config, None),
    );
    let after = get(&restarted, "localhost", "/en").await;
    println!("after a restart with no admin key: {}", after.status);
    assert_eq!(after.status, StatusCode::SERVICE_UNAVAILABLE);
}

// D-29: neither the panel form nor the API can empty site_name / contact_email once set;
// a save that fails validation for another field also changes nothing.
#[tokio::test]
async fn spec_setup_fields_cannot_be_cleared_by_panel_form() {
    let app = build("routing-clear", &[], true).await;
    let cookie = login(&app, "localhost", "/en/admin/login", ADMIN_KEY).await;
    let page = get_with_cookie(&app, "localhost", "/en/admin/settings", &cookie).await;
    let csrf = csrf_of(&page.body);
    let defaults = Settings::default().as_strings();
    for (field, value) in [
        ("site_name", ""),
        ("site_name", "   "),
        ("contact_email", ""),
        ("contact_email", " \t"),
    ] {
        let mut fields: Vec<(String, String)> = defaults
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        fields.retain(|(k, _)| k != "site_name" && k != "contact_email");
        fields.push(("site_name".into(), "Test".into()));
        fields.push(("contact_email".into(), "ops@example.test".into()));
        fields.retain(|(k, _)| k != field);
        fields.push((field.into(), value.into()));
        fields.push(("csrf".into(), csrf.clone()));
        let r = post_form(&app, "localhost", "/en/admin/settings", &cookie, &fields).await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{field}={value:?} accepted"
        );
    }
    let health = get(&app, "localhost", "/api/v1/health").await;
    assert!(health.body.contains(r#""configured":true"#));
    assert_eq!(get(&app, "localhost", "/en").await.status, StatusCode::OK);
}

// D-25: host matching and what a request on the wrong host can reach.
#[tokio::test]
async fn spec_admin_domain_host_matching_and_cookie_scope() {
    let app = build(
        "routing-admin-host",
        &[
            ("SHH_ENV", "production"),
            ("SHH_URL", "https://example.com"),
            ("SHH_ADMIN_ROUTING", "domain"),
        ],
        true,
    )
    .await;
    // Host variants that must select the panel.
    for host in [
        "admin.example.com",
        "ADMIN.Example.COM",
        "admin.example.com:443",
        "admin.example.com:8443",
    ] {
        let r = get(&app, host, "/en/login").await;
        assert_eq!(r.status, StatusCode::OK, "{host}");
    }
    // Host variants that must NOT select the panel.
    for host in [
        "admin.example.com.",
        "xadmin.example.com",
        "admin.example.com.evil",
        "example.com",
        "api.example.com",
        "",
    ] {
        let r = get(&app, host, "/en/login").await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{host:?}: {}", r.status);
        let r = get(&app, host, "/en/admin/login").await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{host:?} path form");
    }
    // A forged Host from a public client reaches the panel: host-based routing, by design;
    // the deploy docs put the allow-list in the proxy. Printed only.
    let forged = send(
        &app,
        Req {
            host: "admin.example.com",
            method: Method::GET,
            path: "/en/login",
            headers: &[("x-forwarded-host", "example.com")],
            body: "",
        },
    )
    .await;
    println!("forged Host from a public client: {}", forged.status);

    // The admin host serves no API and no public page.
    for p in [
        "/api/v1/config",
        "/v1/config",
        "/en/s",
        "/en",
        "/en/report",
        "/en/api/v1/config",
    ] {
        let r = get(&app, "admin.example.com", p).await;
        println!(
            "admin host {p} -> {} {:?}",
            r.status,
            r.headers.get(header::LOCATION)
        );
        assert!(
            matches!(
                r.status,
                StatusCode::NOT_FOUND | StatusCode::SEE_OTHER | StatusCode::TEMPORARY_REDIRECT
            ),
            "{p}: {}",
            r.status
        );
        if r.status == StatusCode::SEE_OTHER {
            assert_eq!(r.headers[header::LOCATION], "/en/login", "{p}");
        }
        if r.status == StatusCode::TEMPORARY_REDIRECT {
            let loc = r.headers[header::LOCATION].to_str().unwrap().to_string();
            let followed = get(&app, "admin.example.com", &loc).await;
            assert_eq!(followed.status, StatusCode::NOT_FOUND, "{p} -> {loc}");
        }
    }
    // Login on the admin host: cookie without Domain; the same cookie on the main host hits
    // nothing (no admin route there, and the admin API refuses cookies).
    let login = send(
        &app,
        Req {
            host: "admin.example.com",
            method: Method::POST,
            path: "/en/login",
            headers: &[("content-type", "application/x-www-form-urlencoded")],
            body: &format!("credential={ADMIN_KEY}"),
        },
    )
    .await;
    assert_eq!(login.status, StatusCode::SEE_OTHER, "{}", login.body);
    let set = login.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    println!(
        "Set-Cookie on the admin host: {}",
        set.replacen(&set[10..60], "…", 1)
    );
    assert!(!set.to_ascii_lowercase().contains("domain="));
    assert!(set.contains("Secure") && set.contains("HttpOnly") && set.contains("SameSite=Strict"));
    let cookie = set.split(';').next().unwrap().to_string();
    let r = get_with_cookie(&app, "example.com", "/en/admin", &cookie).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = send(
        &app,
        Req {
            host: "example.com",
            method: Method::GET,
            path: "/api/v1/admin/stats",
            headers: &[("cookie", &cookie)],
            body: "",
        },
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::UNAUTHORIZED,
        "admin API accepted a cookie"
    );
    // Login POST on the wrong host.
    let wrong = send(
        &app,
        Req {
            host: "example.com",
            method: Method::POST,
            path: "/en/login",
            headers: &[("content-type", "application/x-www-form-urlencoded")],
            body: &format!("credential={ADMIN_KEY}"),
        },
    )
    .await;
    assert_eq!(wrong.status, StatusCode::NOT_FOUND);
    assert!(wrong.headers.get(header::SET_COOKIE).is_none());
    // The CSRF token minted on the admin host works only with that session (host-only cookie).
    let page = get_with_cookie(&app, "admin.example.com", "/en/settings", &cookie).await;
    assert_eq!(page.status, StatusCode::OK);
    let csrf = csrf_of(&page.body);
    let logout_wrong_host = send(
        &app,
        Req {
            host: "example.com",
            method: Method::POST,
            path: "/en/logout",
            headers: &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("cookie", &cookie),
            ],
            body: &format!("csrf={csrf}"),
        },
    )
    .await;
    assert_eq!(logout_wrong_host.status, StatusCode::NOT_FOUND);
    // Absolute-form request target with a different Host header: the URI host wins.
    let abs = send(
        &app,
        Req {
            host: "example.com",
            method: Method::GET,
            path: "http://admin.example.com/en/login",
            headers: &[],
            body: "",
        },
    )
    .await;
    println!(
        "absolute-form URI naming the admin host, Host: example.com -> {}",
        abs.status
    );
}

// SPEC §4 / D-26: the CORS layer, edge by edge.
#[tokio::test]
async fn spec_cors_matches_listed_origins_exactly() {
    let (config, state, store) = parts(
        "routing-cors",
        &[
            ("SHH_ENV", "production"),
            ("SHH_URL", "https://example.com"),
        ],
        true,
    )
    .await;
    let app = app::router(&config, state.clone());
    let auth = format!("Bearer {ADMIN_KEY}");
    let patch = |body: &'static str| {
        let app = app.clone();
        let auth = auth.clone();
        async move {
            send(
                &app,
                Req {
                    host: "example.com",
                    method: Method::PATCH,
                    path: "/api/v1/admin/settings",
                    headers: &[
                        ("content-type", "application/json"),
                        ("authorization", &auth),
                    ],
                    body,
                },
            )
            .await
        }
    };
    let r = patch(r#"{"allowed_origins":"https://app.example"}"#).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let acao = |s: &Seen| {
        s.headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(|v| v.to_str().unwrap().to_string())
    };

    // Preflight for a POST with Authorization and Content-Type from the listed origin.
    let pre = send(
        &app,
        Req {
            host: "example.com",
            method: Method::OPTIONS,
            path: "/api/v1/secrets/reveal",
            headers: &[
                ("origin", "https://app.example"),
                ("access-control-request-method", "POST"),
                (
                    "access-control-request-headers",
                    "authorization, content-type",
                ),
            ],
            body: "",
        },
    )
    .await;
    assert_eq!(pre.status, StatusCode::NO_CONTENT);
    assert_eq!(acao(&pre).as_deref(), Some("https://app.example"));
    assert!(
        pre.headers
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none()
    );
    println!("preflight headers: {:?}", pre.headers);
    // Origins that must get nothing.
    for origin in [
        "null",
        "https://app.example/",
        "https://app.example/path",
        "https://evil.example",
        "https://app.example.evil",
        "http://app.example",
        "https://app.example:443",
        "HTTPS://EXAMPLE.COM/",
        "https://example.com:443",
    ] {
        let r = send(
            &app,
            Req {
                host: "example.com",
                method: Method::GET,
                path: "/api/v1/config",
                headers: &[("origin", origin)],
                body: "",
            },
        )
        .await;
        assert_eq!(acao(&r), None, "{origin}");
        assert!(
            r.headers
                .get_all(header::VARY)
                .iter()
                .any(|v| v == "Origin"),
            "{origin}: Vary"
        );
        assert!(
            r.headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }
    // Case-insensitive match; the site origin by default.
    for origin in [
        "https://App.Example",
        "https://EXAMPLE.com",
        "https://example.com",
    ] {
        let r = send(
            &app,
            Req {
                host: "example.com",
                method: Method::GET,
                path: "/api/v1/config",
                headers: &[("origin", origin)],
                body: "",
            },
        )
        .await;
        assert_eq!(acao(&r).as_deref(), Some(origin), "{origin}");
    }
    // Website routes and the admin panel never carry CORS headers, preflight or not.
    for (m, p) in [
        (Method::GET, "/en"),
        (Method::OPTIONS, "/en/admin/login"),
        (Method::OPTIONS, "/en/s"),
        (Method::GET, "/static/shh.js"),
    ] {
        let r = send(
            &app,
            Req {
                host: "example.com",
                method: m,
                path: p,
                headers: &[
                    ("origin", "https://app.example"),
                    ("access-control-request-method", "POST"),
                ],
                body: "",
            },
        )
        .await;
        assert_eq!(acao(&r), None, "{p}");
        println!("{p} OPTIONS/GET with Origin -> {}", r.status);
    }
    // The admin API from a listed origin with a Bearer key (SPEC §4: same-origin only, no
    // CORS headers). Printed only.
    let admin_pre = send(
        &app,
        Req {
            host: "example.com",
            method: Method::OPTIONS,
            path: "/api/v1/admin/settings",
            headers: &[
                ("origin", "https://app.example"),
                ("access-control-request-method", "PATCH"),
                (
                    "access-control-request-headers",
                    "authorization, content-type",
                ),
            ],
            body: "",
        },
    )
    .await;
    println!(
        "admin API preflight from a listed origin: {} {:?}",
        admin_pre.status,
        admin_pre.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
    let admin_real = send(
        &app,
        Req {
            host: "example.com",
            method: Method::GET,
            path: "/api/v1/admin/stats",
            headers: &[("origin", "https://app.example"), ("authorization", &auth)],
            body: "",
        },
    )
    .await;
    println!(
        "admin API GET from a listed origin: {} ACAO={:?}",
        admin_real.status,
        acao(&admin_real)
    );
    // Preflight short-circuits before the rate limiter and the handler; also with no Origin.
    let no_origin = send(
        &app,
        Req {
            host: "example.com",
            method: Method::OPTIONS,
            path: "/api/v1/secrets/reveal",
            headers: &[],
            body: "",
        },
    )
    .await;
    assert_eq!(no_origin.status, StatusCode::NO_CONTENT);
    assert_eq!(acao(&no_origin), None);
    // A PATCH with a bad origin and a good site_name changes nothing at all.
    let before = state.settings.load().site_name.clone();
    let r = patch(
        r#"{"site_name":"Changed","allowed_origins":"https://ok.example, https://bad.example/x"}"#,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(state.settings.load().site_name, before);
    assert_eq!(
        state.settings.load().allowed_origins,
        vec!["https://app.example"]
    );
    let _ = store;
}

// SPEC §7.2: the duration dropdowns are a UI convenience; the server must validate the
// posted seconds, not the choice list. A crafted form may post any value.
#[tokio::test]
async fn spec_settings_form_validates_posted_values_and_keeps_padding_fields() {
    let (config, state, _) = parts("routing-form", &[], true).await;
    let app = app::router(&config, state.clone());
    let cookie = login(&app, "localhost", "/en/admin/login", ADMIN_KEY).await;
    let page = get_with_cookie(&app, "localhost", "/en/admin/settings", &cookie).await;
    let csrf = csrf_of(&page.body);
    println!(
        "duration choices offered for claim_window_secs: {}",
        page.body
            .split("name=\"claim_window_secs\"")
            .nth(1)
            .map(|s| s
                .split("</select>")
                .next()
                .unwrap_or("")
                .matches("<option")
                .count())
            .unwrap_or(0)
    );
    let base = || -> Vec<(String, String)> {
        let mut f: Vec<(String, String)> = state
            .settings
            .load()
            .as_strings()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        f.push(("csrf".into(), csrf.clone()));
        f
    };
    let post = |fields: Vec<(String, String)>| {
        let app = app.clone();
        let cookie = cookie.clone();
        async move { post_form(&app, "localhost", "/en/admin/settings", &cookie, &fields).await }
    };
    let with = |changes: &[(&str, &str)]| -> Vec<(String, String)> {
        let mut f = base();
        for (k, v) in changes {
            f.retain(|(key, _)| key != k);
            f.push((k.to_string(), v.to_string()));
        }
        f
    };
    // Out of range or inconsistent: refused as a whole (422), nothing applied.
    for changes in [
        vec![("claim_window_secs", "59")],
        vec![("claim_window_secs", "86401")],
        vec![("claim_window_secs", "-1")],
        vec![("claim_window_secs", "1e3")],
        vec![("max_ttl_secs", "1209601")],
        vec![("min_ttl_secs", "59")],
        vec![("ttl_presets", "900,1209601")],
        vec![("ttl_presets", "900,abc")],
        vec![("default_ttl_secs", "30")],
        vec![("min_ttl_secs", "7200"), ("default_ttl_secs", "3600")],
        vec![("salt_rotation_secs", "0")],
        vec![("padding_min", "65535B")],
        vec![("padding_mode", "buckets"), ("padding_ladder", "")],
        vec![("padding_mode", "buckets"), ("padding_ladder", "64K,4G")],
    ] {
        let r = post(with(&changes)).await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{changes:?} accepted"
        );
    }
    assert_eq!(state.settings.load().claim_window_secs, 900);
    // Any seconds in range are accepted even if not in the dropdown (by SPEC §7.2).
    let r = post(with(&[
        ("claim_window_secs", "61"),
        ("ttl_presets", "61,900,900"),
    ]))
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(state.settings.load().claim_window_secs, 61);
    println!(
        "ttl_presets after posting 61,900,900: {:?}",
        state.settings.load().ttl_presets
    );
    let page = get_with_cookie(&app, "localhost", "/en/admin/settings", &cookie).await;
    assert!(
        page.body.contains(r#"value="61" selected"#),
        "the odd value is offered back"
    );
    // Duplicate / repeated scalar fields are joined with a comma and then refused or harmless.
    let mut dup = with(&[("claim_window_secs", "900")]);
    dup.push(("claim_window_secs".into(), "900".into()));
    let r = post(dup).await;
    println!("repeated claim_window_secs field -> {}", r.status);
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let mut dup = with(&[]);
    dup.push(("csrf".into(), csrf.clone()));
    assert_eq!(
        post(dup).await.status,
        StatusCode::FORBIDDEN,
        "a doubled csrf field"
    );
    // padding_ladder is kept while padme is in use, padding_min while buckets is: a save in
    // the other mode preserves both through the panel.
    let r = post(with(&[
        ("padding_mode", "buckets"),
        ("padding_ladder", "64K,128K"),
        ("padding_min", "128K"),
    ]))
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let s = state.settings.load().as_strings();
    assert_eq!(
        (
            s["padding_mode"].as_str(),
            s["padding_min"].as_str(),
            s["padding_ladder"].as_str()
        ),
        ("buckets", "128K", "64K,128K")
    );
    let r = post(with(&[("padding_mode", "padme")])).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let s = state.settings.load().as_strings();
    assert_eq!(
        (
            s["padding_mode"].as_str(),
            s["padding_min"].as_str(),
            s["padding_ladder"].as_str()
        ),
        ("padme", "128K", "64K,128K")
    );
    let r = post(with(&[("padding_mode", "buckets")])).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        state.settings.load().as_strings()["padding_ladder"],
        "64K,128K"
    );
}

// `{{site_name}}` in the Markdown content pages is substituted into already-rendered HTML,
// so markup in the setting must come out escaped there.
#[tokio::test]
async fn spec_site_name_is_escaped_in_content_pages() {
    let (config, state, _) = parts("routing-sitename", &[], true).await;
    let app = app::router(&config, state.clone());
    let auth = format!("Bearer {ADMIN_KEY}");
    let name = r#"Acme <b data-x="1">bold</b><meta http-equiv="refresh" content="0;url=https://evil.example">"#;
    let body = serde_json::json!({ "site_name": name }).to_string();
    let r = send(
        &app,
        Req {
            host: "localhost",
            method: Method::PATCH,
            path: "/api/v1/admin/settings",
            headers: &[
                ("content-type", "application/json"),
                ("authorization", &auth),
            ],
            body: &body,
        },
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let mut raw = Vec::new();
    for path in [
        "/en/terms",
        "/en/privacy",
        "/en/acceptable-use",
        "/de/terms",
        "/en",
        "/en/admin/login",
    ] {
        let page = get(&app, "localhost", path).await;
        let injected = page.body.contains(r#"<b data-x="1">bold</b>"#)
            || page.body.contains(r#"<meta http-equiv="refresh""#);
        println!("{path}: raw site_name markup present = {injected}");
        if injected {
            raw.push(path);
        }
    }
    assert!(raw.is_empty(), "site_name rendered unescaped on: {raw:?}");
}

// Nothing an admin sets can reach the `data-shh-i18n` JSON strings block, the footer
// version, the `data-shh-*` attributes or the `<template>` elements unescaped.
#[tokio::test]
async fn spec_templates_escape_settings_and_version() {
    let (config, state, _) = parts("routing-escape", &[], true).await;
    let app = app::router(&config, state.clone());
    let auth = format!("Bearer {ADMIN_KEY}");
    let body = serde_json::json!({
        "site_name": "</script><script>alert(1)</script>\"'<x>",
        "regions": [{"code": "x", "name": "<img src=x onerror=alert(1)>", "url": "https://r.example/\" onclick=\"alert(1)"}],
        "source_url": "https://s.example/\"><script>",
        "project_url": "https://p.example/?a=1&b=<x>",
    })
    .to_string();
    let r = send(
        &app,
        Req {
            host: "localhost",
            method: Method::PATCH,
            path: "/api/v1/admin/settings",
            headers: &[
                ("content-type", "application/json"),
                ("authorization", &auth),
            ],
            body: &body,
        },
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    for path in [
        "/en",
        "/en/s",
        "/en/about",
        "/en/how-it-works",
        "/en/admin/login",
        "/en/contact",
    ] {
        let page = get(&app, "localhost", path).await;
        assert_eq!(page.status, StatusCode::OK, "{path}");
        for needle in ["<script>alert(1)", "<img src=x onerror", r#"" onclick="#] {
            if let Some(at) = page.body.find(needle) {
                let from = at.saturating_sub(160);
                let to = (at + 120).min(page.body.len());
                println!("{path}: raw {needle:?} at …{}…", &page.body[from..to]);
            }
            assert!(!page.body.contains(needle), "{path}: {needle}");
        }
        let i18n = page
            .body
            .split("data-shh-i18n>")
            .nth(1)
            .map(|s| s.split("</script>").next().unwrap().to_string())
            .unwrap();
        assert!(!i18n.contains('<'), "{path}: a raw < in the i18n block");
        let parsed: serde_json::Value = serde_json::from_str(&i18n).expect("i18n block is JSON");
        assert!(parsed.as_object().unwrap().len() >= 20);
        assert!(
            !i18n.contains("alert(1)"),
            "{path}: a setting reached the i18n block"
        );
        assert!(
            page.body
                .contains(&format!("shhnote {} · AGPL-3.0", env!("CARGO_PKG_VERSION"))),
            "{path}: footer version"
        );
    }
    let config_json = get(&app, "localhost", "/api/v1/config").await;
    let v: serde_json::Value = serde_json::from_str(&config_json.body).unwrap();
    assert_eq!(v["server_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        v["regions"][0]["name"], "<img src=x onerror=alert(1)>",
        "JSON carries it verbatim, which is correct for JSON"
    );
}

// SPEC §8: sessions, CSRF on every state-changing route, login, bootstrap, and the admin
// API's cookie refusal.
#[tokio::test]
async fn spec_admin_sessions_csrf_and_login() {
    let (config, state, store) = parts("routing-session", &[], false).await;
    let app = app::router(&config, state.clone());
    // Bootstrap login while no admin key exists.
    let boot = login(&app, "localhost", "/en/admin/login", BOOTSTRAP).await;
    assert_eq!(
        get_with_cookie(&app, "localhost", "/en/admin", &boot)
            .await
            .status,
        StatusCode::OK
    );
    let page = get_with_cookie(&app, "localhost", "/en/admin/keys", &boot).await;
    let csrf = csrf_of(&page.body);
    let boot_csrf = csrf.clone();
    // Every POST route without the token: 403 (logout included).
    for route in [
        "/en/admin/settings",
        "/en/admin/keys",
        "/en/admin/keys/delete",
        "/en/admin/keys/sessions",
        "/en/admin/logout",
    ] {
        let r = post_form(
            &app,
            "localhost",
            route,
            &boot,
            &[
                ("name".into(), "x".into()),
                ("scope".into(), "admin".into()),
                ("key_hash".into(), "00".repeat(32)),
            ],
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{route} without csrf");
        let r = post_form(
            &app,
            "localhost",
            route,
            &boot,
            &[
                ("csrf".into(), "wrong".into()),
                ("name".into(), "x".into()),
                ("scope".into(), "admin".into()),
            ],
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{route} wrong csrf");
        // No cookie at all: redirect to login, never an action.
        let r = post_form(
            &app,
            "localhost",
            route,
            "",
            &[
                ("csrf".into(), csrf.clone()),
                ("name".into(), "x".into()),
                ("scope".into(), "admin".into()),
            ],
        )
        .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{route} without cookie");
    }
    assert_eq!(
        store.list_api_keys().await.unwrap().len(),
        0,
        "a CSRF-less POST minted a key"
    );
    // Mint the first admin key through the bootstrap session: redirect to login?new=<nonce>,
    // key shown once, bootstrap session dead.
    let r = post_form(
        &app,
        "localhost",
        "/en/admin/keys",
        &boot,
        &[
            ("csrf".into(), csrf.clone()),
            ("name".into(), "first".into()),
            ("scope".into(), "admin".into()),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let location = r.headers[header::LOCATION].to_str().unwrap().to_string();
    assert!(location.starts_with("/en/admin/login?new="), "{location}");
    assert!(!r.body.contains("data-new-key"));
    let nonce = location.split("?new=").nth(1).unwrap().to_string();
    // Another session cannot take the parked key.
    let r = get(&app, "localhost", &location).await;
    assert!(
        !r.body.contains("data-new-key-value"),
        "the key was handed out without the minting session's cookie"
    );
    let shown = get_with_cookie(&app, "localhost", &location, &boot).await;
    assert!(
        shown.body.contains("data-new-key-value"),
        "the key was not shown to the minting session"
    );
    let key = shown
        .body
        .split("data-new-key-value>")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap()
        .to_string();
    let again = get_with_cookie(&app, "localhost", &location, &boot).await;
    assert!(!again.body.contains("data-new-key-value"), "shown twice");
    assert_eq!(
        get_with_cookie(&app, "localhost", "/en/admin", &boot)
            .await
            .status,
        StatusCode::SEE_OTHER,
        "bootstrap session survived the first key"
    );
    let _ = nonce;
    // The bootstrap credential no longer logs in; the key does; a user key does not.
    let r = post_form(
        &app,
        "localhost",
        "/en/admin/login",
        "",
        &[("credential".into(), BOOTSTRAP.into())],
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let cookie = login(&app, "localhost", "/en/admin/login", &key).await;
    let auth = format!("Bearer {key}");
    let minted = send(
        &app,
        Req {
            host: "localhost",
            method: Method::POST,
            path: "/api/v1/admin/keys",
            headers: &[
                ("content-type", "application/json"),
                ("authorization", &auth),
            ],
            body: r#"{"name":"u","scope":"user"}"#,
        },
    )
    .await;
    let user_key = minted
        .body
        .split(r#""key":""#)
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();
    let r = post_form(
        &app,
        "localhost",
        "/en/admin/login",
        "",
        &[("credential".into(), user_key.clone())],
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let wrong = post_form(
        &app,
        "localhost",
        "/en/admin/login",
        "",
        &[("credential".into(), "nope".into())],
    )
    .await;
    assert_eq!(
        r.body, wrong.body,
        "a failed login reveals whether a key exists"
    );
    // Admin cookie on the admin API: refused; user key on the admin API: refused; `bearer`
    // lowercase: refused; empty: refused.
    for (hdrs, what) in [
        (vec![("cookie", cookie.as_str())], "cookie"),
        (vec![("authorization", "Bearer ")], "empty"),
        (vec![("authorization", "bearer x")], "lowercase scheme"),
    ] {
        let r = send(
            &app,
            Req {
                host: "localhost",
                method: Method::GET,
                path: "/api/v1/admin/stats",
                headers: &hdrs,
                body: "",
            },
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{what}");
        assert_eq!(
            r.headers.get(header::CACHE_CONTROL).map(|v| v.as_bytes()),
            Some(&b"no-store"[..]),
            "{what}"
        );
    }
    let ub = format!("Bearer {user_key}");
    let r = send(
        &app,
        Req {
            host: "localhost",
            method: Method::GET,
            path: "/api/v1/admin/stats",
            headers: &[("authorization", &ub)],
            body: "",
        },
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "user key on admin API");
    // Deleting the key ends its session at once; tampered cookies are refused.
    let page = get_with_cookie(&app, "localhost", "/en/admin/keys", &cookie).await;
    let csrf = csrf_of(&page.body);
    let hash_hex: String = credential_hash(key.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // End sessions first: the session dies, the key still works on the API, then re-login works.
    let r = post_form(
        &app,
        "localhost",
        "/en/admin/keys/sessions",
        &cookie,
        &[
            ("csrf".into(), csrf.clone()),
            ("key_hash".into(), hash_hex.clone()),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        get_with_cookie(&app, "localhost", "/en/admin", &cookie)
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    let r = send(
        &app,
        Req {
            host: "localhost",
            method: Method::GET,
            path: "/api/v1/admin/stats",
            headers: &[("authorization", &auth)],
            body: "",
        },
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    // Revocation is strict to the second: a login in the same second as "end sessions" is dead
    // too (fail closed), so wait one second before logging in again.
    let same_second = login(&app, "localhost", "/en/admin/login", &key).await;
    println!(
        "a session issued in the same second as 'end sessions': {}",
        get_with_cookie(&app, "localhost", "/en/admin", &same_second)
            .await
            .status
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let cookie2 = login(&app, "localhost", "/en/admin/login", &key).await;
    let page = get_with_cookie(&app, "localhost", "/en/admin/keys", &cookie2).await;
    let csrf = csrf_of(&page.body);
    // Old CSRF token (other session) with the new cookie: refused.
    let r = post_form(
        &app,
        "localhost",
        "/en/admin/keys/delete",
        &cookie2,
        &[
            ("csrf".into(), boot_csrf.clone()),
            ("key_hash".into(), hash_hex.clone()),
        ],
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::FORBIDDEN,
        "another session's csrf token"
    );
    let r = post_form(
        &app,
        "localhost",
        "/en/admin/keys/delete",
        &cookie2,
        &[
            ("csrf".into(), csrf.clone()),
            ("key_hash".into(), hash_hex.clone()),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        get_with_cookie(&app, "localhost", "/en/admin", &cookie2)
            .await
            .status,
        StatusCode::SEE_OTHER,
        "deleted key's session lives on"
    );
    let r = send(
        &app,
        Req {
            host: "localhost",
            method: Method::GET,
            path: "/api/v1/admin/stats",
            headers: &[("authorization", &auth)],
            body: "",
        },
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // The last admin key is gone: the bootstrap token works again for a NEW login. What the
    // OLD bootstrap cookie does now is pinned by
    // `spec_bootstrap_session_stays_dead_after_last_admin_key_is_deleted`.
    println!(
        "old bootstrap cookie after the last admin key was deleted through the panel: {}",
        get_with_cookie(&app, "localhost", "/en/admin", &boot)
            .await
            .status
    );
    let fresh_boot = post_form(
        &app,
        "localhost",
        "/en/admin/login",
        "",
        &[("credential".into(), BOOTSTRAP.into())],
    )
    .await;
    println!(
        "bootstrap login after the last admin key was deleted (no reset-admin): {}",
        fresh_boot.status
    );
}

// SPEC §8: a bootstrap session is invalid once any admin key exists and never comes back,
// also when the last admin key is deleted through the panel or the admin API rather than
// by `reset-admin`, while the old cookie is still younger than its 12 h lifetime.
#[tokio::test]
async fn spec_bootstrap_session_stays_dead_after_last_admin_key_is_deleted() {
    for via in ["panel", "api"] {
        let (config, state, store) =
            parts(&format!("routing-bootstrap-revive-{via}"), &[], false).await;
        let app = app::router(&config, state.clone());
        let boot = login(&app, "localhost", "/en/admin/login", BOOTSTRAP).await;
        let page = get_with_cookie(&app, "localhost", "/en/admin/keys", &boot).await;
        let csrf = csrf_of(&page.body);
        let r = post_form(
            &app,
            "localhost",
            "/en/admin/keys",
            &boot,
            &[
                ("csrf".into(), csrf.clone()),
                ("name".into(), "first".into()),
                ("scope".into(), "admin".into()),
            ],
        )
        .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER);
        let location = r.headers[header::LOCATION].to_str().unwrap().to_string();
        let shown = get_with_cookie(&app, "localhost", &location, &boot).await;
        let key = shown
            .body
            .split("data-new-key-value>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_string();
        assert_eq!(
            get_with_cookie(&app, "localhost", "/en/admin", &boot)
                .await
                .status,
            StatusCode::SEE_OTHER,
            "dead once a key exists"
        );
        let hash = credential_hash(key.as_bytes());
        let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        match via {
            "panel" => {
                let cookie = login(&app, "localhost", "/en/admin/login", &key).await;
                let page = get_with_cookie(&app, "localhost", "/en/admin/keys", &cookie).await;
                let csrf = csrf_of(&page.body);
                let r = post_form(
                    &app,
                    "localhost",
                    "/en/admin/keys/delete",
                    &cookie,
                    &[("csrf".into(), csrf), ("key_hash".into(), hash_hex.clone())],
                )
                .await;
                assert_eq!(r.status, StatusCode::SEE_OTHER);
            }
            _ => {
                let auth = format!("Bearer {key}");
                let body = format!(r#"{{"id":"{hash_hex}"}}"#);
                let r = send(
                    &app,
                    Req {
                        host: "localhost",
                        method: Method::POST,
                        path: "/api/v1/admin/keys/delete",
                        headers: &[
                            ("content-type", "application/json"),
                            ("authorization", &auth),
                        ],
                        body: &body,
                    },
                )
                .await;
                assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
            }
        }
        assert_eq!(store.admin_key_count().await.unwrap(), 0);
        let revived = get_with_cookie(&app, "localhost", "/en/admin", &boot).await;
        println!(
            "via {via}: old bootstrap cookie after the last admin key is deleted -> {}",
            revived.status
        );
        assert_eq!(
            revived.status,
            StatusCode::SEE_OTHER,
            "via {via}: the pre-key bootstrap session is accepted again"
        );
    }
}

// Login rate limit: web login refuses even the right credential once limited; the admin API
// consults the bucket before the lookup. Both share the bucket per client.
#[tokio::test]
async fn spec_login_limit_is_shared_and_checked_first() {
    let (config, state, _) = parts("routing-login-limit", &[], true).await;
    let app = app::router(&config, state.clone());
    let mut limited_after = None;
    for i in 0..100 {
        let r = post_form(
            &app,
            "localhost",
            "/en/admin/login",
            "",
            &[("credential".into(), "wrong".into())],
        )
        .await;
        if r.status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(r.headers[header::RETRY_AFTER], "60");
            limited_after = Some(i);
            break;
        }
    }
    let n = limited_after.expect("never limited");
    println!("web login limited after {n} failures (rate_login_per_hour=20)");
    let right = post_form(
        &app,
        "localhost",
        "/en/admin/login",
        "",
        &[("credential".into(), ADMIN_KEY.into())],
    )
    .await;
    assert_eq!(
        right.status,
        StatusCode::TOO_MANY_REQUESTS,
        "right credential while limited"
    );
    // Same client, admin API: the bucket is shared, so a right key is refused too.
    let auth = format!("Bearer {ADMIN_KEY}");
    let r = send(
        &app,
        Req {
            host: "localhost",
            method: Method::GET,
            path: "/api/v1/admin/stats",
            headers: &[("authorization", &auth)],
            body: "",
        },
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::TOO_MANY_REQUESTS,
        "admin API with the right key while the client is limited"
    );
    assert_eq!(r.headers[header::RETRY_AFTER], "60");
}

// SPEC §8: `shhnote init --env` succeeds on lines with spaces around `=` or an `export`
// prefix. Prints what counts as "set" and which definition `check` reads (--nocapture).
#[test]
fn spec_init_env_handles_spaced_and_exported_lines() {
    use std::{fs, process::Command};
    let dir = std::env::temp_dir().join(format!("shhnote-routing-init-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let env = dir.join("env");
    fs::write(&env, "SHH_ENV=production\nSHH_SECRET_KEY = keep-this-value-it-is-long-enough-for-sure\nexport SHH_ADMIN_TOKEN=also-keep-this-one-it-is-long-enough-too\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_shhnote"))
        .env_clear()
        .current_dir(&dir)
        .args(["init", "--env", env.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = String::from_utf8_lossy(&out.stdout).to_string();
    let written = fs::read_to_string(&env).unwrap();
    println!(
        "init report:\n{report}\nfile now has {} SHH_SECRET_KEY lines and {} SHH_ADMIN_TOKEN lines",
        written.matches("SHH_SECRET_KEY").count(),
        written.matches("SHH_ADMIN_TOKEN").count()
    );
    // Which definition does the server read? `check` with the file as .env tells: the
    // original admin token is long enough, so if the appended one wins nothing is visible;
    // use a too-short original instead to see who wins.
    let env2 = dir.join(".env");
    fs::write(&env2, format!("SHH_ENV=local\nSHH_URL=http://localhost:3000\nSHH_DB=sqlite\nSHH_SQLITE_PATH={}\nSHH_SECRET_KEY={}\nSHH_ADMIN_TOKEN = short\n", dir.join("db.sqlite").display(), "s".repeat(44))).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_shhnote"))
        .env_clear()
        .current_dir(&dir)
        .args(["init", "--env", env2.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let after = fs::read_to_string(&env2).unwrap();
    let check = Command::new(env!("CARGO_BIN_EXE_shhnote"))
        .env_clear()
        .current_dir(&dir)
        .arg("check")
        .output()
        .unwrap();
    println!(
        "file:\n{}\ncheck: status={} stdout={} stderr={}",
        after.replace(&"s".repeat(44), "<key>"),
        check.status,
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    let _ = fs::remove_dir_all(&dir);
}

// --- helpers

async fn login(app: &Router, host: &str, path: &str, credential: &str) -> String {
    let r = post_form(
        app,
        host,
        path,
        "",
        &[("credential".into(), credential.into())],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    r.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn get_with_cookie(app: &Router, host: &str, path: &str, cookie: &str) -> Seen {
    send(
        app,
        Req {
            host,
            method: Method::GET,
            path,
            headers: &[("cookie", cookie)],
            body: "",
        },
    )
    .await
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

async fn post_form(
    app: &Router,
    host: &str,
    path: &str,
    cookie: &str,
    fields: &[(String, String)],
) -> Seen {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut headers: Vec<(&str, &str)> =
        vec![("content-type", "application/x-www-form-urlencoded")];
    if !cookie.is_empty() {
        headers.push(("cookie", cookie));
    }
    send(
        app,
        Req {
            host,
            method: Method::POST,
            path,
            headers: &headers,
            body: &body,
        },
    )
    .await
}

fn csrf_of(html: &str) -> String {
    let start =
        html.find("name=\"csrf\" value=\"").expect("csrf field") + "name=\"csrf\" value=\"".len();
    let end = html[start..].find('"').unwrap();
    html[start..start + end].to_string()
}
