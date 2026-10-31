// Regression tests from the security review (docs/security-review/findings/SUMMARY.md) for
// the web layer: walks every route in-process and checks the headers, inline markup, assets
// and redirects SPEC §10/§11 require. Ignored tests are waiting for the step that fixes their
// finding; un-ignore them with the fix.

use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use shhnote_core::{config::Config, settings::Settings};
use shhnote_server::{api::ApiState, app};
use shhnote_store::{Store, sqlite_path_for_tests};
use tower::ServiceExt;

const BOOTSTRAP: &str = "spec-web-bootstrap-token-of-at-least-32-char";

async fn build(name: &str, extra: &[(&str, &str)]) -> Router {
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
    app::router(
        &config,
        ApiState::new(store, Settings::default(), &config, None),
    )
}

struct Seen {
    label: String,
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

async fn fetch(
    app: &Router,
    host: &str,
    method: Method,
    path: &str,
    content_type: Option<&str>,
    auth: Option<&str>,
    body: &str,
) -> Seen {
    let mut req = Request::builder()
        .method(method.clone())
        .uri(path)
        .header(header::HOST, host);
    if let Some(ct) = content_type {
        req = req.header(header::CONTENT_TYPE, ct);
    }
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    let mut req = req.body(Body::from(body.to_string())).unwrap();
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
        label: format!("{method} {host}{path}"),
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

const REQUIRED: &[&str] = &[
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
];

// Every page, asset, API endpoint and error the path-routed app answers.
async fn walk(app: &Router, host: &str, api: &str) -> Vec<Seen> {
    let mut seen = Vec::new();
    let pages = [
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
    ];
    for locale in ["en", "de"] {
        for page in pages {
            seen.push(
                fetch(
                    app,
                    host,
                    Method::GET,
                    &format!("/{locale}{page}"),
                    None,
                    None,
                    "",
                )
                .await,
            );
        }
    }
    for asset in [
        "/static/app.css?v=x",
        "/static/app.js?v=x",
        "/static/shh.js",
        "/static/argon2.wasm",
        "/static/fonts/inter.woff2",
        "/static/fonts/inter-italic.woff2",
        "/static/nope.js",
        "/static/../Cargo.toml",
    ] {
        seen.push(fetch(app, host, Method::GET, asset, None, None, "").await);
    }
    // Locale redirect, trailing-slash redirect, 405, a POST without CSRF.
    seen.push(fetch(app, host, Method::GET, "/s", None, None, "").await);
    seen.push(fetch(app, host, Method::GET, "/", None, None, "").await);
    seen.push(fetch(app, host, Method::GET, "/en/", None, None, "").await);
    seen.push(fetch(app, host, Method::POST, "/en/terms", None, None, "").await);
    seen.push(
        fetch(
            app,
            host,
            Method::POST,
            "/en/admin/logout",
            Some("application/x-www-form-urlencoded"),
            None,
            "",
        )
        .await,
    );
    // API.
    let json = Some("application/json");
    for (method, path, ct, body) in [
        (Method::GET, "", None, ""),
        (Method::GET, "/config", None, ""),
        (Method::GET, "/health", None, ""),
        (Method::GET, "/secrets", None, ""),
        (Method::POST, "/secrets/reveal", json, r#"{"lookup":"x"}"#),
        (Method::POST, "/secrets/reveal", json, "not json"),
        (
            Method::POST,
            "/secrets/confirm",
            json,
            r#"{"lookup":"x","claim_token":"y"}"#,
        ),
        (Method::POST, "/secrets/burn", json, r#"{"burn_token":"x"}"#),
        (Method::POST, "/reports", json, r#"{"lookup":"x"}"#),
        (Method::GET, "/admin/stats", None, ""),
        (Method::GET, "/nope", None, ""),
    ] {
        seen.push(fetch(app, host, method, &format!("{api}{path}"), ct, None, body).await);
    }
    let bearer = format!("Bearer {BOOTSTRAP}");
    seen.push(
        fetch(
            app,
            host,
            Method::GET,
            &format!("{api}/admin/settings"),
            None,
            Some(&bearer),
            "",
        )
        .await,
    );
    seen
}

fn missing_headers(seen: &[Seen], hsts: bool) -> Vec<String> {
    seen.iter()
        .flat_map(|s| {
            let mut m: Vec<String> = REQUIRED
                .iter()
                .filter(|n| !s.headers.contains_key(**n))
                .map(|n| format!("{} lacks {n}", s.label))
                .collect();
            if hsts && !s.headers.contains_key("strict-transport-security") {
                m.push(format!("{} lacks hsts", s.label));
            }
            m
        })
        .collect()
}

// SPEC §11: the security headers are on every response, API, redirect and error included.
#[tokio::test]
#[ignore = "S-25"]
async fn spec_every_response_has_the_security_headers() {
    let app = build("spec-web-headers-spec", &[]).await;
    let seen = walk(&app, "localhost", "/api/v1").await;
    let missing = missing_headers(&seen, false);
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

// SPEC §11: HSTS and the other headers on every production response, the API subdomain included.
#[tokio::test]
#[ignore = "S-25"]
async fn spec_hsts_on_every_production_response() {
    let app = build(
        "spec-web-headers-hsts",
        &[
            ("SHH_ENV", "production"),
            ("SHH_URL", "https://example.com"),
            ("SHH_API_ROUTING", "subdomain"),
        ],
    )
    .await;
    let mut seen = walk(&app, "example.com", "/nope-not-api").await;
    for path in ["/v1", "/v1/config", "/v1/health", "/v1/nope", "/v1/", "/"] {
        seen.push(fetch(&app, "api.example.com", Method::GET, path, None, None, "").await);
    }
    seen.push(
        fetch(
            &app,
            "api.example.com",
            Method::POST,
            "/v1/secrets/reveal",
            Some("application/json"),
            None,
            r#"{"lookup":"x"}"#,
        )
        .await,
    );
    let missing = missing_headers(&seen, true);
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

// Finds `style="…"`, `<style`, `on…=` handlers and inline `<script>` without `src` other
// than the JSON i18n block.
fn inline_problems(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = html.to_ascii_lowercase();
    for (i, _) in lower.match_indices(" style=") {
        out.push(lower[i..(i + 40).min(lower.len())].to_string());
    }
    if lower.contains("<style") {
        out.push("<style> element".into());
    }
    for (i, _) in lower.match_indices("<script") {
        let tag_end = lower[i..].find('>').map_or(lower.len(), |e| i + e);
        let tag = &lower[i..tag_end];
        if !tag.contains(" src=") && !tag.contains("application/json") {
            out.push(tag.to_string());
        }
    }
    for attr in [
        " onclick=",
        " onload=",
        " onerror=",
        " onsubmit=",
        " onchange=",
    ] {
        if lower.contains(attr) {
            out.push(attr.to_string());
        }
    }
    out
}

// SPEC §10/§11: no inline scripts or styles anywhere.
#[tokio::test]
#[ignore = "S-38"]
async fn spec_no_inline_styles_or_scripts_on_any_page() {
    let app = build("spec-web-inline", &[]).await;
    let bearer_free = walk(&app, "localhost", "/api/v1").await;
    // Admin pages need a session; log in with the bootstrap token.
    let login = fetch(
        &app,
        "localhost",
        Method::POST,
        "/en/admin/login",
        Some("application/x-www-form-urlencoded"),
        None,
        &format!("credential={BOOTSTRAP}"),
    )
    .await;
    let cookie = login.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let mut problems = Vec::new();
    for s in &bearer_free {
        let is_html = s
            .headers
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v.to_str().unwrap_or("").starts_with("text/html"));
        if is_html {
            for p in inline_problems(&s.body) {
                problems.push(format!("{}: {p}", s.label));
            }
        }
    }
    for page in ["/en/admin", "/en/admin/settings", "/en/admin/keys"] {
        let req = Request::get(page)
            .header(header::HOST, "localhost")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{page}");
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        for p in inline_problems(&String::from_utf8_lossy(&body)) {
            problems.push(format!("GET {page}: {p}"));
        }
    }
    problems.sort();
    problems.dedup();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

// SPEC §10/§11: content types, path traversal, the locale redirect and hostile Accept-Language.
#[tokio::test]
async fn spec_assets_redirects_and_accept_language() {
    let app = build("spec-web-assets", &[]).await;
    let wasm = fetch(
        &app,
        "localhost",
        Method::GET,
        "/static/argon2.wasm?v=anything",
        None,
        None,
        "",
    )
    .await;
    assert_eq!(wasm.status, StatusCode::OK);
    assert_eq!(wasm.headers[header::CONTENT_TYPE], "application/wasm");
    for path in [
        "/static/../Cargo.toml",
        "/static/%2e%2e/Cargo.toml",
        "/static/app.js/..",
        "/static//etc/passwd",
    ] {
        let s = fetch(&app, "localhost", Method::GET, path, None, None, "").await;
        assert!(!s.body.contains("[package]"), "{path}");
    }

    let send = |al: String, path: &'static str| {
        let app = app.clone();
        async move {
            let req = Request::get(path)
                .header(header::HOST, "localhost")
                .header(header::ACCEPT_LANGUAGE, al)
                .body(Body::empty())
                .unwrap();
            app.oneshot(req).await.unwrap()
        }
    };
    let long = "x-".repeat(30_000) + ",de;q=0.9";
    for al in [
        long,
        "de;q=NaN,en;q=0.1".to_string(),
        "de;q=inf".to_string(),
        "de,de,de,de;q=2".to_string(),
        ";;;,,,;q=,".to_string(),
    ] {
        let res = send(al.clone(), "/s").await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        let loc = res.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string();
        assert!(loc == "/en/s" || loc == "/de/s", "{loc}");
    }
    for path in [
        "//evil.com",
        "/\\evil.com",
        "/de//evil.com",
        "/en/..//evil.com",
        "/%2F%2Fevil.com",
        "/s?next=//evil.com",
    ] {
        let req = Request::get(path)
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let loc = res
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap().to_string());
        if let Some(loc) = loc {
            assert!(
                loc.starts_with('/') && !loc.starts_with("//") && !loc.starts_with("/\\"),
                "{loc}"
            );
        }
    }
}
