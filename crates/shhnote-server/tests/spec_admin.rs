// Regression tests from the security review (docs/security-review/findings/SUMMARY.md) for
// admin sessions, CSRF, login, the admin JSON API and settings validation (SPEC §8). Ignored
// tests are waiting for the step that fixes their finding; un-ignore them with the fix.

use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use shhnote_core::{config::Config, settings::Settings};
use shhnote_server::{api::ApiState, app};
use shhnote_store::{Store, sqlite_path_for_tests};
use tower::ServiceExt;

const BOOTSTRAP: &str = "spec-admin-bootstrap-token-of-at-least-32-ch";
const OTHER_TOKEN: &str = "another-bootstrap-token-of-at-least-32-ch";

fn config(token: &str) -> Config {
    let vars: HashMap<String, String> = [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
        ("SHH_ADMIN_TOKEN", token),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    Config::from_vars(&vars).unwrap()
}

async fn build(name: &str) -> (Router, Store) {
    let config = config(BOOTSTRAP);
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

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
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

fn request(
    method: Method,
    path: &str,
    cookie: &str,
    auth: Option<&str>,
    content_type: Option<&str>,
    body: Vec<u8>,
    ip: &str,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost");
    if !cookie.is_empty() {
        b = b.header(header::COOKIE, cookie);
    }
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, a);
    }
    if let Some(ct) = content_type {
        b = b.header(header::CONTENT_TYPE, ct);
    }
    let mut req = b.body(Body::from(body)).unwrap();
    let addr: SocketAddr = format!("{ip}:40000").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    req
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

async fn get(app: &Router, path: &str, cookie: &str) -> Reply {
    send(
        app,
        request(Method::GET, path, cookie, None, None, vec![], "192.0.2.1"),
    )
    .await
}

async fn post_form(app: &Router, path: &str, cookie: &str, fields: &[(&str, &str)]) -> Reply {
    post_form_from(app, path, cookie, fields, "192.0.2.1").await
}

async fn post_form_from(
    app: &Router,
    path: &str,
    cookie: &str,
    fields: &[(&str, &str)],
    ip: &str,
) -> Reply {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    send(
        app,
        request(
            Method::POST,
            path,
            cookie,
            None,
            Some("application/x-www-form-urlencoded"),
            body.into_bytes(),
            ip,
        ),
    )
    .await
}

async fn admin_api(
    app: &Router,
    method: Method,
    path: &str,
    auth: &str,
    body: Option<Value>,
) -> Reply {
    let (ct, bytes) = match body {
        Some(v) => (Some("application/json"), v.to_string().into_bytes()),
        None => (None, vec![]),
    };
    send(
        app,
        request(
            method,
            &format!("/api/v1/admin{path}"),
            "",
            Some(auth),
            ct,
            bytes,
            "192.0.2.50",
        ),
    )
    .await
}

fn cookie_of(reply: &Reply) -> String {
    reply.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn csrf_of(page: &Reply) -> String {
    let text = page.text();
    let start = text.find("name=\"csrf\" value=\"").unwrap() + "name=\"csrf\" value=\"".len();
    let end = text[start..].find('"').unwrap();
    text[start..start + end].to_string()
}

async fn login(app: &Router, credential: &str) -> String {
    let reply = post_form(app, "/en/admin/login", "", &[("credential", credential)]).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text());
    cookie_of(&reply)
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

async fn mint(app: &Router, auth: &str, scope: &str) -> String {
    let reply = admin_api(
        app,
        Method::POST,
        "/keys",
        auth,
        Some(json!({"name": format!("spec-{scope}"), "scope": scope})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.text());
    reply.json()["key"].as_str().unwrap().to_string()
}

// --- sessions

// SPEC §8: the session MAC covers every field, and a rotated SHH_SECRET_KEY ends every session.
#[tokio::test]
async fn spec_tampered_and_foreign_cookies_are_rejected() {
    let (app, _) = build("spec-admin-tamper").await;
    let cookie = login(&app, BOOTSTRAP).await;
    assert_eq!(get(&app, "/en/admin", &cookie).await.status, StatusCode::OK);

    let value = cookie.strip_prefix("shh_admin=").unwrap();
    let (payload, tag) = value.split_once('.').unwrap();
    let mut bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
    // Push the expiry (bytes 33..41) a year into the future, keep the old tag.
    let expires = i64::from_be_bytes(bytes[33..41].try_into().unwrap()) + 365 * 86_400;
    bytes[33..41].copy_from_slice(&expires.to_be_bytes());
    let forged = format!("shh_admin={}.{tag}", URL_SAFE_NO_PAD.encode(&bytes));
    assert_eq!(
        get(&app, "/en/admin", &forged).await.status,
        StatusCode::SEE_OTHER
    );
    // Flip the bootstrap flag off: also rejected.
    let mut flipped = URL_SAFE_NO_PAD.decode(payload).unwrap();
    flipped[0] ^= 1;
    let forged = format!("shh_admin={}.{tag}", URL_SAFE_NO_PAD.encode(&flipped));
    assert_eq!(
        get(&app, "/en/admin", &forged).await.status,
        StatusCode::SEE_OTHER
    );
    for junk in [
        "shh_admin=",
        "shh_admin=.",
        "shh_admin=a.b",
        "shh_admin=%%%.%%%",
        "shh_admin_x=1",
    ] {
        assert_eq!(
            get(&app, "/en/admin", junk).await.status,
            StatusCode::SEE_OTHER,
            "{junk}"
        );
    }
    // A cookie signed under a different SHH_SECRET_KEY is refused.
    let mut vars: HashMap<String, String> = HashMap::new();
    for (k, v) in [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_DB", "sqlite"),
        ("SHH_ADMIN_TOKEN", BOOTSTRAP),
    ] {
        vars.insert(k.into(), v.into());
    }
    vars.insert("SHH_SECRET_KEY".into(), "t".repeat(44));
    let rotated = Config::from_vars(&vars).unwrap();
    let path = sqlite_path_for_tests("spec-admin-tamper");
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let app2 = app::router(
        &rotated,
        ApiState::new(store, Settings::default(), &rotated, None),
    );
    assert_eq!(
        get(&app2, "/en/admin", &cookie).await.status,
        StatusCode::SEE_OTHER
    );
}

// SPEC §8: HttpOnly, SameSite=Strict, 12 hours (Secure is added in production).
#[tokio::test]
async fn spec_session_cookie_attributes() {
    let (app, _) = build("spec-admin-cookie").await;
    let reply = post_form(&app, "/en/admin/login", "", &[("credential", BOOTSTRAP)]).await;
    let set = reply.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    for attr in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=43200"] {
        assert!(set.contains(attr), "{attr} missing from {set}");
    }
}

// SPEC §8: logout requires the CSRF token.
#[tokio::test]
#[ignore = "S-40"]
async fn spec_logout_requires_csrf() {
    let (app, _) = build("spec-admin-logout-csrf").await;
    let cookie = login(&app, BOOTSTRAP).await;
    let reply = post_form(&app, "/en/admin/logout", &cookie, &[]).await;
    assert_eq!(
        reply.status,
        StatusCode::FORBIDDEN,
        "logout without csrf was accepted: {}",
        reply.status
    );
}

// SPEC §8: a bootstrap session is invalid once any admin key exists, and `reset-admin` does
// not revive it.
#[tokio::test]
#[ignore = "S-39"]
async fn spec_bootstrap_session_does_not_come_back() {
    let (app, store) = build("spec-admin-bootstrap-revive").await;
    let old = login(&app, BOOTSTRAP).await;
    let admin_key = mint(&app, &bearer(BOOTSTRAP), "admin").await;
    assert_eq!(
        get(&app, "/en/admin", &old).await.status,
        StatusCode::SEE_OTHER
    );
    // What `shhnote reset-admin` does.
    store.delete_admin_keys().await.unwrap();
    let _ = admin_key;
    let revived = get(&app, "/en/admin", &old).await;
    assert_eq!(
        revived.status,
        StatusCode::SEE_OTHER,
        "pre-key bootstrap cookie accepted again"
    );
}

// SPEC §8: a bootstrap session is bound to the hash of the token that created it.
#[tokio::test]
#[ignore = "S-39"]
async fn spec_bootstrap_cookie_dies_with_token_rotation() {
    let name = "spec-admin-token-rotation";
    let (app, _) = build(name).await;
    let cookie = login(&app, BOOTSTRAP).await;
    // Same database and SHH_SECRET_KEY, but the operator changed SHH_ADMIN_TOKEN.
    let rotated = config(OTHER_TOKEN);
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let app2 = app::router(
        &rotated,
        ApiState::new(store, Settings::default(), &rotated, None),
    );
    let reply = get(&app2, "/en/admin", &cookie).await;
    assert_eq!(
        reply.status,
        StatusCode::SEE_OTHER,
        "cookie for the old token still works"
    );
}

// SPEC §8: every admin response carries `Cache-Control: no-store`, the page that shows a new
// key most of all.
#[tokio::test]
#[ignore = "S-18"]
async fn spec_admin_pages_are_no_store() {
    let (app, _) = build("spec-admin-cache").await;
    let cookie = login(&app, BOOTSTRAP).await;
    let csrf = csrf_of(&get(&app, "/en/admin/keys", &cookie).await);
    let created = post_form(
        &app,
        "/en/admin/keys",
        &cookie,
        &[("csrf", &csrf), ("name", "cache-test"), ("scope", "user")],
    )
    .await;
    assert!(created.status.is_success() || created.status.is_redirection());
    let mut missing = Vec::new();
    if created
        .headers
        .get(header::CACHE_CONTROL)
        .is_none_or(|v| v != "no-store")
    {
        missing.push("POST /en/admin/keys".to_string());
    }
    for page in [
        "/en/admin",
        "/en/admin/settings",
        "/en/admin/keys",
        "/en/admin/login",
    ] {
        let r = get(&app, page, &cookie).await;
        if r.headers
            .get(header::CACHE_CONTROL)
            .is_none_or(|v| v != "no-store")
        {
            missing.push(page.to_string());
        }
    }
    let unauth = admin_api(&app, Method::GET, "/stats", "Bearer nope", None).await;
    if unauth
        .headers
        .get(header::CACHE_CONTROL)
        .is_none_or(|v| v != "no-store")
    {
        missing.push(format!("GET /api/v1/admin/stats ({})", unauth.status));
    }
    assert!(
        missing.is_empty(),
        "no `Cache-Control: no-store` on:\n{}",
        missing.join("\n")
    );
}

// --- CSRF on every state-changing panel route

// SPEC §8: every state-changing panel route checks the CSRF token, bound to its session.
#[tokio::test]
async fn spec_csrf_checked_on_settings_and_keys() {
    let (app, store) = build("spec-admin-csrf").await;
    let cookie = login(&app, BOOTSTRAP).await;
    for (path, fields) in [
        ("/en/admin/settings", vec![("site_name", "pwned")]),
        ("/en/admin/keys", vec![("name", "x"), ("scope", "admin")]),
        ("/en/admin/keys/delete", vec![("key_hash", "00")]),
    ] {
        let no = post_form(&app, path, &cookie, &fields).await;
        assert_eq!(no.status, StatusCode::FORBIDDEN, "{path} without csrf");
        let mut wrong = fields.clone();
        wrong.push(("csrf", "AAAA"));
        let bad = post_form(&app, path, &cookie, &wrong).await;
        assert_eq!(bad.status, StatusCode::FORBIDDEN, "{path} wrong csrf");
    }
    // A CSRF token from another session does not work.
    let other = login(&app, BOOTSTRAP).await;
    let other_csrf = csrf_of(&get(&app, "/en/admin", &other).await);
    let r = post_form(
        &app,
        "/en/admin/keys",
        &cookie,
        &[("csrf", &other_csrf), ("name", "x"), ("scope", "admin")],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(store.admin_key_count().await.unwrap(), 0);
}

// --- login

// SPEC §8: a failed login does not say whether a key exists, and the web login consults the
// bucket before the credential.
#[tokio::test]
async fn spec_login_failures_look_alike_and_are_limited() {
    let (app, _) = build("spec-admin-login").await;
    let user_key = mint(&app, &bearer(BOOTSTRAP), "user").await;
    let a = post_form_from(
        &app,
        "/en/admin/login",
        "",
        &[("credential", "nope")],
        "198.51.100.1",
    )
    .await;
    let b = post_form_from(
        &app,
        "/en/admin/login",
        "",
        &[("credential", &user_key)],
        "198.51.100.2",
    )
    .await;
    assert_eq!(a.status, b.status);
    assert_eq!(
        a.text(),
        b.text(),
        "user key and unknown key fail identically"
    );
    let mut last = StatusCode::OK;
    for _ in 0..25 {
        last = post_form_from(
            &app,
            "/en/admin/login",
            "",
            &[("credential", "nope")],
            "198.51.100.3",
        )
        .await
        .status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    let right = post_form_from(
        &app,
        "/en/admin/login",
        "",
        &[("credential", BOOTSTRAP)],
        "198.51.100.3",
    )
    .await;
    assert_eq!(right.status, StatusCode::TOO_MANY_REQUESTS);
}

// SPEC §8: the admin API consults the login bucket before the lookup, so a limited client
// gets no answer for a right guess either.
#[tokio::test]
#[ignore = "S-41"]
async fn spec_admin_api_limit_blocks_guessing() {
    let (app, _) = build("spec-admin-api-limit").await;
    let mut statuses = Vec::new();
    for _ in 0..25 {
        statuses.push(
            admin_api(&app, Method::GET, "/stats", "Bearer wrong-guess", None)
                .await
                .status,
        );
    }
    assert_eq!(*statuses.last().unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let right = admin_api(&app, Method::GET, "/stats", &bearer(BOOTSTRAP), None).await;
    assert_eq!(
        right.status,
        StatusCode::TOO_MANY_REQUESTS,
        "guessing is not blocked while limited"
    );
}

// --- admin API authentication

// SPEC §8: Bearer only, admin scope only, no cookies on the admin API, and the bootstrap token
// retires with the first admin key.
#[tokio::test]
async fn spec_bearer_parsing_and_scopes() {
    let (app, _) = build("spec-admin-bearer").await;
    let user_key = mint(&app, &bearer(BOOTSTRAP), "user").await;
    for value in [
        "Bearer".to_string(),
        "Bearer ".to_string(),
        format!("Basic {BOOTSTRAP}"),
        BOOTSTRAP.to_string(),
    ] {
        let r = admin_api(&app, Method::GET, "/stats", &value, None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{value:?}");
    }
    let r = admin_api(&app, Method::GET, "/stats", &bearer(&user_key), None).await;
    assert_eq!(
        r.status,
        StatusCode::UNAUTHORIZED,
        "user key on admin route"
    );
    // An admin key on a user route is treated as anonymous: it works but gets no special limit.
    let admin_key = mint(&app, &bearer(BOOTSTRAP), "admin").await;
    let reveal = send(
        &app,
        request(
            Method::POST,
            "/api/v1/secrets/reveal",
            "",
            Some(&bearer(&admin_key)),
            Some("application/json"),
            json!({"lookup": "x"}).to_string().into_bytes(),
            "192.0.2.77",
        ),
    )
    .await;
    assert_eq!(reveal.status, StatusCode::NOT_FOUND);
    // The bootstrap token stops working on the API once an admin key exists.
    let r = admin_api(&app, Method::GET, "/stats", &bearer(BOOTSTRAP), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Admin cookies are not accepted by the admin API (so it needs no CSRF token).
    let cookie = login(&app, &admin_key).await;
    let r = send(
        &app,
        request(
            Method::GET,
            "/api/v1/admin/stats",
            &cookie,
            None,
            None,
            vec![],
            "192.0.2.78",
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

// CLAUDE.md: no reachable panic in a handler; a non-ASCII key id is a plain client error.
#[tokio::test]
#[ignore = "S-29"]
async fn spec_admin_key_delete_does_not_panic_on_non_ascii() {
    let (app, _) = build("spec-admin-unhex").await;
    // "0é…": the 2-byte slice at 0..2 ends inside the 'é'.
    let id = format!("0é{}", "0".repeat(61));
    assert_eq!(id.len(), 64);
    let req = request(
        Method::POST,
        "/api/v1/admin/keys/delete",
        "",
        Some(&bearer(BOOTSTRAP)),
        Some("application/json"),
        json!({ "id": id }).to_string().into_bytes(),
        "192.0.2.60",
    );
    let outcome = tokio::spawn(app.clone().oneshot(req)).await;
    let res = outcome.expect("handler panicked").unwrap();
    assert!(res.status().is_client_error(), "{}", res.status());
}

// --- settings validation

// SPEC §7.2: every setting is range-checked as a whole.
#[tokio::test]
#[ignore = "S-10"]
async fn spec_settings_patch_rejects_values_that_break_the_instance() {
    let (app, _) = build("spec-admin-settings").await;
    let auth = bearer(BOOTSTRAP);
    let bad: Vec<(&str, Value)> = vec![
        ("padding_min", json!(0)),
        ("padding_min", json!(1)),
        ("padding_mode/ladder", json!(null)),
        ("claim_window_secs", json!(-1)),
        ("claim_window_secs", json!(0)),
        ("claim_window_secs", json!(i64::MAX)),
        ("min_ttl_secs", json!(-100)),
        ("ttl_presets", json!([30 * 86_400])),
        ("ttl_presets", json!([-5])),
        ("max_ttl_secs", json!(30 * 86_400)),
        ("text_max_bytes", json!(u64::MAX)),
        ("text_max_bytes", json!(0)),
        ("rate_user_multiplier", json!(u32::MAX)),
        ("rate_user_multiplier", json!(0)),
        ("salt_rotation_secs", json!(-1)),
        ("daily_retention_days", json!(i64::MAX)),
        (
            "regions",
            json!(r#"[{"code":"x","name":"X","url":"javascript:alert(1)"}]"#),
        ),
        ("source_url", json!("javascript:alert(1)")),
        ("contact_email", json!("a@b.c\"><x")),
    ];
    let mut accepted = Vec::new();
    for (key, value) in bad {
        let body = if key == "padding_mode/ladder" {
            json!({"padding_mode": "buckets", "padding_ladder": "0,1,5"})
        } else {
            json!({ key: value })
        };
        let r = admin_api(&app, Method::PATCH, "/settings", &auth, Some(body.clone())).await;
        if r.status.is_success() {
            let stored = &r.json()["values"];
            accepted.push(format!(
                "{body} stored as {}",
                stored
                    .get(key.split('/').next().unwrap())
                    .unwrap_or(&Value::Null)
            ));
        }
        // Back to defaults for the next case.
        let reset: serde_json::Map<String, Value> = [
            "padding_min",
            "padding_mode",
            "padding_ladder",
            "claim_window_secs",
            "min_ttl_secs",
            "ttl_presets",
            "max_ttl_secs",
            "text_max_bytes",
            "rate_user_multiplier",
            "salt_rotation_secs",
            "daily_retention_days",
            "regions",
            "source_url",
            "contact_email",
        ]
        .iter()
        .map(|k| (k.to_string(), Value::Null))
        .collect();
        let r = admin_api(
            &app,
            Method::PATCH,
            "/settings",
            &auth,
            Some(Value::Object(reset)),
        )
        .await;
        assert!(r.status.is_success());
    }
    assert!(accepted.is_empty(), "accepted:\n{}", accepted.join("\n"));
}

// SPEC §11: every settings value is escaped where it is rendered.
#[tokio::test]
async fn spec_settings_markup_is_escaped_in_pages() {
    let (app, _) = build("spec-admin-render").await;
    let auth = bearer(BOOTSTRAP);
    let r = admin_api(
        &app,
        Method::PATCH,
        "/settings",
        &auth,
        Some(json!({
            "site_name": "<script>alert(1)</script>\"'&",
            "regions": r#"[{"code":"eu","name":"<b>EU</b>","url":"https://eu.example.com"}]"#,
        })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let home = get(&app, "/en", "").await.text();
    assert!(!home.contains("<script>alert"));
    assert!(!home.contains("<b>EU</b>"));
    let settings_page = get(&app, "/en/admin/settings", &login(&app, BOOTSTRAP).await)
        .await
        .text();
    assert!(!settings_page.contains("<script>alert(1)</script>"));
}

// SPEC §7.2: region and source URLs are https:// only (http:// when SHH_ENV is local), so no
// javascript: or data: link ever reaches a page.
#[tokio::test]
#[ignore = "S-42"]
async fn spec_settings_refuse_non_http_urls() {
    let (app, _) = build("spec-admin-urls").await;
    let auth = bearer(BOOTSTRAP);
    for body in [
        json!({"source_url": "javascript:alert(document.domain)"}),
        json!({"regions": r#"[{"code":"eu","name":"EU","url":"javascript:alert(1)"}]"#}),
        json!({"regions": r#"[{"code":"us","name":"US","url":"data:text/html,<script>alert(1)</script>"}]"#}),
        json!({"contact_email": "x\"><img src=x onerror=alert(1)>@e.com"}),
    ] {
        let r = admin_api(&app, Method::PATCH, "/settings", &auth, Some(body.clone())).await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{body} was accepted"
        );
    }
    let home = get(&app, "/en", "").await.text();
    assert!(!home.contains("href=\"javascript:"));
    assert!(!home.contains("href=\"data:"));
}

// SPEC §8: key creation answers with a redirect and a one-time nonce, so replaying the POST
// (what a browser refresh does) mints nothing.
#[tokio::test]
#[ignore = "S-43"]
async fn spec_key_create_resubmit_mints_nothing() {
    let (app, store) = build("spec-admin-prg").await;
    let cookie = login(&app, BOOTSTRAP).await;
    let csrf = csrf_of(&get(&app, "/en/admin/keys", &cookie).await);
    let fields = [("csrf", csrf.as_str()), ("name", "dup"), ("scope", "user")];
    let a = post_form(&app, "/en/admin/keys", &cookie, &fields).await;
    assert_eq!(a.status, StatusCode::SEE_OTHER, "{}", a.text());
    let b = post_form(&app, "/en/admin/keys", &cookie, &fields).await;
    assert!(!b.status.is_success() || !b.text().contains("data-new-key-value"));
    let keys = store.list_api_keys().await.unwrap();
    assert_eq!(keys.len(), 1, "a replayed POST minted a second key");
}
