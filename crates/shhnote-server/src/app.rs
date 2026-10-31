use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
};
use shhnote_core::config::{ApiRouting, Config};
use tower::ServiceExt;

use crate::{
    api::{self, ApiState},
    drain::{self, Drain},
    web,
};

pub fn router(config: &Config, state: ApiState) -> Router {
    with_headers(core(config, state), config)
}

// The same router with the drain middleware inside the header layer, so even its
// "shutting down" answer carries the SPEC §11 headers.
pub fn router_with_drain(config: &Config, state: ApiState, drain: Arc<Drain>) -> Router {
    let tracked = core(config, state).layer(middleware::from_fn_with_state(drain, drain::track));
    with_headers(tracked, config)
}

// Headers on every response: pages, API, redirects, errors (SPEC §11). Outermost, so no
// route and no middleware answers without them.
fn with_headers(router: Router, config: &Config) -> Router {
    router.layer(middleware::map_response_with_state(
        web::SecurityHeaders::from_config(config),
        web::security_headers,
    ))
}

fn core(config: &Config, state: ApiState) -> Router {
    let web = web::router(config, &state);
    let api = api::router(state);

    let app = match &config.api_routing {
        ApiRouting::Path => web.nest("/api", api),
        ApiRouting::Subdomain { host } => {
            // The page and the API are different origins here, so browsers need CORS.
            let api = api.layer(middleware::from_fn_with_state(
                HeaderValue::from_str(config.url.trim_end_matches('/'))
                    .expect("SHH_URL is validated"),
                cors,
            ));
            route_by_host(host.clone(), api, web)
        }
    };
    app.layer(middleware::from_fn(redirect_trailing_slash))
        .layer(middleware::from_fn(request_timeout))
}

// Time a handler may take to produce its response head (SPEC §7.1). Uploads are the exception:
// `api::create` bounds them chunk by chunk, since a large blob takes longer than this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

async fn request_timeout(req: Request, next: Next) -> Response {
    let is_upload = req.method() == Method::POST
        && req.uri().path().trim_end_matches('/').ends_with("/secrets");
    if is_upload {
        return next.run(req).await;
    }
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(response) => response,
        Err(_) => api::error_response(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "The request took too long.",
        ),
    }
}

// Gives every page one URL, so `/api/v1/` and `/api/v1` don't count as different pages.
async fn redirect_trailing_slash(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path == "/" || !path.ends_with('/') {
        return next.run(req).await;
    }

    // Collapse leading slashes too: a redirect to `//evil.com` would send the browser to another site.
    let path = format!("/{}", path.trim_matches(['/', '\\']));
    let location = match req.uri().query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    // 308 keeps the request method, so a POST is not silently turned into a GET.
    Redirect::permanent(&location).into_response()
}

// CORS for the subdomain variant: the site origin only, nothing else. Preflights are answered
// here; real responses get the allow-origin header and expose the headers the client reads.
async fn cors(State(site): State<HeaderValue>, req: Request, next: Next) -> Response {
    let mut response = if req.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PATCH, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("content-type, authorization"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"),
        );
        response
    } else {
        next.run(req).await
    };
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, site);
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("x-shh-claim-token, x-shh-expires-in-hours, retry-after"),
    );
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    response
}

// Sends requests for the API subdomain to the API router, and everything else to the website.
fn route_by_host(api_host: String, api: Router, web: Router) -> Router {
    Router::new().fallback(move |req: Request| {
        let is_api = request_host(&req).is_some_and(|host| host.eq_ignore_ascii_case(&api_host));
        let router = if is_api { api.clone() } else { web.clone() };
        async move {
            let Ok(response) = router.oneshot(req).await;
            response
        }
    })
}

fn request_host(req: &Request) -> Option<&str> {
    // HTTP/2 puts the host in the URI, HTTP/1 sends it in the Host header.
    let host = match req.uri().host() {
        Some(host) => host,
        None => req.headers().get(header::HOST)?.to_str().ok()?,
    };
    host.split(':').next()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::{body::Body, http::StatusCode};
    use shhnote_core::settings::Settings;
    use shhnote_store::{Store, sqlite_path_for_tests};

    use super::*;

    // Each test gets its own database file; the helper deletes any existing file with that name.
    static NEXT_DB: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    async fn state(config: &Config) -> ApiState {
        let n = NEXT_DB.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = sqlite_path_for_tests(&format!("app-{n}"));
        let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .unwrap();
        ApiState::new(store, Settings::default(), config, None)
    }

    async fn build(changes: &[(&str, &str)]) -> Router {
        let config = config(changes);
        router(&config, state(&config).await)
    }

    fn config(changes: &[(&str, &str)]) -> Config {
        let mut vars: HashMap<String, String> = [
            ("SHH_ENV", "local"),
            ("SHH_URL", "http://localhost:3000"),
            ("SHH_SECRET_KEY", &"s".repeat(44)),
            ("SHH_DB", "sqlite"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        for (k, v) in changes {
            vars.insert(k.to_string(), v.to_string());
        }
        Config::from_vars(&vars).unwrap()
    }

    async fn get(app: &Router, host: &str, path: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .uri(path)
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn path_routing() {
        let app = build(&[]).await;

        let (status, body) = get(&app, "localhost:3000", "/api/v1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#""version":"v1""#));

        let (status, body) = get(&app, "localhost:3000", "/en").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#"data-api="http://localhost:3000/api/v1""#));
        assert!(body.contains(r#"data-max-blob-bytes=""#));

        let (status, body) = get(&app, "localhost:3000", "/api/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains(r#""code":"no_such_endpoint""#));

        let (status, _) = get(&app, "localhost:3000", "/en/v1").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn website_pages() {
        let app = build(&[]).await;

        for path in [
            "/en",
            "/en/s",
            "/en/burn",
            "/en/how-it-works",
            "/en/about",
            "/en/contact",
            "/en/terms",
            "/en/privacy",
            "/en/security",
        ] {
            let (status, _) = get(&app, "localhost", path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
        }

        let (status, body) = get(&app, "localhost", "/de/terms").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("<h1>Nutzungsbedingungen</h1>"));
        assert!(body.contains(r#"<html lang="de">"#));

        let (status, body) = get(&app, "localhost", "/de/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("Seite nicht gefunden"));
    }

    #[tokio::test]
    async fn redirects_to_browser_language() {
        let app = build(&[]).await;
        let req = Request::builder()
            .uri("/s?x=1")
            .header(header::HOST, "localhost")
            .header(header::ACCEPT_LANGUAGE, "de-DE,de;q=0.9")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(res.headers()[header::LOCATION], "/de/s?x=1");
        assert_eq!(res.headers()[header::VARY], "Accept-Language");
    }

    #[tokio::test]
    async fn sets_security_headers() {
        let app = build(&[]).await;
        let req = Request::builder()
            .uri("/en/s")
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let headers = res.headers();
        let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("font-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }

    async fn location(app: &Router, host: &str, path: &str) -> String {
        let req = Request::builder()
            .uri(path)
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
        res.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn redirects_trailing_slashes() {
        let app = build(&[]).await;
        assert_eq!(location(&app, "localhost", "/api/v1/").await, "/api/v1");
        assert_eq!(
            location(&app, "localhost", "/api/v1/?a=1").await,
            "/api/v1?a=1"
        );
        assert_eq!(
            location(&app, "localhost", "//evil.com/").await,
            "/evil.com"
        );
        assert_eq!(
            location(&app, "localhost", "/\\evil.com/").await,
            "/evil.com"
        );

        let (status, _) = get(&app, "localhost", "/en").await;
        assert_eq!(status, StatusCode::OK);

        let api_app = build(&[
            ("SHH_ENV", "production"),
            ("SHH_URL", "https://example.com"),
            ("SHH_API_ROUTING", "subdomain"),
        ])
        .await;
        assert_eq!(location(&api_app, "api.example.com", "/v1/").await, "/v1");
    }

    #[tokio::test]
    async fn subdomain_routing() {
        let app = build(&[
            ("SHH_ENV", "production"),
            ("SHH_URL", "https://example.com"),
            ("SHH_API_ROUTING", "subdomain"),
        ])
        .await;

        let (status, body) = get(&app, "api.example.com", "/v1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#""version":"v1""#));

        let (status, body) = get(&app, "example.com", "/en").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#"data-api="https://api.example.com/v1""#));

        // Each host only serves its own routes.
        let (status, _) = get(&app, "example.com", "/en/api/v1").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = get(&app, "api.example.com", "/").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn subdomain_api_sends_cors_for_the_site_origin_only() {
        let app = build(&[
            ("SHH_ENV", "production"),
            ("SHH_URL", "https://example.com"),
            ("SHH_API_ROUTING", "subdomain"),
        ])
        .await;
        let send = |method: &str, host: &str, path: &str| {
            let req = axum::http::Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, host)
                .header(header::ORIGIN, "https://example.com")
                .body(Body::empty())
                .unwrap();
            app.clone().oneshot(req)
        };

        let preflight = send("OPTIONS", "api.example.com", "/v1/secrets/reveal")
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            preflight.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://example.com"
        );
        assert!(
            preflight.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
                .to_str()
                .unwrap()
                .contains("content-type")
        );

        let response = send("GET", "api.example.com", "/v1/config").await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://example.com"
        );
        assert!(
            response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS]
                .to_str()
                .unwrap()
                .contains("x-shh-claim-token")
        );

        // Pages never carry CORS headers, and neither does the path-routed API.
        let page = send("GET", "example.com", "/en").await.unwrap();
        assert!(
            page.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        let path_app = build(&[("SHH_URL", "http://localhost:3000")]).await;
        let req = axum::http::Request::get("/api/v1/config")
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap();
        let response = path_app.oneshot(req).await.unwrap();
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }
}
