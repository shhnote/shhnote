use axum::{
    Router,
    extract::Request,
    http::header,
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
};
use shhnote_core::config::{ApiRouting, Config};
use tower::ServiceExt;

use crate::{
    api::{self, ApiState},
    web,
};

pub fn router(config: &Config, state: ApiState) -> Router {
    let api = api::router(state);
    let web = web::router(config);

    let app = match &config.api_routing {
        ApiRouting::Path => web.nest("/api", api),
        ApiRouting::Subdomain { host } => route_by_host(host.clone(), api, web),
    };
    app.layer(middleware::from_fn(redirect_trailing_slash))
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
    use std::{collections::HashMap, sync::Arc};

    use axum::{body::Body, http::StatusCode};
    use shhnote_core::settings::Settings;
    use shhnote_store::{Store, sqlite_path_for_tests};

    use super::*;
    use crate::api::Limits;

    // Each test gets its own database file; the helper deletes any existing file with that name.
    static NEXT_DB: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    async fn state(config: &Config) -> ApiState {
        let n = NEXT_DB.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = sqlite_path_for_tests(&format!("app-{n}"));
        let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .unwrap();
        ApiState {
            store,
            settings: Arc::new(Settings::default()),
            limits: Limits::from_config(config),
        }
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
}
