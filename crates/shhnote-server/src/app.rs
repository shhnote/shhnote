use axum::{
    Router,
    extract::Request,
    http::header,
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
};
use shhnote_core::config::{ApiRouting, Config};
use tower::ServiceExt;

use crate::{api, web};

pub fn router(config: &Config) -> Router {
    let api = api::router();
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
    use std::collections::HashMap;

    use axum::{body::Body, http::StatusCode};

    use super::*;

    fn config(changes: &[(&str, &str)]) -> Config {
        let mut vars: HashMap<String, String> = [
            ("APP_ENV", "local"),
            ("APP_URL", "http://localhost:3000"),
            ("APP_SECRET_KEY", &"s".repeat(44)),
            ("APP_ENCRYPTION_KEY", &"e".repeat(44)),
            ("DB_CONNECTION", "sqlite"),
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
        let app = router(&config(&[]));

        let (status, body) = get(&app, "localhost:3000", "/api/v1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#""version":"v1""#));

        let (status, body) = get(&app, "localhost:3000", "/en").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#"data-api="http://localhost:3000/api/v1""#));

        let (status, body) = get(&app, "localhost:3000", "/api/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains(r#""code":"not_found""#));

        let (status, _) = get(&app, "localhost:3000", "/en/v1").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn website_pages() {
        let app = router(&config(&[]));

        for path in [
            "/en",
            "/en/s/abc123",
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

        let (status, _) = get(&app, "localhost", "/en/s/bad%22id").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn redirects_to_browser_language() {
        let app = router(&config(&[]));
        let req = Request::builder()
            .uri("/s/abc?x=1")
            .header(header::HOST, "localhost")
            .header(header::ACCEPT_LANGUAGE, "de-DE,de;q=0.9")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(res.headers()[header::LOCATION], "/de/s/abc?x=1");
        assert_eq!(res.headers()[header::VARY], "Accept-Language");
    }

    #[tokio::test]
    async fn sets_security_headers() {
        let app = router(&config(&[]));
        let req = Request::builder()
            .uri("/en/s/abc")
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
        let app = router(&config(&[]));
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

        let api_app = router(&config(&[
            ("APP_ENV", "production"),
            ("APP_URL", "https://example.com"),
            ("API_ROUTING", "subdomain"),
        ]));
        assert_eq!(location(&api_app, "api.example.com", "/v1/").await, "/v1");
    }

    #[tokio::test]
    async fn subdomain_routing() {
        let app = router(&config(&[
            ("APP_ENV", "production"),
            ("APP_URL", "https://example.com"),
            ("API_ROUTING", "subdomain"),
        ]));

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
