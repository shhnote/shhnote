use axum::{Router, extract::Request, http::header};
use shhnote_core::config::{ApiRouting, Config};
use tower::ServiceExt;

use crate::{api, web};

pub fn router(config: &Config) -> Router {
    let api = api::router();
    let web = web::router(config);

    match &config.api_routing {
        ApiRouting::Path => web.nest("/api", api),
        ApiRouting::Subdomain { host } => route_by_host(host.clone(), api, web),
    }
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

        let (status, body) = get(&app, "localhost:3000", "/").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#"href="http://localhost:3000/api/v1""#));

        let (status, _) = get(&app, "localhost:3000", "/v1").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
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

        let (status, body) = get(&app, "example.com", "/").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#"href="https://api.example.com/v1""#));

        // Each host only serves its own routes.
        let (status, _) = get(&app, "example.com", "/api/v1").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = get(&app, "api.example.com", "/").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
