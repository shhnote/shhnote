use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;

// Each API version gets its own router, so a new version can change things without breaking the old one.
pub fn router() -> Router {
    Router::new().nest("/v1", v1()).fallback(not_found)
}

fn v1() -> Router {
    Router::new().route("/", get(info))
}

#[derive(Serialize)]
struct Info {
    name: &'static str,
    version: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: &'static str,
}

// API clients expect JSON errors, never the website's HTML error pages.
async fn not_found() -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: "not_found",
            message: "This endpoint does not exist.",
        },
    };
    (StatusCode::NOT_FOUND, Json(body)).into_response()
}

async fn info() -> Json<Info> {
    Json(Info {
        name: "shhnote",
        version: "v1",
        message: "Hello from the shhnote API",
    })
}
