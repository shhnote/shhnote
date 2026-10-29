use axum::{Json, Router, routing::get};
use serde::Serialize;

// Each API version gets its own router, so a new version can change things without breaking the old one.
pub fn router() -> Router {
    Router::new().nest("/v1", v1())
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

async fn info() -> Json<Info> {
    Json(Info {
        name: "shhnote",
        version: "v1",
        message: "Hello from the shhnote API",
    })
}
