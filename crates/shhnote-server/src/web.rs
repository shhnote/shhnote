use std::sync::Arc;

use askama::Template;
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use shhnote_core::config::Config;

#[derive(Clone)]
struct WebState {
    api_url: Arc<str>,
}

pub fn router(config: &Config) -> Router {
    let state = WebState {
        api_url: config.api_url.as_str().into(),
    };
    Router::new().route("/", get(index)).with_state(state)
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage<'a> {
    api_url: &'a str,
}

async fn index(State(state): State<WebState>) -> Response {
    render(IndexPage {
        api_url: &state.api_url,
    })
}

// A template error becomes a 500 page instead of crashing the request.
fn render(page: impl Template) -> Response {
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            eprintln!("template error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
