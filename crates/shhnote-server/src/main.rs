mod api;
mod app;
mod web;

use shhnote_core::config::Config;

#[tokio::main]
async fn main() {
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };

    let app = app::router(&config);

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .unwrap();
    println!("listening on http://{}", listener.local_addr().unwrap());
    println!("site at {}, API at {}/v1", config.url, config.api_url);
    axum::serve(listener, app).await.unwrap();
}
