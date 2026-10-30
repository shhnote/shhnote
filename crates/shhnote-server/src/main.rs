use std::{sync::Arc, time::Duration};

use shhnote_core::{config::Config, settings::Settings};
use shhnote_server::{
    api::{ApiState, Limits},
    app, scheduler,
};
use shhnote_store::Store;

#[tokio::main]
async fn main() {
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };

    let store = match Store::connect(&config.database).await {
        Ok(store) => store,
        Err(e) => {
            eprintln!("database error: {e}");
            std::process::exit(1);
        }
    };

    let overrides = match store.setting_overrides().await {
        Ok(overrides) => overrides,
        Err(e) => {
            eprintln!("database error: {e}");
            std::process::exit(1);
        }
    };
    let (settings, warnings) = Settings::with_overrides(&overrides);
    for warning in warnings {
        eprintln!("warning: {warning}");
    }

    scheduler::spawn(
        store.clone(),
        Duration::from_secs(60),
        settings.daily_retention_days,
    );

    let state = ApiState {
        store,
        settings: Arc::new(settings),
        limits: Limits::from_config(&config),
    };
    let app = app::router(&config, state);

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .unwrap();
    println!("listening on http://{}", listener.local_addr().unwrap());
    println!("site at {}, API at {}/v1", config.url, config.api_url);
    axum::serve(listener, app).await.unwrap();
}
