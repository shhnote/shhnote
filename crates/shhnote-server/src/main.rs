use std::{net::SocketAddr, sync::Arc, time::Duration};

use shhnote_core::{config::Config, settings::Settings};
use shhnote_server::{api::ApiState, app, log, scheduler, storage::Blobs};
use shhnote_store::Store;

#[tokio::main]
async fn main() {
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            shhnote_server::log_error!("config error: {e}");
            std::process::exit(1);
        }
    };
    log::init(config.log_level);
    if let Err(e) = shhnote_server::i18n::enabled_locales(&config.locales) {
        eprintln!("configuration error: {e}");
        std::process::exit(1);
    }

    let store = match Store::connect(&config.database).await {
        Ok(store) => store,
        Err(e) => {
            shhnote_server::log_error!("database error: {e}");
            std::process::exit(1);
        }
    };

    let overrides = match store.setting_overrides().await {
        Ok(overrides) => overrides,
        Err(e) => {
            shhnote_server::log_error!("database error: {e}");
            std::process::exit(1);
        }
    };
    let (settings, warnings) = Settings::with_overrides(&overrides);
    for warning in warnings {
        shhnote_server::log_warn!("{warning}");
    }

    if std::env::args().nth(1).as_deref() == Some("reset-admin") {
        match store.delete_admin_keys().await {
            Ok(n) => println!(
                "deleted {n} admin key(s); SHH_ADMIN_TOKEN works again until a new one is created"
            ),
            Err(e) => {
                shhnote_server::log_error!("database error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if config.admin_token.is_some() && matches!(store.admin_key_count().await, Ok(n) if n > 0) {
        shhnote_server::log_error!(
            "warning: SHH_ADMIN_TOKEN is set but an admin API key exists, so the token is ignored; unset it"
        );
    }

    let storage = match &config.storage.external {
        Some(external) => match Blobs::open(external).await {
            Ok(blobs) => Some(Arc::new(blobs)),
            Err(e) => {
                shhnote_server::log_error!("storage error: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    if !settings.inline_enabled && storage.is_none() {
        shhnote_server::log_error!(
            "warning: inline_enabled is off but SHH_STORAGE is inline, so blobs stay in the database"
        );
    }

    let state = ApiState::new(store.clone(), settings, &config, storage.clone());
    scheduler::spawn(
        store,
        Duration::from_secs(60),
        state.settings.clone(),
        storage,
    );
    let app = app::router(&config, state);

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .unwrap();
    println!("listening on http://{}", listener.local_addr().unwrap());
    println!("site at {}, API at {}/v1", config.url, config.api_url);
    // The socket address is what rate limiting keys on (behind SHH_TRUSTED_PROXIES, the forwarded one).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
