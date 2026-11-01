use std::{sync::Arc, time::Duration};

use shhnote_core::{config::Config, settings::Settings};
use shhnote_server::{api::ApiState, app, drain::Drain, health, log, scheduler, storage::Blobs};
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
    if let Err(e) = shhnote_server::i18n::offered(&config.locales, config.default_locale.as_deref())
    {
        shhnote_server::log_error!("configuration error: {e}");
        std::process::exit(1);
    }

    let command = std::env::args().nth(1);
    // `health` asks a running server; it must not need the database itself.
    if command.as_deref() == Some("health") {
        match health::probe(&config).await {
            Ok(()) => println!("ok"),
            Err(e) => {
                shhnote_server::log_error!("unhealthy: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    let store = match Store::connect(&config.database).await {
        Ok(store) => store,
        Err(e) => {
            shhnote_server::log_error!("database error: {e}");
            std::process::exit(1);
        }
    };

    match command.as_deref() {
        // Everything a start needs, without starting: config parsed, database reachable.
        Some("check") => {
            if let Err(e) = store.ping().await {
                shhnote_server::log_error!("database error: {e}");
                std::process::exit(1);
            }
            println!("ok (SHH_WEB={})", config.web.as_str());
            return;
        }
        Some("reset-admin") => {
            match store.delete_admin_keys(shhnote_server::clock::now()).await {
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
        Some(other) => {
            shhnote_server::log_error!(
                "unknown command {other:?}; commands: check, health, reset-admin"
            );
            std::process::exit(2);
        }
        None => {}
    }

    let overrides = match store.setting_overrides().await {
        Ok(overrides) => overrides,
        Err(e) => {
            shhnote_server::log_error!("database error: {e}");
            std::process::exit(1);
        }
    };
    let (settings, warnings) = Settings::with_overrides(&overrides, config.env);
    for warning in warnings {
        shhnote_server::log_warn!("{warning}");
    }
    if config.admin_token.is_some() && matches!(store.admin_key_count().await, Ok(n) if n > 0) {
        shhnote_server::log_warn!(
            "SHH_ADMIN_TOKEN is set but an admin API key exists, so the token is ignored; unset it"
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

    if let Some(storage) = &storage {
        match storage.collect_orphans(&store).await {
            Ok(0) => {}
            Ok(n) => {
                shhnote_server::log_warn!("storage: removed {n} object(s) no secret referenced")
            }
            Err(e) => {
                shhnote_server::log_error!("storage error: {e}");
                std::process::exit(1);
            }
        }
    }

    if !settings.inline_enabled && storage.is_none() {
        shhnote_server::log_warn!(
            "inline_enabled is off but SHH_STORAGE is inline, so blobs stay in the database"
        );
    }

    let state = ApiState::new(store.clone(), settings, &config, storage.clone());
    scheduler::spawn(
        store,
        Duration::from_secs(60),
        state.settings.clone(),
        storage,
    );
    let drain = Arc::new(Drain::default());
    let app = app::router_with_drain(&config, state, drain.clone());

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .unwrap();
    // Configuration is never printed at startup (SPEC §11); the bind address goes through the
    // log macros like every other diagnostic, so SHH_LOG_LEVEL decides.
    shhnote_server::log_info!("listening on {}", listener.local_addr().unwrap());
    shhnote_server::serve::serve(
        listener,
        app,
        drain,
        shutdown_signal(),
        Duration::from_secs(30),
    )
    .await;
    shhnote_server::log_info!("stopped");
}

// SIGTERM (what `docker stop` and systemd send) or Ctrl-C: stop accepting connections and
// let in-flight requests finish, so an upload in progress is not cut off.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    shhnote_server::log_info!("shutting down, finishing in-flight requests");
}
