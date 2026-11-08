use std::{sync::Arc, time::Duration};

use shhnote_core::{config::Config, settings::Settings};
use shhnote_server::{api::ApiState, app, drain::Drain, health, log, scheduler, storage::Blobs};
use shhnote_store::Store;

const USAGE: &str = "usage: shhnote [command]
  (none)        run the server
  init          generate SHH_SECRET_KEY and SHH_ADMIN_TOKEN (--env <path> writes them into that file)
  check         load the configuration and ping the database (applies pending migrations)
  health        ask the running server's health endpoint
  reset-admin   delete every admin API key, so SHH_ADMIN_TOKEN works again
  --version     print the version
  --help        print this help
Every command except init, --version and --help reads the SHH_* environment (or .env).";

#[tokio::main]
async fn main() {
    // These run before any configuration exists: `init` makes the secrets a start needs, and
    // the version and help must work right after installing the binary.
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => {
            if let Err(e) = shhnote_server::init::run(&args[2..]) {
                shhnote_server::log_error!("init: {e}");
                std::process::exit(1);
            }
            return;
        }
        Some("--version" | "-V") => {
            println!("shhnote {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return;
        }
        // Refused here, so a typo never connects to the database or applies migrations.
        Some(other) if !matches!(other, "check" | "health" | "reset-admin") => {
            shhnote_server::log_error!("unknown command {other:?}\n{USAGE}");
            std::process::exit(2);
        }
        _ => {}
    }

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
        // Unknown commands were refused before the configuration was read.
        _ => {}
    }

    let overrides = match store.setting_overrides().await {
        Ok(overrides) => overrides,
        Err(e) => {
            shhnote_server::log_error!("database error: {e}");
            std::process::exit(1);
        }
    };
    let (mut settings, mut warnings) = Settings::with_overrides(&overrides, config.env);
    warnings.extend(settings.check_blob_limit(config.storage.max_blob_bytes()));
    for warning in warnings {
        shhnote_server::log_warn!("{warning}");
    }
    if config.admin_token.is_some() && matches!(store.admin_key_count().await, Ok(n) if n > 0) {
        shhnote_server::log_warn!(
            "SHH_ADMIN_TOKEN is set but an admin API key exists, so the token is ignored; unset it"
        );
    }

    // Anything in the tier younger than the longest possible upload may belong to a process
    // this one is replacing, so the startup cleanup leaves it alone (SPEC §6.1).
    let upload_window = shhnote_server::api::upload_window(config.storage.max_blob_bytes());
    let storage = match &config.storage.external {
        Some(external) => match Blobs::open_with(external, upload_window).await {
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
            Ok(sweep) => {
                if sweep.removed > 0 {
                    shhnote_server::log_warn!(
                        "storage: removed {} object(s) no secret referenced",
                        sweep.removed
                    );
                }
                if sweep.ignored > 0 {
                    shhnote_server::log_warn!(
                        "storage: left {} other entry(s) in the blob area alone: not shhnote objects",
                        sweep.ignored
                    );
                }
                if sweep.young > 0 {
                    shhnote_server::log_info!(
                        "storage: left {} unreferenced object(s) that may still be uploads in flight",
                        sweep.young
                    );
                }
                if sweep.failed > 0 {
                    shhnote_server::log_warn!(
                        "storage: could not remove {} unreferenced object(s); they are retried at the next start",
                        sweep.failed
                    );
                }
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
