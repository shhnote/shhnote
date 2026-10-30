use std::{sync::Arc, time::Duration};

use shhnote_core::settings::SettingsCell;
use shhnote_store::Store;

use crate::api::now;

// One task, one duty cycle: destroy expired secrets and lapsed claims, fold old daily
// buckets into their year. External-object scrubbing joins this loop once the external tier exists.
pub fn spawn(store: Store, interval: Duration, settings: Arc<SettingsCell>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now = now();
            if let Err(e) = store.sweep(now).await {
                eprintln!("scheduler: sweep failed: {e}");
            }
            let cutoff = now - settings.load().daily_retention_days * 86_400;
            if let Err(e) = store.rollup_daily(cutoff).await {
                eprintln!("scheduler: roll-up failed: {e}");
            }
        }
    });
}
