use std::{sync::Arc, time::Duration};

use shhnote_core::settings::SettingsCell;
use shhnote_store::Store;

use crate::{clock::now, storage::Blobs};

// One task, one duty cycle: destroy expired secrets and lapsed claims, delete external
// objects whose rows are parked, fold old daily buckets into their year.
pub fn spawn(
    store: Store,
    interval: Duration,
    settings: Arc<SettingsCell>,
    storage: Option<Arc<Blobs>>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now = now();
            if let Err(e) = store.sweep(now).await {
                eprintln!("scheduler: sweep failed: {e}");
            }
            scrub(&store, storage.as_deref()).await;
            let cutoff = now - settings.load().daily_retention_days * 86_400;
            if let Err(e) = store.rollup_daily(cutoff).await {
                eprintln!("scheduler: roll-up failed: {e}");
            }
        }
    });
}

// Deletes parked objects and only then their rows, retrying on every pass until each is
// confirmed gone (SPEC §5). A row is never removed before its object.
pub async fn scrub(store: &Store, storage: Option<&Blobs>) {
    let pending = match store.pending_deletes().await {
        Ok(pending) => pending,
        Err(e) => {
            eprintln!("scheduler: listing pending deletes failed: {e}");
            return;
        }
    };
    if pending.is_empty() {
        return;
    }
    let Some(storage) = storage else {
        eprintln!(
            "scheduler: {} object(s) await deletion but no external tier is configured",
            pending.len()
        );
        return;
    };
    for (lookup_key, key) in pending {
        match storage.delete(&key).await {
            Ok(()) => {
                if let Err(e) = store.finish_delete(&lookup_key).await {
                    eprintln!("scheduler: finishing delete failed: {e}");
                }
            }
            Err(e) => eprintln!("scheduler: deleting object failed: {e}"),
        }
    }
}
