use std::{sync::Arc, time::Duration};

use shhnote_core::settings::SettingsCell;
use shhnote_store::Store;

use crate::{clock::now, storage::Blobs};

// Parked objects deleted per tick; the rest wait for the next one, so one slow object store
// never holds the scrubber for longer than a bounded batch.
pub const SCRUB_BATCH: i64 = 200;

// Two tasks on one duty cycle. Sweep and roll-up are database work and run together; the
// scrubber talks to the object store and runs on its own, so a slow store (SPEC §6.1) can
// delay deletions but never expiries.
pub fn spawn(
    store: Store,
    interval: Duration,
    settings: Arc<SettingsCell>,
    storage: Option<Arc<Blobs>>,
) {
    let sweeper = store.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now = now();
            if let Err(e) = sweeper.sweep(now).await {
                crate::log_error!("scheduler: sweep failed: {e}");
            }
            let retention = settings.load().daily_retention_days;
            if retention > 0
                && let Err(e) = sweeper
                    .rollup_daily(now.saturating_sub(retention.saturating_mul(86_400)))
                    .await
            {
                crate::log_error!("scheduler: roll-up failed: {e}");
            }
        }
    });
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            scrub(&store, storage.as_deref()).await;
        }
    });
}

// Deletes parked objects and only then their rows, retrying on every pass until each is
// confirmed gone (SPEC §5). A row is never removed before its object.
pub async fn scrub(store: &Store, storage: Option<&Blobs>) {
    let pending = match store.pending_deletes_sized(SCRUB_BATCH).await {
        Ok(pending) => pending,
        Err(e) => {
            crate::log_error!("scheduler: listing pending deletes failed: {e}");
            return;
        }
    };
    if pending.is_empty() {
        return;
    }
    let Some(storage) = storage else {
        crate::log_error!(
            "scheduler: {} object(s) await deletion but no external tier is configured",
            pending.len()
        );
        return;
    };
    for (lookup_key, key, bucket) in pending {
        match storage.delete(&key).await {
            Ok(()) => match store.finish_delete(&lookup_key).await {
                Ok(()) => storage.release_stored(crate::storage::object_bytes(bucket)),
                Err(e) => crate::log_error!("scheduler: finishing delete failed: {e}"),
            },
            Err(e) => crate::log_error!("scheduler: deleting object failed: {e}"),
        }
    }
}
