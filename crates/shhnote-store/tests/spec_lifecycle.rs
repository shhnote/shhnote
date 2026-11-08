use std::time::{Duration, Instant};

use shhnote_store::{Lifetime, NewSecret, Scope, Store, sqlite_path_for_tests};
use sqlx::Connection;

const WINDOW: i64 = 900;

fn key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).unwrap();
    k
}

fn secret(lookup_key: [u8; 32], lifetime: Lifetime, expires_at: i64, size: usize) -> NewSecret {
    NewSecret {
        lookup_key,
        burn_key: key(),
        lifetime,
        bucket: 65536,
        blob: Some(vec![0xAB; size]),
        external_ref: None,
        expires_at,
    }
}

async fn sqlite(name: &str) -> (Store, std::path::PathBuf) {
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    (store, path)
}

// A writer holding the SQLite write lock longer than busy_timeout (5 s) turns every claim
// into a database error (the API maps it to 500; issue #19). The error is the same whether
// or not the row exists, so it is not an existence oracle (SPEC §4), and nothing is
// consumed by it. Slow on purpose: it waits out the timeout twice.
#[tokio::test]
async fn spec_sqlite_lock_holder_makes_claims_fail_after_busy_timeout() {
    let (store, path) = sqlite("spec-lifecycle-busy").await;
    let lookup = key();
    let now = 1_000_000;
    store
        .create(&secret(lookup, Lifetime::SingleView, now + 3600, 100), now)
        .await
        .unwrap();
    let mut raw = sqlx::SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut raw)
        .await
        .unwrap();

    let started = Instant::now();
    let existing = store.claim(&lookup, &key(), now, WINDOW).await;
    let missing = store.claim(&key(), &key(), now, WINDOW).await;
    let elapsed = started.elapsed();
    sqlx::query("ROLLBACK").execute(&mut raw).await.unwrap();
    assert!(existing.is_err() && missing.is_err());
    assert!(elapsed >= Duration::from_secs(9));
    assert!(
        store
            .claim(&lookup, &key(), now, WINDOW)
            .await
            .unwrap()
            .is_some()
    );
}

// A key used again on the day it was last used only reads its row, so it never waits for
// SQLite's write lock (D-23): keyed requests come far more often than days, and a write per
// request would contend with every claim and sweep.
#[tokio::test]
async fn spec_same_day_key_use_takes_no_write_lock() {
    let (store, path) = sqlite("spec-lifecycle-touch").await;
    let key_hash = key();
    let midnight = 1_700_006_400;
    store
        .create_api_key(&key_hash, "ci", Scope::User, midnight)
        .await
        .unwrap();
    store.touch_api_key(&key_hash, midnight + 60).await.unwrap();

    let mut raw = sqlx::SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut raw)
        .await
        .unwrap();
    let started = Instant::now();
    let same_day = store.touch_api_key(&key_hash, midnight + 3600).await;
    let elapsed = started.elapsed();
    sqlx::query("ROLLBACK").execute(&mut raw).await.unwrap();

    assert!(same_day.is_ok(), "{same_day:?}");
    assert!(elapsed < Duration::from_secs(2), "waited {elapsed:?}");
}

// The claim window and the narrow predicates (SPEC §5.1, §5.3).
#[tokio::test]
async fn spec_claim_window_lifecycle() {
    let (store, _) = sqlite("spec-lifecycle-window").await;
    let now = 1_000_000;

    // Re-download works inside the window, not after confirm.
    let lookup = key();
    let s = secret(lookup, Lifetime::SingleView, now + 3600, 100);
    let burn_key = s.burn_key;
    store.create(&s, now).await.unwrap();
    let claim = key();
    assert!(
        store
            .claim(&lookup, &claim, now, WINDOW)
            .await
            .unwrap()
            .is_some()
    );
    // Burn and report never touch a claimed row (SPEC §5.3).
    assert!(!store.burn(&burn_key, now + 1).await.unwrap());
    assert!(!store.report(&lookup, now + 1).await.unwrap());
    assert!(
        store
            .redownload(&lookup, &claim, now + 10)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .redownload(&lookup, &key(), now + 10)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.confirm(&lookup, &claim, now + 20).await.unwrap());
    assert!(
        store
            .redownload(&lookup, &claim, now + 21)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!store.confirm(&lookup, &claim, now + 22).await.unwrap());

    // After the window (which ends on the next whole minute, D-18): no re-download, no
    // confirm, and the sweep destroys it as viewed.
    let after = now + WINDOW + 60;
    let lookup = key();
    store
        .create(&secret(lookup, Lifetime::SingleView, now + 3600, 100), now)
        .await
        .unwrap();
    let claim = key();
    store
        .claim(&lookup, &claim, now, WINDOW)
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .redownload(&lookup, &claim, after)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!store.confirm(&lookup, &claim, after).await.unwrap());
    let swept = store.sweep(after).await.unwrap();
    assert_eq!(swept.consumed, 1);
    // Nothing ever reverts: a fresh claim fails too.
    assert!(
        store
            .claim(&lookup, &key(), after, WINDOW)
            .await
            .unwrap()
            .is_none()
    );

    // A claim whose window outlives the secret's TTL: re-download is still allowed until the
    // window ends, because the claimed predicate does not look at expires_at.
    let lookup = key();
    store
        .create(&secret(lookup, Lifetime::SingleView, now + 60, 100), now)
        .await
        .unwrap();
    let claim = key();
    store
        .claim(&lookup, &claim, now, WINDOW)
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .redownload(&lookup, &claim, now + 120)
            .await
            .unwrap()
            .is_some()
    );
}
