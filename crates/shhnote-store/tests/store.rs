use std::sync::Arc;

use shhnote_store::{Lifetime, NewSecret, Scope, Store, Sweep, sqlite_path_for_tests};
use tokio::sync::Mutex;

const WINDOW: i64 = 900;

// Every test runs on SQLite. It also runs on Postgres when SHH_TEST_PG_URL is set, which
// points at a throwaway database: the tests clear its tables.
async fn backends(name: &str) -> Vec<(&'static str, Store)> {
    let sqlite = Store::connect_url(&format!(
        "sqlite://{}?mode=rwc",
        sqlite_path_for_tests(name).display()
    ))
    .await
    .expect("sqlite");
    let mut out = vec![("sqlite", sqlite)];
    match std::env::var("SHH_TEST_PG_URL") {
        Ok(url) => {
            let store = Store::connect_url(&url).await.expect("postgres");
            out.push(("postgres", store));
        }
        Err(_) => eprintln!("SHH_TEST_PG_URL not set: skipping the Postgres run of {name}"),
    }
    out
}

// Postgres tests share one database, so they must not interleave.
static PG_LOCK: Mutex<()> = Mutex::const_new(());

async fn fresh(backend: &str, store: &Store) -> Option<tokio::sync::MutexGuard<'static, ()>> {
    let guard = if backend == "postgres" {
        Some(PG_LOCK.lock().await)
    } else {
        None
    };
    store.wipe_for_tests().await.unwrap();
    guard
}

fn key(seed: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).unwrap();
    k[0] = seed;
    k
}

fn secret(lifetime: Lifetime, expires_at: i64) -> NewSecret {
    NewSecret {
        lookup_key: key(1),
        burn_key: key(2),
        lifetime,
        bucket: 4096,
        blob: Some(vec![0xAB; 4207]),
        external_ref: None,
        expires_at,
    }
}

#[tokio::test]
async fn single_view_lifecycle() {
    for (backend, store) in backends("single_view").await {
        let _guard = fresh(backend, &store).await;
        let now = 1_000_000;
        let s = secret(Lifetime::SingleView, now + 3600);
        assert!(store.create(&s, now).await.unwrap(), "{backend}");
        assert!(
            !store.create(&s, now).await.unwrap(),
            "{backend}: duplicate must be refused"
        );

        // Not readable as TTL, not burnable by the wrong key.
        assert!(
            store.read_ttl(&s.lookup_key, now).await.unwrap().is_none(),
            "{backend}"
        );

        let claim = key(3);
        let served = store
            .claim(&s.lookup_key, &claim, now, WINDOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(served.blob.as_deref(), Some(&[0xAB; 4207][..]), "{backend}");
        assert_eq!(served.bucket, 4096);

        // A second claim loses; the claimant can re-download; others cannot.
        assert!(
            store
                .claim(&s.lookup_key, &key(4), now + 1, WINDOW)
                .await
                .unwrap()
                .is_none(),
            "{backend}"
        );
        assert!(
            store
                .redownload(&s.lookup_key, &claim, now + 10)
                .await
                .unwrap()
                .is_some(),
            "{backend}"
        );
        assert!(
            store
                .redownload(&s.lookup_key, &key(4), now + 10)
                .await
                .unwrap()
                .is_none(),
            "{backend}"
        );
        assert!(
            store
                .redownload(&s.lookup_key, &claim, now + WINDOW)
                .await
                .unwrap()
                .is_none(),
            "{backend}: window closed"
        );

        // Burn and report don't touch a claimed secret.
        assert!(
            !store.burn(&s.burn_key, now + 10).await.unwrap(),
            "{backend}"
        );
        assert!(
            !store.report(&s.lookup_key, now + 10).await.unwrap(),
            "{backend}"
        );

        assert!(
            !store
                .confirm(&s.lookup_key, &key(4), now + 10)
                .await
                .unwrap(),
            "{backend}: wrong token"
        );
        assert!(
            store
                .confirm(&s.lookup_key, &claim, now + 10)
                .await
                .unwrap(),
            "{backend}"
        );
        assert!(
            !store
                .confirm(&s.lookup_key, &claim, now + 10)
                .await
                .unwrap(),
            "{backend}: already gone"
        );

        let stats = store.stats().await.unwrap();
        assert_eq!(
            (stats.created, stats.viewed, stats.active),
            (1, 1, 0),
            "{backend}"
        );
        let days = store.daily(0).await.unwrap();
        assert_eq!(days.len(), 1);
        assert_eq!(
            (days[0].created, days[0].viewed, days[0].burned),
            (1, 1, 0),
            "{backend}"
        );
        // The unmatched report above left no trace (D-19).
        assert_eq!(stats.removed, 0, "{backend}");
    }
}

#[tokio::test]
async fn exactly_one_concurrent_claim_wins() {
    for (backend, store) in backends("concurrent").await {
        let _guard = fresh(backend, &store).await;
        let now = 2_000_000;
        let s = secret(Lifetime::SingleView, now + 3600);
        store.create(&s, now).await.unwrap();

        let store = Arc::new(store);
        let mut tasks = Vec::new();
        for i in 0..32u8 {
            let store = store.clone();
            let lookup = s.lookup_key;
            tasks.push(tokio::spawn(async move {
                store
                    .claim(&lookup, &key(i), now, WINDOW)
                    .await
                    .unwrap()
                    .is_some()
            }));
        }
        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "{backend}");
    }
}

#[tokio::test]
async fn ttl_lifecycle_and_burn() {
    for (backend, store) in backends("ttl").await {
        let _guard = fresh(backend, &store).await;
        let now = 3_000_000;
        let s = secret(Lifetime::Ttl, now + 7200);
        store.create(&s, now).await.unwrap();

        // Readable many times, never claimable, flat.
        for t in [now, now + 100, now + 7199] {
            let read = store.read_ttl(&s.lookup_key, t).await.unwrap().unwrap();
            assert_eq!(read.expires_at, now + 7200, "{backend}");
            assert_eq!(read.served.bucket, 4096);
        }
        assert!(
            store
                .claim(&s.lookup_key, &key(9), now, WINDOW)
                .await
                .unwrap()
                .is_none(),
            "{backend}"
        );
        assert!(
            store
                .read_ttl(&s.lookup_key, now + 7200)
                .await
                .unwrap()
                .is_none(),
            "{backend}: expired"
        );

        assert!(
            !store.burn(&key(7), now).await.unwrap(),
            "{backend}: unknown burn key"
        );
        assert!(store.burn(&s.burn_key, now).await.unwrap(), "{backend}");
        assert!(
            !store.burn(&s.burn_key, now).await.unwrap(),
            "{backend}: already burned"
        );
        assert!(
            store.read_ttl(&s.lookup_key, now).await.unwrap().is_none(),
            "{backend}"
        );

        let stats = store.stats().await.unwrap();
        assert_eq!(
            (stats.burned, stats.active, stats.viewed),
            (1, 0, 0),
            "{backend}"
        );
        // TTL reads are deliberately uncounted; the burn lands in today's bucket.
        let days = store.daily(0).await.unwrap();
        assert_eq!(
            (days[0].created, days[0].viewed, days[0].burned),
            (1, 0, 1),
            "{backend}"
        );
    }
}

#[tokio::test]
async fn report_removes_and_keeps_no_ledger() {
    for (backend, store) in backends("report").await {
        let _guard = fresh(backend, &store).await;
        let now = 4_000_000;
        let s = secret(Lifetime::Ttl, now + 7200);
        store.create(&s, now).await.unwrap();

        assert!(
            !store.report(&key(5), now).await.unwrap(),
            "{backend}: no match"
        );
        assert!(
            store.report(&s.lookup_key, now + 1).await.unwrap(),
            "{backend}"
        );
        assert!(
            !store.report(&s.lookup_key, now + 2).await.unwrap(),
            "{backend}: already removed"
        );

        // Only the takedown is counted; which secret was reported is not kept anywhere.
        assert_eq!(store.stats().await.unwrap().removed, 1, "{backend}");
        let days = store.daily(0).await.unwrap();
        assert_eq!(days.len(), 1, "{backend}");
        assert_eq!(days[0].removed, 1, "{backend}");
    }
}

#[tokio::test]
async fn sweep_destroys_expired_and_lapsed_claims() {
    for (backend, store) in backends("sweep").await {
        let _guard = fresh(backend, &store).await;
        let now = 5_000_000;
        let expiring = secret(Lifetime::Ttl, now + 10);
        let claimed = secret(Lifetime::SingleView, now + 3600);
        let fine = secret(Lifetime::Ttl, now + 3600);
        for s in [&expiring, &claimed, &fine] {
            store.create(s, now).await.unwrap();
        }
        store
            .claim(&claimed.lookup_key, &key(8), now, WINDOW)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            store.sweep(now + 5).await.unwrap(),
            Sweep::default(),
            "{backend}: nothing due yet"
        );
        assert_eq!(
            store.sweep(now + WINDOW).await.unwrap(),
            Sweep {
                expired: 1,
                consumed: 1
            },
            "{backend}"
        );
        assert!(
            store
                .read_ttl(&fine.lookup_key, now + WINDOW)
                .await
                .unwrap()
                .is_some(),
            "{backend}"
        );

        let stats = store.stats().await.unwrap();
        assert_eq!(
            (stats.created, stats.expired, stats.viewed, stats.active),
            (3, 1, 1, 1),
            "{backend}"
        );
    }
}

#[tokio::test]
async fn external_rows_park_in_pending_delete() {
    for (backend, store) in backends("external").await {
        let _guard = fresh(backend, &store).await;
        let now = 6_000_000;
        let mut s = secret(Lifetime::Ttl, now + 3600);
        s.blob = None;
        s.external_ref = Some("blobs/abc".into());
        store.create(&s, now).await.unwrap();

        let read = store.read_ttl(&s.lookup_key, now).await.unwrap().unwrap();
        assert_eq!(
            read.served.external_ref.as_deref(),
            Some("blobs/abc"),
            "{backend}"
        );
        assert!(store.burn(&s.burn_key, now).await.unwrap(), "{backend}");

        // Parked, never served, then gone once the object is confirmed deleted.
        assert!(
            store.read_ttl(&s.lookup_key, now).await.unwrap().is_none(),
            "{backend}"
        );
        let pending = store.pending_deletes().await.unwrap();
        assert_eq!(
            pending,
            vec![(s.lookup_key.to_vec(), "blobs/abc".to_string())],
            "{backend}"
        );
        store.finish_delete(&s.lookup_key).await.unwrap();
        assert!(
            store.pending_deletes().await.unwrap().is_empty(),
            "{backend}"
        );
    }
}

#[tokio::test]
async fn settings_overrides_round_trip() {
    for (backend, store) in backends("settings").await {
        let _guard = fresh(backend, &store).await;
        assert!(
            store.setting_overrides().await.unwrap().is_empty(),
            "{backend}"
        );
        store.set_setting("site_name", "shh").await.unwrap();
        store.set_setting("site_name", "shhnote").await.unwrap();
        store.set_setting("padding_min", "65536").await.unwrap();
        let all = store.setting_overrides().await.unwrap();
        assert_eq!(
            all.get("site_name").map(String::as_str),
            Some("shhnote"),
            "{backend}"
        );
        assert_eq!(all.len(), 2);
        store.clear_setting("site_name").await.unwrap();
        assert_eq!(
            store.setting_overrides().await.unwrap().len(),
            1,
            "{backend}"
        );
    }
}

#[tokio::test]
async fn old_days_roll_up_into_their_year() {
    for (backend, store) in backends("rollup").await {
        let _guard = fresh(backend, &store).await;
        let day = 86_400;
        let jan1_2025 = 1_735_689_600;
        let jan1_2026 = 1_767_225_600;
        // Three days in 2025, one on 1 January 2026, one later in 2026.
        for t in [
            jan1_2025 + 40 * day,
            jan1_2025 + 41 * day,
            jan1_2025 + 200 * day,
            jan1_2026,
            jan1_2026 + 100 * day,
        ] {
            store
                .create(&secret(Lifetime::Ttl, t + 3600), t)
                .await
                .unwrap();
        }
        let total_before = store.stats().await.unwrap().created;
        assert_eq!(total_before, 5, "{backend}");

        // Everything before mid-2026 is older than the window: 2025's days fold into one row,
        // 2026-01-01 is already an accumulator and stays.
        let folded = store.rollup_daily(jan1_2026 + 50 * day).await.unwrap();
        assert_eq!(folded, 3, "{backend}");
        let days = store.daily(0).await.unwrap();
        let rows: Vec<(i64, i64)> = days.iter().map(|d| (d.day, d.created)).collect();
        assert_eq!(
            rows,
            vec![(jan1_2025, 3), (jan1_2026, 1), (jan1_2026 + 100 * day, 1)],
            "{backend}"
        );
        assert_eq!(
            store.stats().await.unwrap().created,
            total_before,
            "{backend}: totals survive"
        );
        assert_eq!(
            store.rollup_daily(jan1_2026 + 50 * day).await.unwrap(),
            0,
            "{backend}: idempotent"
        );
    }
}

#[tokio::test]
async fn api_keys_round_trip() {
    for (backend, store) in backends("api_keys").await {
        let _guard = fresh(backend, &store).await;
        let admin = key(1);
        let user = key(2);
        assert_eq!(store.admin_key_count().await.unwrap(), 0, "{backend}");
        store
            .create_api_key(&admin, "laptop", Scope::Admin, 100)
            .await
            .unwrap();
        store
            .create_api_key(&user, "ci", Scope::User, 200)
            .await
            .unwrap();
        assert_eq!(store.admin_key_count().await.unwrap(), 1, "{backend}");

        let found = store.find_api_key(&user).await.unwrap().unwrap();
        assert_eq!(
            (found.name.as_str(), found.scope, found.last_used_on),
            ("ci", Scope::User, None),
            "{backend}"
        );
        // Use at 2 days + 1000 s is recorded as the start of day 2, never the second.
        store.touch_api_key(&user, 2 * 86_400 + 1000).await.unwrap();
        assert_eq!(
            store
                .find_api_key(&user)
                .await
                .unwrap()
                .unwrap()
                .last_used_on,
            Some(2 * 86_400),
            "{backend}"
        );
        assert!(
            store.find_api_key(&key(3)).await.unwrap().is_none(),
            "{backend}"
        );

        let listed = store.list_api_keys().await.unwrap();
        assert_eq!(
            listed.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(),
            vec!["ci", "laptop"],
            "{backend}"
        );
        assert!(store.delete_api_key(&user).await.unwrap(), "{backend}");
        assert!(!store.delete_api_key(&user).await.unwrap(), "{backend}");
        assert_eq!(store.delete_admin_keys().await.unwrap(), 1, "{backend}");
        assert!(store.list_api_keys().await.unwrap().is_empty(), "{backend}");
    }
}
