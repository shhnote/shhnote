// Regression tests from the security review (docs/security-review/findings/SUMMARY.md): what a
// SQLite dump or a copy of the database files must not show. Ignored tests are waiting for the
// step that fixes their finding; un-ignore them with the fix.
use shhnote_store::{Lifetime, NewSecret, Scope, Store, sqlite_path_for_tests};
use sqlx::{Row, SqlitePool};

const BUCKET: u64 = 65536;
const BLOB_LEN: usize = 95 + 65536 + 16;
const PRESETS: [i64; 9] = [
    900, 1800, 3600, 21600, 43200, 86400, 259200, 604800, 1209600,
];

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

fn secret(lifetime: Lifetime, expires_at: i64, blob: Vec<u8>) -> NewSecret {
    NewSecret {
        lookup_key: random(),
        burn_key: random(),
        lifetime,
        bucket: BUCKET,
        blob: Some(blob),
        external_ref: None,
        expires_at,
    }
}

fn random_blob() -> Vec<u8> {
    let mut v = vec![0u8; BLOB_LEN];
    getrandom::fill(&mut v).unwrap();
    v
}

async fn open(name: &str) -> (Store, std::path::PathBuf, SqlitePool) {
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    // A second, read-only look at the same file: what a dump holder or backup sees.
    let raw = SqlitePool::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    (store, path, raw)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// `secrets` has no rowid (SPEC §3), so a dump cannot sort secrets by creation.
#[tokio::test]
async fn spec_sqlite_secrets_have_no_rowid() {
    let (store, _, raw) = open("spec-privacy-rowid").await;
    for _ in 0..8 {
        let s = secret(Lifetime::Ttl, 4_000_000_000, random_blob());
        assert!(store.create(&s, 1_800_000_000).await.unwrap());
    }
    let by_rowid = sqlx::query("SELECT rowid, lookup_key FROM secrets ORDER BY rowid")
        .fetch_all(&raw)
        .await;
    assert!(
        by_rowid.is_err(),
        "a WITHOUT ROWID table has no rowid to order by"
    );
}

// A destroyed secret's ciphertext does not outlive the row in the -wal file once the scheduler
// has run (SPEC §6.1 accepted residuals: the WAL is truncated after each sweep).
#[tokio::test]
#[ignore = "S-15"]
async fn spec_destroyed_blob_leaves_the_wal_after_sweep() {
    let (store, path, raw) = open("spec-privacy-wal").await;
    let blob = random_blob();
    let marker = blob[1000..1064].to_vec();
    let s = secret(Lifetime::Ttl, 4_000_000_000, blob);
    let burn_key = s.burn_key;
    assert!(store.create(&s, 1_800_000_000).await.unwrap());
    assert!(store.burn(&burn_key, 1_800_000_001).await.unwrap());
    let n: i64 = sqlx::query("SELECT COUNT(*) AS n FROM secrets")
        .fetch_one(&raw)
        .await
        .unwrap()
        .get("n");
    assert_eq!(n, 0, "row is gone");
    store.sweep(1_800_000_002).await.unwrap();
    let wal = std::fs::read(format!("{}-wal", path.display())).unwrap_or_default();
    let db = std::fs::read(&path).unwrap();
    assert!(
        !contains(&db, &marker),
        "secure_delete keeps the main file clean"
    );
    assert!(
        !contains(&wal, &marker),
        "the -wal file still holds the destroyed blob ({} bytes)",
        wal.len()
    );
}

// `api_keys.last_used_on` is a UTC day (D-23), so it joins neither `expires_at - preset` nor
// `claim_expires_at - window`. The calls below are what the server does for a keyed create
// and a keyed reveal.
#[tokio::test]
async fn spec_dump_cannot_link_user_key_to_its_secrets() {
    let (store, _, raw) = open("spec-privacy-keyjoin").await;
    let key_hash: [u8; 32] = random();
    store
        .create_api_key(&key_hash, "acme-integration", Scope::User, 1_700_000_000)
        .await
        .unwrap();
    for i in 0..20 {
        let t = 1_800_000_000 + 37 * i;
        store
            .create(&secret(Lifetime::Ttl, t + 86_400, random_blob()), t)
            .await
            .unwrap();
    }
    let t = 1_800_000_500;
    store.touch_api_key(&key_hash, t).await.unwrap();
    let mine = secret(Lifetime::Ttl, t + 86_400, random_blob());
    store.create(&mine, t).await.unwrap();

    let presets = PRESETS.map(|p| p.to_string()).join(",");
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT k.name, s.lookup_key FROM api_keys k, secrets s \
         WHERE s.expires_at - k.last_used_on IN ({presets})"
    )))
    .fetch_all(&raw)
    .await
    .unwrap();
    assert!(rows.is_empty(), "join hits: {}", rows.len());

    let sv = secret(Lifetime::SingleView, 1_900_000_000, random_blob());
    store.create(&sv, 1_800_000_900).await.unwrap();
    let t2 = 1_800_001_234;
    store.touch_api_key(&key_hash, t2).await.unwrap();
    store
        .claim(&sv.lookup_key, &random(), t2, 900)
        .await
        .unwrap()
        .unwrap();
    let rows = sqlx::query(
        "SELECT s.lookup_key FROM api_keys k, secrets s WHERE s.claim_expires_at - 900 = k.last_used_on",
    )
    .fetch_all(&raw)
    .await
    .unwrap();
    assert!(rows.is_empty(), "claim join hits: {}", rows.len());
}

// `expires_at` sits on the expiry grid (D-18), so subtracting a preset never lands on the
// creation second.
#[tokio::test]
#[ignore = "S-6"]
async fn spec_expires_at_does_not_reveal_creation_second() {
    let (store, _, raw) = open("spec-privacy-created").await;
    let created = 1_800_012_345;
    store
        .create(
            &secret(Lifetime::Ttl, created + 3 * 86_400, random_blob()),
            created,
        )
        .await
        .unwrap();
    let e: i64 = sqlx::query("SELECT expires_at FROM secrets")
        .fetch_one(&raw)
        .await
        .unwrap()
        .get("expires_at");
    // A three-day TTL rounds up to the next whole day.
    assert_eq!(e % 86_400, 0, "expires_at={e} is not on the grid");
    assert!(
        !PRESETS.iter().any(|p| e - p == created),
        "expires_at={e} minus a preset gives the creation second"
    );
}
