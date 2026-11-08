use shhnote_core::{
    expiry::{claim_expires_at, expires_at, grid},
    padding::{PaddingPolicy, blob_len, chunk_count, padme},
};

// D-18: the grid boundaries are exactly 1 h and 3 days; rounding is always up, never past
// one grid step, and extreme inputs saturate instead of overflowing.
#[test]
fn spec_expiry_grid_boundaries_and_extremes() {
    assert_eq!(grid(0), 300);
    assert_eq!(grid(60), 300);
    assert_eq!(grid(3599), 300);
    assert_eq!(grid(3600), 3600);
    assert_eq!(grid(86_400), 3600);
    assert_eq!(grid(259_199), 3600);
    assert_eq!(grid(259_200), 86_400);
    assert_eq!(grid(14 * 86_400), 86_400);
    assert_eq!(grid(i64::MAX), 86_400);
    // Negative or zero TTLs are refused by the handler; the function itself must not panic.
    assert_eq!(grid(-1), 300);
    assert_eq!(grid(i64::MIN), 300);
    for now in [0i64, 1, 299, 300, 1_800_012_345, i64::MAX - 1, i64::MAX] {
        for ttl in [60i64, 3599, 3600, 259_199, 259_200, 14 * 86_400] {
            let e = expires_at(now, ttl);
            let g = grid(ttl);
            assert!(e == i64::MAX || e % g == 0, "now {now} ttl {ttl}");
            assert!(e >= now.saturating_add(ttl), "now {now} ttl {ttl}");
            assert!(
                e - now.saturating_add(ttl) < g || e == i64::MAX,
                "now {now} ttl {ttl}"
            );
        }
        let _ = expires_at(now, i64::MIN);
        let _ = expires_at(now, i64::MAX);
        let _ = expires_at(now, -60);
        let _ = claim_expires_at(now, 60);
        let _ = claim_expires_at(now, 86_400);
        let _ = claim_expires_at(now, i64::MAX);
        let _ = claim_expires_at(now, i64::MIN);
    }
    let _ = expires_at(i64::MIN, 60);
    let _ = claim_expires_at(i64::MIN, 60);
    // 1_000_020 is a whole minute (60 × 16 667).
    assert_eq!(claim_expires_at(1_000_020, 900), 1_000_920);
    assert_eq!(claim_expires_at(1_000_020 + 59, 60), 1_000_140);
    assert_eq!(claim_expires_at(1_000_020 + 60, 60), 1_000_140);
    assert_eq!(claim_expires_at(1_000_020 + 61, 60), 1_000_200);
}

// The padded-size helpers at the ends of their domains: no panic, no wrap.
#[test]
fn spec_padding_helpers_on_extreme_sizes() {
    for size in [
        0u64,
        1,
        2,
        3,
        65_535,
        65_536,
        u32::MAX as u64,
        u64::MAX - 1,
        u64::MAX,
    ] {
        let _ = padme(size);
        let _ = chunk_count(size);
        let _ = blob_len(size);
        for policy in [
            PaddingPolicy::Padme { min: 65_536 },
            PaddingPolicy::Padme { min: 2 },
            PaddingPolicy::Buckets {
                ladder: vec![65_536, 1 << 20],
            },
            PaddingPolicy::Buckets { ladder: vec![] },
        ] {
            let _ = policy.padded_size(size);
            let _ = policy.is_valid_padded_size(size);
            let _ = policy.largest_valid_at_most(size);
            let _ = policy.largest_blob_len_at_most(size);
            let _ = policy.bucket_for_blob_len(size);
        }
    }
    assert_eq!(padme(u64::MAX), u64::MAX);
    assert_eq!(blob_len(u64::MAX), u64::MAX);
    assert_eq!(chunk_count(0), 1);
    assert_eq!(blob_len(0), 95 + 16);
    // An empty ladder stores nothing: every check says no rather than panicking.
    let empty = PaddingPolicy::Buckets { ladder: vec![] };
    assert_eq!(empty.padded_size(10), None);
    assert_eq!(empty.largest_blob_len_at_most(u64::MAX), None);
}

// From 1019 chunks on, the header and tags alone exceed 16 KiB. That is why the route body
// limit starts from `blob_len(max_blob_bytes)` and not from `max_blob_bytes + 16 KiB`:
// otherwise the largest advertised bucket (SPEC §4) could not be uploaded.
#[test]
fn spec_framing_overhead_exceeds_16_kib_from_1019_chunks() {
    let slack = 16 * 1024;
    assert!(blob_len(2 << 20) <= (2 << 20) + slack);
    assert!(blob_len(62 << 20) <= (62 << 20) + slack);
    assert!(blob_len(64 << 20) > (64 << 20) + slack);
    assert!(blob_len(4 << 30) > (4 << 30) + slack);
    // The first bucket for which it fails.
    let first = (0..=1024u64)
        .map(|chunks| chunks * 65_536)
        .find(|&b| blob_len(b) > b + slack)
        .unwrap();
    assert_eq!(first, 1019 * 65_536);
}
