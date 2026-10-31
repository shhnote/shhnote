// Regression tests from the security review (docs/security-review/findings/SUMMARY.md) for the
// protocol pieces the conformance vectors do not pin: length math at the edges and the few
// parser decisions that have no vector yet. Ignored tests are waiting for the step that fixes
// their finding; un-ignore them with the fix.
use shhnote_core::{
    Error,
    container::Payload,
    fragment::Fragment,
    kdf::Argon2Params,
    padding::{PaddingPolicy, blob_len, chunk_count, padme},
    secret::{self, Randomness},
};

const CHUNK: u64 = 65536;

// Every bucket near a chunk boundary round-trips, and every blob length near it maps to at
// most one bucket whose blob length is exactly that length.
#[test]
fn spec_blob_len_and_bucket_agree_around_chunk_boundaries() {
    let any = PaddingPolicy::Padme { min: 1 };
    for k in 0..40u64 {
        for delta in -40i64..=40 {
            let bucket = (k * CHUNK) as i64 + delta;
            if bucket <= 0 {
                continue;
            }
            let bucket = bucket as u64;
            let n = blob_len(bucket);
            assert_eq!(chunk_count(bucket), bucket.div_ceil(CHUNK).max(1));
            if any.is_valid_padded_size(bucket) {
                assert_eq!(any.bucket_for_blob_len(n), Ok(bucket), "bucket {bucket}");
            }
        }
    }
    // Inverse direction: every length in a window either fails or maps back exactly.
    for n in 0..(3 * (CHUNK + 16) + 400) {
        if let Ok(bucket) = any.bucket_for_blob_len(n) {
            assert!(bucket > 0);
            assert_eq!(blob_len(bucket), n, "length {n}");
        }
    }
    // Lengths that are not a ladder entry under a real policy are refused.
    let real = PaddingPolicy::Padme { min: 65536 };
    for n in 0..(blob_len(65536)) {
        assert!(real.bucket_for_blob_len(n).is_err(), "length {n}");
    }
}

// Padmé fixed points stay fixed and never shrink, for every power-of-two neighbourhood up to 2^40.
#[test]
fn spec_padme_edges() {
    for bits in 1..40u32 {
        let base = 1u64 << bits;
        for len in [base - 1, base, base + 1, base + 3] {
            let p = padme(len);
            assert!(p >= len);
            assert_eq!(padme(p), p);
            // Overhead never above 12% (SPEC §6.2) once lengths leave the tiny range.
            if len >= 256 {
                assert!((p - len) * 100 <= len * 12, "{len} -> {p}");
            }
        }
    }
}

// Extreme inputs must fail cleanly, not overflow (SPEC §7.2: arithmetic on sizes is checked).
#[test]
#[ignore = "S-10"]
fn spec_extreme_lengths_do_not_panic() {
    let policy = PaddingPolicy::Padme { min: 65536 };
    let mut panics = Vec::new();
    for n in [
        u64::MAX,
        u64::MAX - 1,
        u64::MAX - 95,
        u64::MAX / 2,
        1 << 63,
        u32::MAX as u64 + 1,
    ] {
        if std::panic::catch_unwind(|| policy.bucket_for_blob_len(n)).is_err() {
            panics.push(format!("bucket_for_blob_len({n})"));
        }
        if std::panic::catch_unwind(|| padme(n)).is_err() {
            panics.push(format!("padme({n})"));
        }
        if std::panic::catch_unwind(|| blob_len(n)).is_err() {
            panics.push(format!("blob_len({n})"));
        }
    }
    assert!(panics.is_empty(), "overflow panics: {panics:?}");
}

// An empty passphrase is a passphrase here. The TypeScript client reads "" as "no passphrase"
// (S-46); whichever meaning the spec settles on, both sides must agree, and this pins today's.
#[test]
fn spec_empty_passphrase_is_a_passphrase() {
    let rand = Randomness::generate().unwrap();
    let payload = Payload {
        text: Some("empty-pass".into()),
        files: vec![],
    };
    let policy = PaddingPolicy::Padme { min: 4096 };
    let out = secret::encrypt(&rand, &payload, Some(""), Argon2Params::MIN, &policy).unwrap();
    let seed = Fragment::decode(&out.fragment).unwrap().bytes;
    assert_eq!(
        secret::decrypt(&out.blob, &seed, None),
        Err(Error::PassphraseRequired)
    );
    assert_eq!(
        secret::decrypt(&out.blob, &seed, Some("")).unwrap(),
        payload
    );
}

// Whitespace inside or around a fragment is never tolerated (the alphabet and padding cases
// are in the vectors).
#[test]
fn spec_fragment_rejects_whitespace() {
    let good = Fragment::share([0xfb; 32]).encode();
    assert_eq!(
        Fragment::decode(&format!("{good} ")),
        Err(Error::InvalidFragment)
    );
    assert_eq!(
        Fragment::decode(&format!(" {}", &good[1..])),
        Err(Error::InvalidFragment)
    );
    assert_eq!(
        Fragment::decode(&format!("{}\n{}", &good[..20], &good[21..])),
        Err(Error::InvalidFragment)
    );
}
