use crate::{Error, blob::HEADER_LEN};

pub const CHUNK_SIZE: u64 = 65536;
pub const TAG_LEN: u64 = 16;
// The length prefix inside the padding (SPEC §2.6).
pub const LENGTH_PREFIX: u64 = 4;

// How an instance rounds payloads up (SPEC §6.2). Decryption never needs this;
// only the creating client and the server's length check do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingPolicy {
    Padme { min: u64 },
    Buckets { ladder: Vec<u64> },
}

impl PaddingPolicy {
    pub const DEFAULT_MIN: u64 = 64 * 1024;

    // The padded size for `len = payload_len + 4`, or `None` when the ladder has no room.
    pub fn padded_size(&self, len: u64) -> Option<u64> {
        match self {
            Self::Padme { min } => Some(padme(len.max(*min))),
            Self::Buckets { ladder } => ladder.iter().copied().find(|&b| b >= len),
        }
    }

    pub fn is_valid_padded_size(&self, size: u64) -> bool {
        match self {
            Self::Padme { min } => size >= *min && padme(size) == size,
            Self::Buckets { ladder } => ladder.contains(&size),
        }
    }

    // The largest valid padded size at or below `size`, if any.
    pub fn largest_valid_at_most(&self, size: u64) -> Option<u64> {
        match self {
            Self::Padme { min } => {
                if size < (*min).max(2) {
                    return None;
                }
                // Clearing the bits Padmé rounds away gives the largest size it keeps unchanged.
                let e = u64::BITS - 1 - size.leading_zeros();
                let s = u32::BITS - e.leading_zeros();
                let mask = (1u64 << (e - s)) - 1;
                let kept = size & !mask;
                (kept >= *min).then_some(kept)
            }
            Self::Buckets { ladder } => ladder.iter().copied().filter(|&b| b <= size).max(),
        }
    }

    // The longest valid blob that is at most `max_len` bytes, if any. The server uses it when it
    // knows a blob's length only as an upper bound, before reading it.
    pub fn largest_blob_len_at_most(&self, max_len: u64) -> Option<u64> {
        let mut bucket = self.largest_valid_at_most(max_len.checked_sub(HEADER_LEN as u64)?)?;
        // The tags add a little on top of the bucket; step down a size until the blob fits.
        while blob_len(bucket) > max_len {
            bucket = self.largest_valid_at_most(bucket.checked_sub(1)?)?;
        }
        Some(blob_len(bucket))
    }

    // Server-side check: the bucket a blob of this length must have, if the length is valid at all.
    pub fn bucket_for_blob_len(&self, blob_len: u64) -> Result<u64, Error> {
        let body = blob_len
            .checked_sub(HEADER_LEN as u64)
            .ok_or(Error::InvalidBlobLength)?;
        let chunks = body.div_ceil(CHUNK_SIZE + TAG_LEN);
        let bucket = body
            .checked_sub(TAG_LEN * chunks)
            .filter(|&b| b > 0 && chunk_count(b) == chunks)
            .ok_or(Error::InvalidBlobLength)?;
        if self.is_valid_padded_size(bucket) {
            Ok(bucket)
        } else {
            Err(Error::InvalidBlobLength)
        }
    }
}

// Padmé (Nikitin et al., PURBs 2019): keeps only the top few bits of the length,
// so overhead is at most 12% and shrinks as sizes grow.
pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = u64::BITS - 1 - len.leading_zeros();
    let s = u32::BITS - e.leading_zeros();
    let mask = (1u64 << (e - s)) - 1;
    // Unreachable through the API (the body limit bounds every length), but never a panic.
    len.checked_add(mask).map_or(u64::MAX, |v| v & !mask)
}

pub fn chunk_count(bucket: u64) -> u64 {
    bucket.div_ceil(CHUNK_SIZE).max(1)
}

pub fn blob_len(bucket: u64) -> u64 {
    (HEADER_LEN as u64)
        .saturating_add(bucket)
        .saturating_add(TAG_LEN.saturating_mul(chunk_count(bucket)))
}

// `[payload_len: u32 BE][payload][0x00 fill]`, sized by the policy.
pub fn pad(payload: &[u8], policy: &PaddingPolicy) -> Result<Vec<u8>, Error> {
    let len = payload.len() as u64 + LENGTH_PREFIX;
    if payload.len() > u32::MAX as usize {
        return Err(Error::PayloadTooLarge);
    }
    let bucket = policy.padded_size(len).ok_or(Error::PayloadTooLarge)?;
    let mut padded = Vec::with_capacity(bucket as usize);
    padded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    padded.extend_from_slice(payload);
    padded.resize(bucket as usize, 0);
    Ok(padded)
}

pub fn unpad(padded: &[u8]) -> Result<&[u8], Error> {
    let prefix: [u8; 4] = padded
        .get(..4)
        .and_then(|p| p.try_into().ok())
        .ok_or(Error::Corrupt("padding too short"))?;
    let len = u32::from_be_bytes(prefix) as usize;
    padded
        .get(4..4 + len)
        .ok_or(Error::Corrupt("length prefix exceeds the bucket"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_examples() {
        assert_eq!(padme(65536), 65536);
        assert_eq!(padme(65537), 67584);
        assert_eq!(padme(4096), 4096);
        assert_eq!(padme(4097), 4352);
        assert_eq!(padme(1 << 20), 1 << 20);
        // Around 1 MiB the step is 32 KiB; around 64 MiB it is 2 MiB.
        assert_eq!(padme((1 << 20) + 1), (1 << 20) + (32 << 10));
        assert_eq!(padme((64 << 20) + 1), (64 << 20) + (2 << 20));
    }

    #[test]
    fn padme_output_is_a_fixed_point() {
        for len in [5u64, 100, 4097, 65537, 70000, (3 << 20) + 17] {
            let out = padme(len);
            assert!(out >= len);
            assert_eq!(padme(out), out);
        }
    }

    #[test]
    fn policies_pick_sizes() {
        let padme_policy = PaddingPolicy::Padme { min: 65536 };
        assert_eq!(padme_policy.padded_size(10), Some(65536));
        assert_eq!(padme_policy.padded_size(70004), Some(71680));
        assert!(padme_policy.is_valid_padded_size(71680));
        assert!(!padme_policy.is_valid_padded_size(4096));

        let ladder = PaddingPolicy::Buckets {
            ladder: vec![4096, 16384, 65536],
        };
        assert_eq!(ladder.padded_size(5004), Some(16384));
        assert_eq!(ladder.padded_size(65537), None);
        assert!(!ladder.is_valid_padded_size(8192));
    }

    #[test]
    fn largest_valid_size_at_or_below() {
        let padme_policy = PaddingPolicy::Padme { min: 65536 };
        assert_eq!(padme_policy.largest_valid_at_most(65535), None);
        assert_eq!(padme_policy.largest_valid_at_most(65536), Some(65536));
        assert_eq!(padme_policy.largest_valid_at_most(67583), Some(65536));
        assert_eq!(padme_policy.largest_valid_at_most(67584), Some(67584));
        // Around 1 MiB the step is 32 KiB.
        assert_eq!(
            padme_policy.largest_valid_at_most((1 << 20) + (32 << 10) - 1),
            Some(1 << 20)
        );
        for size in [65536u64, 70000, 200_000, (3 << 20) + 17, 1 << 30] {
            let kept = padme_policy.largest_valid_at_most(size).unwrap();
            assert!(kept <= size && padme_policy.is_valid_padded_size(kept));
            assert!(
                padme(kept + 1) > size,
                "{kept} is not the largest at or below {size}"
            );
        }

        let ladder = PaddingPolicy::Buckets {
            ladder: vec![65536, 262144, 1048576],
        };
        assert_eq!(ladder.largest_valid_at_most(65535), None);
        assert_eq!(ladder.largest_valid_at_most(262143), Some(65536));
        assert_eq!(ladder.largest_valid_at_most(u64::MAX), Some(1048576));
    }

    #[test]
    fn longest_blob_at_or_below_a_length() {
        let policy = PaddingPolicy::Padme { min: 65536 };
        for bucket in [65536u64, 71680, 131072, 1 << 20] {
            let len = blob_len(bucket);
            assert_eq!(policy.largest_blob_len_at_most(len), Some(len));
            // A few bytes over a valid blob are still that blob; a byte under is the one before.
            assert_eq!(policy.largest_blob_len_at_most(len + 15), Some(len));
            let below = policy.largest_blob_len_at_most(len - 1).unwrap_or(0);
            assert!(below < len);
        }
        assert_eq!(policy.largest_blob_len_at_most(blob_len(65536) - 1), None);
        assert_eq!(policy.largest_blob_len_at_most(10), None);
        let ladder = PaddingPolicy::Buckets {
            ladder: vec![65536, 1048576],
        };
        assert_eq!(
            ladder.largest_blob_len_at_most(blob_len(1048576) - 1),
            Some(blob_len(65536))
        );
    }

    #[test]
    fn blob_length_round_trips() {
        let policy = PaddingPolicy::Padme { min: 4096 };
        for bucket in [4096u64, 4352, 65536, 71680, 131072] {
            assert_eq!(policy.bucket_for_blob_len(blob_len(bucket)), Ok(bucket));
            assert_eq!(
                policy.bucket_for_blob_len(blob_len(bucket) - 16),
                Err(Error::InvalidBlobLength)
            );
            assert_eq!(
                policy.bucket_for_blob_len(blob_len(bucket) + 1),
                Err(Error::InvalidBlobLength)
            );
        }
        assert_eq!(
            policy.bucket_for_blob_len(10),
            Err(Error::InvalidBlobLength)
        );
    }

    #[test]
    fn pad_and_unpad() {
        let policy = PaddingPolicy::Padme { min: 4096 };
        let padded = pad(b"hello", &policy).unwrap();
        assert_eq!(padded.len(), 4096);
        assert_eq!(unpad(&padded).unwrap(), b"hello");

        let mut bad = padded.clone();
        bad[..4].copy_from_slice(&4096u32.to_be_bytes());
        assert!(unpad(&bad).is_err());
    }
}
