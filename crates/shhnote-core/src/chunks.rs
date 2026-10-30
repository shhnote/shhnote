use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Nonce},
};

use crate::{
    Error,
    blob::NONCE_PREFIX_LEN,
    padding::{CHUNK_SIZE, TAG_LEN},
};

// Encrypts the padded plaintext 64 KiB at a time (SPEC §2.7). Every chunk gets its own nonce,
// built from the prefix, its index and a last-chunk flag, so chunks cannot be reordered,
// dropped or truncated without a tag failing.
pub struct ChunkCipher {
    cipher: Aes256Gcm,
    prefix: [u8; NONCE_PREFIX_LEN],
}

impl ChunkCipher {
    pub fn new(ek: &[u8; 32], prefix: [u8; NONCE_PREFIX_LEN]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(ek).expect("32-byte key"),
            prefix,
        }
    }

    fn nonce(&self, index: u32, last: bool) -> Nonce<Aes256Gcm> {
        let mut nonce = [0u8; 12];
        nonce[..7].copy_from_slice(&self.prefix);
        nonce[7..11].copy_from_slice(&index.to_be_bytes());
        nonce[11] = u8::from(last);
        Nonce::<Aes256Gcm>::from(nonce)
    }

    pub fn seal(&self, index: u32, last: bool, chunk: &[u8]) -> Vec<u8> {
        self.cipher
            .encrypt(&self.nonce(index, last), chunk)
            .expect("AES-GCM encryption cannot fail on in-memory data")
    }

    pub fn open(&self, index: u32, last: bool, sealed: &[u8]) -> Result<Vec<u8>, Error> {
        self.cipher
            .decrypt(&self.nonce(index, last), sealed)
            .map_err(|_| Error::Corrupt("chunk failed to authenticate"))
    }

    pub fn seal_all(&self, padded: &[u8]) -> Vec<u8> {
        let count = padded.len().div_ceil(CHUNK_SIZE as usize).max(1);
        let mut out = Vec::with_capacity(padded.len() + count * TAG_LEN as usize);
        let mut chunks = padded.chunks(CHUNK_SIZE as usize).peekable();
        let mut index = 0u32;
        // An empty input still produces one (empty) sealed chunk carrying the last flag.
        if chunks.peek().is_none() {
            return self.seal(0, true, &[]);
        }
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            out.extend_from_slice(&self.seal(index, last, chunk));
            index += 1;
        }
        out
    }

    // The sealed body's length says where every chunk starts: all but the last are exactly
    // 64 KiB + 16 bytes. The final chunk is opened with the last flag set, so a body cut short
    // fails there, which is how truncation is detected.
    pub fn open_all(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        let sealed_len = (CHUNK_SIZE + TAG_LEN) as usize;
        let count = body.len().div_ceil(sealed_len);
        if count == 0 || body.len() < count * TAG_LEN as usize {
            return Err(Error::InvalidBlobLength);
        }
        let mut out = Vec::with_capacity(body.len() - count * TAG_LEN as usize);
        let mut chunks = body.chunks(sealed_len).peekable();
        let mut index = 0u32;
        while let Some(sealed) = chunks.next() {
            let last = chunks.peek().is_none();
            out.extend_from_slice(&self.open(index, last, sealed)?);
            index += 1;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> ChunkCipher {
        ChunkCipher::new(&[9; 32], [1, 2, 3, 4, 5, 6, 7])
    }

    #[test]
    fn round_trips_across_chunk_boundaries() {
        let cipher = cipher();
        for len in [0usize, 1, 65535, 65536, 65537, 150_000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let body = cipher.seal_all(&data);
            let expected_chunks = len.div_ceil(65536).max(1);
            assert_eq!(body.len(), len + 16 * expected_chunks, "{len}");
            assert_eq!(cipher.open_all(&body).unwrap(), data, "{len}");
        }
    }

    #[test]
    fn detects_truncation_reordering_and_tampering() {
        let cipher = cipher();
        let data = vec![7u8; 150_000];
        let body = cipher.seal_all(&data);

        // Dropping the final chunk makes chunk 1 the last one, which it was not sealed as.
        assert!(cipher.open_all(&body[..65552 * 2]).is_err());
        // Swapping two full chunks breaks their indexes.
        let mut swapped = body.clone();
        swapped[..65552].copy_from_slice(&body[65552..65552 * 2]);
        swapped[65552..65552 * 2].copy_from_slice(&body[..65552]);
        assert!(cipher.open_all(&swapped).is_err());
        // One flipped bit anywhere fails that chunk's tag.
        let mut tampered = body.clone();
        tampered[100_000] ^= 1;
        assert!(cipher.open_all(&tampered).is_err());
    }
}
