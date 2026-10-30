use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Nonce},
};
use zeroize::Zeroizing;

use crate::{
    Error,
    blob::{HEADER_LEN, Header, NONCE_PREFIX_LEN, WRAP_IV_LEN},
    chunks::ChunkCipher,
    container::Payload,
    fragment::Fragment,
    kdf::{self, Argon2Params, SALT_LEN},
    padding::{self, PaddingPolicy},
};

// Every random value a secret needs, generated once per secret. Tests inject fixed values
// from the conformance vectors; real callers use `generate`.
pub struct Randomness {
    pub seed: Zeroizing<[u8; 32]>,
    pub burn_token: Zeroizing<[u8; 32]>,
    pub ek: Zeroizing<[u8; 32]>,
    pub salt: [u8; SALT_LEN],
    pub wrap_iv: [u8; WRAP_IV_LEN],
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl Randomness {
    pub fn generate() -> Result<Self, Error> {
        let mut r = Self {
            seed: Zeroizing::new([0; 32]),
            burn_token: Zeroizing::new([0; 32]),
            ek: Zeroizing::new([0; 32]),
            salt: [0; SALT_LEN],
            wrap_iv: [0; WRAP_IV_LEN],
            nonce_prefix: [0; NONCE_PREFIX_LEN],
        };
        for buf in [&mut r.seed[..], &mut r.burn_token[..], &mut r.ek[..]] {
            getrandom::fill(buf).map_err(|_| Error::Random)?;
        }
        getrandom::fill(&mut r.salt).map_err(|_| Error::Random)?;
        getrandom::fill(&mut r.wrap_iv).map_err(|_| Error::Random)?;
        getrandom::fill(&mut r.nonce_prefix).map_err(|_| Error::Random)?;
        Ok(r)
    }
}

// What the creating client ends up with: the blob to upload, the values the server stores,
// and the two links to show the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    pub blob: Vec<u8>,
    pub bucket: u64,
    pub fragment: String,
    pub burn_fragment: String,
    // Sent to the server at creation (hashed); the preimages are sent when the secret is used.
    pub lookup_key: [u8; 32],
    pub burn_key: [u8; 32],
}

// The value a client sends to find a secret; the server stores only `credential_hash` of it.
pub fn lookup(seed: &[u8; 32]) -> [u8; 32] {
    kdf::hkdf(seed, kdf::INFO_LOOKUP)
}

pub fn credential_hash(value: &[u8]) -> [u8; 32] {
    kdf::sha256(value)
}

fn kek_direct(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(kdf::hkdf(seed, kdf::INFO_KEK_DIRECT))
}

fn kek_pass(
    seed: &[u8; 32],
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    argon: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let pass_key = Zeroizing::new(kdf::argon2id(passphrase, salt, argon)?);
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(seed);
    ikm[32..].copy_from_slice(&*pass_key);
    Ok(Zeroizing::new(kdf::hkdf(&*ikm, kdf::INFO_KEK_PASS)))
}

fn wrap(kek: &[u8; 32], wrap_iv: &[u8; WRAP_IV_LEN], ek: &[u8; 32]) -> [u8; 48] {
    Aes256Gcm::new_from_slice(kek)
        .expect("32-byte key")
        .encrypt(&Nonce::<Aes256Gcm>::from(*wrap_iv), &ek[..])
        .expect("AES-GCM encryption cannot fail on in-memory data")
        .try_into()
        .expect("32 bytes plus a 16-byte tag")
}

fn unwrap(
    kek: &[u8; 32],
    wrap_iv: &[u8; WRAP_IV_LEN],
    wrapped: &[u8; 48],
) -> Option<Zeroizing<[u8; 32]>> {
    let ek = Aes256Gcm::new_from_slice(kek)
        .expect("32-byte key")
        .decrypt(&Nonce::<Aes256Gcm>::from(*wrap_iv), &wrapped[..])
        .ok()?;
    Some(Zeroizing::new(ek.as_slice().try_into().ok()?))
}

pub fn encrypt(
    rand: &Randomness,
    payload: &Payload,
    passphrase: Option<&str>,
    argon: Argon2Params,
    policy: &PaddingPolicy,
) -> Result<Encrypted, Error> {
    let argon = argon.check_bounds()?;
    let kek = match passphrase {
        None => kek_direct(&rand.seed),
        Some(passphrase) => kek_pass(&rand.seed, passphrase, &rand.salt, argon)?,
    };
    let header = Header {
        salt: rand.salt,
        // In direct mode these are filler; the layout stays identical to a passphrase blob.
        argon,
        wrap_iv: rand.wrap_iv,
        wrapped_ek: wrap(&kek, &rand.wrap_iv, &rand.ek),
        nonce_prefix: rand.nonce_prefix,
    };

    let padded = Zeroizing::new(padding::pad(&payload.encode()?, policy)?);
    let bucket = padded.len() as u64;
    let mut blob = Vec::with_capacity(padding::blob_len(bucket) as usize);
    blob.extend_from_slice(&header.to_bytes());
    blob.extend_from_slice(&ChunkCipher::new(&rand.ek, rand.nonce_prefix).seal_all(&padded));
    debug_assert_eq!(blob.len() as u64, padding::blob_len(bucket));

    Ok(Encrypted {
        blob,
        bucket,
        fragment: Fragment::new(*rand.seed).encode(),
        burn_fragment: Fragment::new(*rand.burn_token).encode(),
        lookup_key: credential_hash(&lookup(&rand.seed)),
        burn_key: credential_hash(&*rand.burn_token),
    })
}

// SPEC §2.10. Tries direct mode first; a failed unwrap is the only signal that a passphrase is needed.
pub fn decrypt(blob: &[u8], seed: &[u8; 32], passphrase: Option<&str>) -> Result<Payload, Error> {
    let header = Header::parse(blob)?;
    let ek = match unwrap(&kek_direct(seed), &header.wrap_iv, &header.wrapped_ek) {
        Some(ek) => ek,
        None => {
            let passphrase = passphrase.ok_or(Error::PassphraseRequired)?;
            let kek = kek_pass(seed, passphrase, &header.salt, header.argon)?;
            unwrap(&kek, &header.wrap_iv, &header.wrapped_ek).ok_or(Error::WrongPassphrase)?
        }
    };
    let padded =
        Zeroizing::new(ChunkCipher::new(&ek, header.nonce_prefix).open_all(&blob[HEADER_LEN..])?);
    Payload::decode(padding::unpad(&padded)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::File;

    fn randomness() -> Randomness {
        let mut r = Randomness::generate().unwrap();
        // Keep the test deterministic apart from the values that must differ per call.
        r.salt = [5; SALT_LEN];
        r
    }

    fn payload() -> Payload {
        Payload {
            text: Some("the password is hunter2".into()),
            files: vec![File {
                name: "key.txt".into(),
                mime: "text/plain".into(),
                bytes: vec![1, 2, 3],
            }],
        }
    }

    #[test]
    fn direct_round_trip_and_passphrase_round_trip_have_identical_shape() {
        let policy = PaddingPolicy::Padme { min: 4096 };
        let fast = Argon2Params::MIN;
        let direct = encrypt(&randomness(), &payload(), None, fast, &policy).unwrap();
        let with_pass = encrypt(&randomness(), &payload(), Some("pw"), fast, &policy).unwrap();
        assert_eq!(direct.blob.len(), with_pass.blob.len());
        assert_eq!(direct.bucket, 4096);

        let seed = Fragment::decode(&direct.fragment).unwrap().bytes;
        assert_eq!(decrypt(&direct.blob, &seed, None).unwrap(), payload());
        // A passphrase offered to a direct-mode blob is simply unused.
        assert_eq!(
            decrypt(&direct.blob, &seed, Some("ignored")).unwrap(),
            payload()
        );

        let seed = Fragment::decode(&with_pass.fragment).unwrap().bytes;
        assert_eq!(
            decrypt(&with_pass.blob, &seed, None),
            Err(Error::PassphraseRequired)
        );
        assert_eq!(
            decrypt(&with_pass.blob, &seed, Some("nope")),
            Err(Error::WrongPassphrase)
        );
        assert_eq!(
            decrypt(&with_pass.blob, &seed, Some("pw")).unwrap(),
            payload()
        );
    }

    #[test]
    fn wrong_seed_looks_like_a_missing_passphrase() {
        let policy = PaddingPolicy::Padme { min: 4096 };
        let secret = encrypt(&randomness(), &payload(), None, Argon2Params::MIN, &policy).unwrap();
        assert_eq!(
            decrypt(&secret.blob, &[0; 32], None),
            Err(Error::PassphraseRequired)
        );
    }

    #[test]
    fn generate_produces_distinct_values() {
        let a = Randomness::generate().unwrap();
        let b = Randomness::generate().unwrap();
        assert_ne!(*a.seed, *b.seed);
        assert_ne!(*a.ek, *b.ek);
        assert_ne!(a.seed, a.burn_token);
    }
}
