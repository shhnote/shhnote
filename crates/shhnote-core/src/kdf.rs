use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::Error;

// Frozen: changing any of these is a new fragment version (SPEC §2.3, §2.13).
pub const INFO_LOOKUP: &[u8] = b"shhnote/lookup/v1";
pub const INFO_KEK_DIRECT: &[u8] = b"shhnote/kek-direct/v1";
pub const INFO_KEK_PASS: &[u8] = b"shhnote/kek-pass/v1";

pub const SALT_LEN: usize = 16;

// SPEC §2.9. `m` is in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Argon2Params {
    pub const DEFAULT: Self = Self {
        m: 64 * 1024,
        t: 3,
        p: 1,
    };
    pub const MIN: Self = Self {
        m: 8 * 1024,
        t: 1,
        p: 1,
    };
    pub const MAX: Self = Self {
        m: 256 * 1024,
        t: 8,
        p: 4,
    };

    // A blob can name any cost it likes, so this check must run before the KDF does.
    pub fn check_bounds(self) -> Result<Self, Error> {
        let ok = (Self::MIN.m..=Self::MAX.m).contains(&self.m)
            && (Self::MIN.t..=Self::MAX.t).contains(&self.t)
            && (Self::MIN.p..=Self::MAX.p).contains(&self.p);
        if ok {
            Ok(self)
        } else {
            Err(Error::Argon2OutOfBounds)
        }
    }
}

// HKDF-SHA-256 with an empty salt, which RFC 5869 defines as HashLen zero bytes.
pub fn hkdf(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, &mut out)
        .expect("32 bytes is far below the HKDF output limit");
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn argon2id(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
) -> Result<[u8; 32], Error> {
    let params = params.check_bounds()?;
    let params = Params::new(params.m, params.t, params.p, Some(32))
        .map_err(|_| Error::Argon2OutOfBounds)?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|_| Error::Argon2OutOfBounds)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_enforced() {
        assert!(Argon2Params::DEFAULT.check_bounds().is_ok());
        assert!(Argon2Params::MIN.check_bounds().is_ok());
        assert!(Argon2Params::MAX.check_bounds().is_ok());
        for bad in [
            Argon2Params {
                m: 4096,
                ..Argon2Params::DEFAULT
            },
            Argon2Params {
                m: 1 << 30,
                ..Argon2Params::DEFAULT
            },
            Argon2Params {
                t: 0,
                ..Argon2Params::DEFAULT
            },
            Argon2Params {
                t: 9,
                ..Argon2Params::DEFAULT
            },
            Argon2Params {
                p: 5,
                ..Argon2Params::DEFAULT
            },
        ] {
            assert_eq!(bad.check_bounds(), Err(Error::Argon2OutOfBounds));
        }
    }

    #[test]
    fn hkdf_matches_rfc_5869_test_case_1() {
        // RFC 5869 appendix A.1, truncated to 32 bytes; salt there is non-empty, so use extract directly.
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut out = [0u8; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut out)
            .unwrap();
        assert_eq!(out[..8], [0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a]);
    }
}
