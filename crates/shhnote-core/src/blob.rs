use crate::{
    Error,
    kdf::{Argon2Params, SALT_LEN},
};

pub const WRAP_IV_LEN: usize = 12;
pub const WRAPPED_EK_LEN: usize = 48;
pub const NONCE_PREFIX_LEN: usize = 7;
pub const HEADER_LEN: usize = SALT_LEN + 12 + WRAP_IV_LEN + WRAPPED_EK_LEN + NONCE_PREFIX_LEN;

// The fixed 95-byte header in front of the ciphertext chunks (SPEC §2.8).
// Identical in shape for direct and passphrase blobs; there is no mode, version or flags field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub salt: [u8; SALT_LEN],
    pub argon: Argon2Params,
    pub wrap_iv: [u8; WRAP_IV_LEN],
    pub wrapped_ek: [u8; WRAPPED_EK_LEN],
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..16].copy_from_slice(&self.salt);
        out[16..20].copy_from_slice(&self.argon.m.to_be_bytes());
        out[20..24].copy_from_slice(&self.argon.t.to_be_bytes());
        out[24..28].copy_from_slice(&self.argon.p.to_be_bytes());
        out[28..40].copy_from_slice(&self.wrap_iv);
        out[40..88].copy_from_slice(&self.wrapped_ek);
        out[88..95].copy_from_slice(&self.nonce_prefix);
        out
    }

    // Parses and bounds-checks the Argon2 parameters, so a hostile blob is refused before any KDF runs.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::InvalidBlobLength);
        }
        let u32_at = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
        let argon = Argon2Params {
            m: u32_at(16),
            t: u32_at(20),
            p: u32_at(24),
        }
        .check_bounds()?;
        Ok(Self {
            salt: bytes[..16].try_into().unwrap(),
            argon,
            wrap_iv: bytes[28..40].try_into().unwrap(),
            wrapped_ek: bytes[40..88].try_into().unwrap(),
            nonce_prefix: bytes[88..95].try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_95_bytes_and_round_trips() {
        assert_eq!(HEADER_LEN, 95);
        let header = Header {
            salt: [1; 16],
            argon: Argon2Params::DEFAULT,
            wrap_iv: [2; 12],
            wrapped_ek: [3; 48],
            nonce_prefix: [4; 7],
        };
        let bytes = header.to_bytes();
        assert_eq!(&bytes[16..20], &65536u32.to_be_bytes());
        assert_eq!(Header::parse(&bytes).unwrap(), header);
        assert_eq!(Header::parse(&bytes[..94]), Err(Error::InvalidBlobLength));
    }

    #[test]
    fn rejects_out_of_bounds_argon_before_anything_else() {
        let mut bytes = Header {
            salt: [0; 16],
            argon: Argon2Params {
                m: 1 << 30,
                ..Argon2Params::DEFAULT
            },
            wrap_iv: [0; 12],
            wrapped_ek: [0; 48],
            nonce_prefix: [0; 7],
        }
        .to_bytes()
        .to_vec();
        bytes.extend_from_slice(&[0; 4112]);
        assert_eq!(Header::parse(&bytes), Err(Error::Argon2OutOfBounds));
    }
}
