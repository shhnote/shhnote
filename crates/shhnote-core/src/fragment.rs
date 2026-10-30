use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::Error;

// The only suite defined so far (SPEC §2).
pub const VERSION: u8 = 1;
pub const FRAGMENT_CHARS: usize = 44;

// What a share or burn link carries after `#`: a version byte and 32 bytes of random material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub version: u8,
    pub bytes: [u8; 32],
}

impl Fragment {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            version: VERSION,
            bytes,
        }
    }

    pub fn encode(&self) -> String {
        let mut raw = [0u8; 33];
        raw[0] = self.version;
        raw[1..].copy_from_slice(&self.bytes);
        URL_SAFE_NO_PAD.encode(raw)
    }

    // Accepts only the exact shape; a fragment of any other length is not ours.
    pub fn decode(text: &str) -> Result<Self, Error> {
        let text = text.strip_prefix('#').unwrap_or(text);
        if text.len() != FRAGMENT_CHARS {
            return Err(Error::InvalidFragment);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| Error::InvalidFragment)?;
        let (version, rest) = raw.split_first().ok_or(Error::InvalidFragment)?;
        let bytes: [u8; 32] = rest.try_into().map_err(|_| Error::InvalidFragment)?;
        if *version != VERSION {
            return Err(Error::UnsupportedVersion(*version));
        }
        Ok(Self {
            version: *version,
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_fixed_length() {
        let fragment = Fragment::new([7u8; 32]);
        let text = fragment.encode();
        assert_eq!(text.len(), FRAGMENT_CHARS);
        assert_eq!(Fragment::decode(&text).unwrap(), fragment);
        assert_eq!(Fragment::decode(&format!("#{text}")).unwrap(), fragment);
    }

    #[test]
    fn rejects_other_shapes() {
        assert_eq!(Fragment::decode(""), Err(Error::InvalidFragment));
        assert_eq!(Fragment::decode("abc"), Err(Error::InvalidFragment));
        let padded = format!("{}=", &Fragment::new([1; 32]).encode()[..43]);
        assert_eq!(Fragment::decode(&padded), Err(Error::InvalidFragment));

        let mut raw = [0u8; 33];
        raw[0] = 2;
        let text = URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(Fragment::decode(&text), Err(Error::UnsupportedVersion(2)));
    }
}
