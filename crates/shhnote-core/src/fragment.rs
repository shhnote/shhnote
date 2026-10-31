use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::Error;

// The only suite defined so far (SPEC §2). The kind byte names the suite and the link's role.
pub const VERSION: u8 = 1;
pub const FRAGMENT_CHARS: usize = 44;

// Which link a fragment belongs to. A burn fragment must be told apart from a share fragment
// before anything is derived or sent (D-2), so the two have different first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Share,
    Burn,
}

impl Kind {
    pub fn byte(self) -> u8 {
        match self {
            Self::Share => 0x01,
            Self::Burn => 0x02,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Share),
            0x02 => Some(Self::Burn),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Share => "share",
            Self::Burn => "burn",
        }
    }
}

// What a share or burn link carries after `#`: a kind byte and 32 bytes of random material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub kind: Kind,
    pub bytes: [u8; 32],
}

impl Fragment {
    pub fn share(seed: [u8; 32]) -> Self {
        Self {
            kind: Kind::Share,
            bytes: seed,
        }
    }

    pub fn burn(token: [u8; 32]) -> Self {
        Self {
            kind: Kind::Burn,
            bytes: token,
        }
    }

    pub fn encode(&self) -> String {
        let mut raw = [0u8; 33];
        raw[0] = self.kind.byte();
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
        let (first, rest) = raw.split_first().ok_or(Error::InvalidFragment)?;
        let bytes: [u8; 32] = rest.try_into().map_err(|_| Error::InvalidFragment)?;
        let kind = Kind::from_byte(*first).ok_or(Error::UnsupportedVersion(*first))?;
        Ok(Self { kind, bytes })
    }

    // Decodes a fragment that must be of `expected` kind: a share link given to the burn
    // page, or the other way round, is refused before anything is derived from it.
    pub fn decode_as(text: &str, expected: Kind) -> Result<[u8; 32], Error> {
        let fragment = Self::decode(text)?;
        if fragment.kind != expected {
            return Err(Error::WrongKind {
                expected,
                found: fragment.kind,
            });
        }
        Ok(fragment.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_fixed_length() {
        let fragment = Fragment::share([7u8; 32]);
        let text = fragment.encode();
        assert_eq!(text.len(), FRAGMENT_CHARS);
        assert_eq!(Fragment::decode(&text).unwrap(), fragment);
        assert_eq!(Fragment::decode(&format!("#{text}")).unwrap(), fragment);

        let burn = Fragment::burn([9u8; 32]);
        assert_eq!(Fragment::decode(&burn.encode()).unwrap(), burn);
        assert_ne!(Fragment::share([9u8; 32]).encode(), burn.encode());
    }

    #[test]
    fn kinds_are_told_apart_before_use() {
        let share = Fragment::share([1u8; 32]).encode();
        let burn = Fragment::burn([2u8; 32]).encode();
        assert_eq!(Fragment::decode_as(&share, Kind::Share), Ok([1u8; 32]));
        assert_eq!(Fragment::decode_as(&burn, Kind::Burn), Ok([2u8; 32]));
        assert_eq!(
            Fragment::decode_as(&share, Kind::Burn),
            Err(Error::WrongKind {
                expected: Kind::Burn,
                found: Kind::Share,
            })
        );
        assert_eq!(
            Fragment::decode_as(&burn, Kind::Share),
            Err(Error::WrongKind {
                expected: Kind::Share,
                found: Kind::Burn,
            })
        );
    }

    #[test]
    fn rejects_other_shapes() {
        assert_eq!(Fragment::decode(""), Err(Error::InvalidFragment));
        assert_eq!(Fragment::decode("abc"), Err(Error::InvalidFragment));
        let padded = format!("{}=", &Fragment::share([1; 32]).encode()[..43]);
        assert_eq!(Fragment::decode(&padded), Err(Error::InvalidFragment));

        let mut raw = [0u8; 33];
        raw[0] = 3;
        let text = URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(Fragment::decode(&text), Err(Error::UnsupportedVersion(3)));
    }
}
