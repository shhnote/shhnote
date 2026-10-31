use std::fmt;

use crate::fragment::Kind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // The fragment is not 44 base64url characters decoding to 33 bytes.
    InvalidFragment,
    // The first byte names no known suite or role.
    UnsupportedVersion(u8),
    // A share fragment where a burn fragment was expected, or the other way round.
    WrongKind { expected: Kind, found: Kind },
    // The blob's length does not match any valid padded size.
    InvalidBlobLength,
    // Argon2 parameters in the header are outside the client bounds (a hostile or corrupt blob).
    Argon2OutOfBounds,
    // The direct unwrap failed and no passphrase was given.
    PassphraseRequired,
    // A passphrase was given but is the empty string: never "no passphrase", always an error
    // at the API boundary (§2.10).
    EmptyPassphrase,
    // A passphrase was given but the unwrap still failed.
    WrongPassphrase,
    // Authentication or structure failure after the key was unwrapped.
    Corrupt(&'static str),
    // A payload needs at least text or one file.
    EmptyPayload,
    PayloadTooLarge,
    Manifest(String),
    Random,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFragment => f.write_str("the link fragment is malformed"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported fragment version {v}"),
            Self::WrongKind { expected, found } => write!(
                f,
                "a {} link was given where a {} link was expected",
                found.as_str(),
                expected.as_str()
            ),
            Self::InvalidBlobLength => f.write_str("blob length matches no valid padded size"),
            Self::Argon2OutOfBounds => f.write_str("Argon2 parameters are out of bounds"),
            Self::PassphraseRequired => f.write_str("a passphrase is required"),
            Self::EmptyPassphrase => f.write_str("a passphrase cannot be empty; omit it instead"),
            Self::WrongPassphrase => f.write_str("wrong passphrase"),
            Self::Corrupt(what) => write!(f, "blob is corrupt: {what}"),
            Self::EmptyPayload => f.write_str("a secret needs text or at least one file"),
            Self::PayloadTooLarge => f.write_str("payload is larger than the biggest allowed size"),
            Self::Manifest(reason) => write!(f, "manifest is invalid: {reason}"),
            Self::Random => f.write_str("the system random number generator failed"),
        }
    }
}

impl std::error::Error for Error {}
