use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use shhnote_core::{
    Error,
    blob::Header,
    container::{File, Payload},
    fragment::Fragment,
    kdf::{self, Argon2Params},
    padding::PaddingPolicy,
    secret::{self, Randomness},
};
use zeroize::Zeroizing;

const VECTORS: &str = include_str!("../../../vectors/v1.json");

#[derive(Deserialize)]
struct Doc {
    version: u8,
    vectors: Vec<Vector>,
    reject: Vec<Reject>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    inputs: Inputs,
    expected: Expected,
}

#[derive(Deserialize)]
struct Inputs {
    seed: String,
    burn_token: String,
    passphrase: Option<String>,
    argon2: Argon,
    text: Option<String>,
    files: Vec<FileIn>,
    ek: String,
    salt: String,
    wrap_iv: String,
    nonce_prefix: String,
    padding: Padding,
}

#[derive(Deserialize)]
struct Argon {
    m: u32,
    t: u32,
    p: u32,
}

#[derive(Deserialize)]
struct FileIn {
    name: String,
    #[serde(rename = "type")]
    mime: String,
    bytes_base64: String,
}

#[derive(Deserialize)]
struct Padding {
    mode: String,
    min: Option<u64>,
    ladder: Option<Vec<u64>>,
}

#[derive(Deserialize)]
struct Expected {
    fragment: String,
    burn_fragment: String,
    lookup: String,
    lookup_key: String,
    burn_key: String,
    pass_key: Option<String>,
    kek: String,
    wrapped_ek: String,
    manifest: String,
    payload_len: usize,
    payload_sha256: String,
    bucket: u64,
    chunk_count: u64,
    blob_len: usize,
    header: String,
    blob_base64: String,
}

#[derive(Deserialize)]
struct Reject {
    name: String,
    base: String,
    blob_base64: String,
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}

fn doc() -> Doc {
    serde_json::from_str(VECTORS).unwrap()
}

impl Inputs {
    fn randomness(&self) -> Randomness {
        Randomness {
            seed: Zeroizing::new(arr(&self.seed)),
            burn_token: Zeroizing::new(arr(&self.burn_token)),
            ek: Zeroizing::new(arr(&self.ek)),
            salt: arr(&self.salt),
            wrap_iv: arr(&self.wrap_iv),
            nonce_prefix: arr(&self.nonce_prefix),
        }
    }

    fn payload(&self) -> Payload {
        Payload {
            text: self.text.clone(),
            files: self
                .files
                .iter()
                .map(|f| File {
                    name: f.name.clone(),
                    mime: f.mime.clone(),
                    bytes: b64(&f.bytes_base64),
                })
                .collect(),
        }
    }

    fn argon(&self) -> Argon2Params {
        Argon2Params {
            m: self.argon2.m,
            t: self.argon2.t,
            p: self.argon2.p,
        }
    }

    fn policy(&self) -> PaddingPolicy {
        match self.padding.mode.as_str() {
            "padme" => PaddingPolicy::Padme {
                min: self.padding.min.unwrap(),
            },
            "buckets" => PaddingPolicy::Buckets {
                ladder: self.padding.ladder.clone().unwrap(),
            },
            other => panic!("unknown padding mode {other}"),
        }
    }
}

#[test]
fn file_is_for_this_protocol_version() {
    assert_eq!(doc().version, shhnote_core::fragment::VERSION);
}

#[test]
fn derivations_match() {
    for v in doc().vectors {
        let seed: [u8; 32] = arr(&v.inputs.seed);
        let name = &v.name;

        assert_eq!(Fragment::new(seed).encode(), v.expected.fragment, "{name}");
        assert_eq!(
            Fragment::new(arr(&v.inputs.burn_token)).encode(),
            v.expected.burn_fragment,
            "{name}"
        );
        assert_eq!(
            Fragment::decode(&v.expected.fragment).unwrap().bytes,
            seed,
            "{name}"
        );

        let lookup = secret::lookup(&seed);
        assert_eq!(lookup.to_vec(), hex(&v.expected.lookup), "{name}");
        assert_eq!(
            secret::credential_hash(&lookup).to_vec(),
            hex(&v.expected.lookup_key),
            "{name}"
        );
        assert_eq!(
            secret::credential_hash(&hex(&v.inputs.burn_token)).to_vec(),
            hex(&v.expected.burn_key),
            "{name}"
        );

        match &v.inputs.passphrase {
            None => assert_eq!(
                kdf::hkdf(&seed, kdf::INFO_KEK_DIRECT).to_vec(),
                hex(&v.expected.kek),
                "{name}"
            ),
            Some(passphrase) => {
                let pass_key =
                    kdf::argon2id(passphrase, &arr(&v.inputs.salt), v.inputs.argon()).unwrap();
                assert_eq!(
                    pass_key.to_vec(),
                    hex(v.expected.pass_key.as_ref().unwrap()),
                    "{name}"
                );
                let mut ikm = seed.to_vec();
                ikm.extend_from_slice(&pass_key);
                assert_eq!(
                    kdf::hkdf(&ikm, kdf::INFO_KEK_PASS).to_vec(),
                    hex(&v.expected.kek),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn payloads_match() {
    for v in doc().vectors {
        let payload = v.inputs.payload();
        assert_eq!(
            serde_json::to_string(&payload.manifest()).unwrap(),
            v.expected.manifest,
            "{}",
            v.name
        );
        let bytes = payload.encode().unwrap();
        assert_eq!(bytes.len(), v.expected.payload_len, "{}", v.name);
        assert_eq!(
            Sha256::digest(&bytes).to_vec(),
            hex(&v.expected.payload_sha256),
            "{}",
            v.name
        );
        assert_eq!(Payload::decode(&bytes).unwrap(), payload, "{}", v.name);
    }
}

#[test]
fn encryption_reproduces_every_blob_byte_for_byte() {
    for v in doc().vectors {
        let name = &v.name;
        let out = secret::encrypt(
            &v.inputs.randomness(),
            &v.inputs.payload(),
            v.inputs.passphrase.as_deref(),
            v.inputs.argon(),
            &v.inputs.policy(),
        )
        .unwrap();

        assert_eq!(out.bucket, v.expected.bucket, "{name}");
        assert_eq!(out.blob.len(), v.expected.blob_len, "{name}");
        assert_eq!(out.fragment, v.expected.fragment, "{name}");
        assert_eq!(out.burn_fragment, v.expected.burn_fragment, "{name}");
        assert_eq!(
            out.lookup_key.to_vec(),
            hex(&v.expected.lookup_key),
            "{name}"
        );
        assert_eq!(out.burn_key.to_vec(), hex(&v.expected.burn_key), "{name}");

        let header = Header::parse(&out.blob).unwrap();
        assert_eq!(
            header.to_bytes().to_vec(),
            hex(&v.expected.header),
            "{name}"
        );
        assert_eq!(
            header.wrapped_ek.to_vec(),
            hex(&v.expected.wrapped_ek),
            "{name}"
        );
        assert_eq!(
            shhnote_core::padding::chunk_count(out.bucket),
            v.expected.chunk_count,
            "{name}"
        );
        assert_eq!(out.blob, b64(&v.expected.blob_base64), "{name}");

        // The server accepts exactly this length under the instance policy.
        assert_eq!(
            v.inputs.policy().bucket_for_blob_len(out.blob.len() as u64),
            Ok(v.expected.bucket),
            "{name}"
        );
    }
}

#[test]
fn decryption_recovers_every_payload() {
    for v in doc().vectors {
        let blob = b64(&v.expected.blob_base64);
        let seed = arr(&v.inputs.seed);
        let payload = secret::decrypt(&blob, &seed, v.inputs.passphrase.as_deref()).unwrap();
        assert_eq!(payload, v.inputs.payload(), "{}", v.name);

        if v.inputs.passphrase.is_some() {
            assert_eq!(
                secret::decrypt(&blob, &seed, None),
                Err(Error::PassphraseRequired),
                "{}",
                v.name
            );
            assert_eq!(
                secret::decrypt(&blob, &seed, Some("wrong")),
                Err(Error::WrongPassphrase),
                "{}",
                v.name
            );
        }
    }
}

#[test]
fn direct_and_passphrase_blobs_are_indistinguishable_in_shape() {
    let doc = doc();
    let find = |name: &str| doc.vectors.iter().find(|v| v.name == name).unwrap();
    let direct = find("text-direct");
    let pass = find("text-passphrase");
    assert_eq!(direct.expected.blob_len, pass.expected.blob_len);
    assert_eq!(direct.expected.bucket, pass.expected.bucket);
    // Same field widths, same Argon2 parameter slots present, only the values differ.
    let a = Header::parse(&b64(&direct.expected.blob_base64)).unwrap();
    let b = Header::parse(&b64(&pass.expected.blob_base64)).unwrap();
    assert_ne!(a, b);
}

#[test]
fn reject_cases_are_rejected() {
    let doc = doc();
    for r in doc.reject {
        let base = doc.vectors.iter().find(|v| v.name == r.base).unwrap();
        let blob = b64(&r.blob_base64);
        let seed = arr(&base.inputs.seed);
        let policy = base.inputs.policy();

        let server_check = policy.bucket_for_blob_len(blob.len() as u64);
        let client_result = secret::decrypt(&blob, &seed, base.inputs.passphrase.as_deref());
        assert!(
            server_check.is_err() || client_result.is_err(),
            "{} was accepted by both the server length check and the client",
            r.name
        );

        let expected_client = match r.name.as_str() {
            "argon-m-below-bounds" | "argon-m-above-bounds" | "argon-t-above-bounds" => {
                Some(Error::Argon2OutOfBounds)
            }
            "wrapped-ek-tampered" => Some(Error::PassphraseRequired),
            "truncated" => None,
            _ => Some(Error::Corrupt("")),
        };
        match (expected_client, client_result) {
            (None, _) => assert_eq!(server_check, Err(Error::InvalidBlobLength), "{}", r.name),
            (Some(Error::Corrupt(_)), Err(Error::Corrupt(_))) => {}
            (Some(expected), actual) => assert_eq!(actual, Err(expected), "{}", r.name),
        }
    }
}
