use serde::{Deserialize, Serialize};

use crate::Error;

pub const MANIFEST_VERSION: u32 = 1;
pub const MAX_MANIFEST_LEN: usize = 1024 * 1024;

// The JSON at the front of every payload (SPEC §2.5). Field order matters: it is what the vectors pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub v: u32,
    pub text: Option<String>,
    pub files: Vec<FileMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub name: String,
    #[serde(rename = "type")]
    pub mime: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    // Untrusted display data on the receiving side; never use it as a path.
    pub name: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Payload {
    pub text: Option<String>,
    pub files: Vec<File>,
}

impl Payload {
    pub fn manifest(&self) -> Manifest {
        Manifest {
            v: MANIFEST_VERSION,
            text: self.text.clone(),
            files: self
                .files
                .iter()
                .map(|f| FileMeta {
                    name: f.name.clone(),
                    mime: f.mime.clone(),
                    size: f.bytes.len() as u64,
                })
                .collect(),
        }
    }

    // `[manifest_len: u32 BE][manifest JSON][file bytes in manifest order]`
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.text.is_none() && self.files.is_empty() {
            return Err(Error::EmptyPayload);
        }
        let manifest =
            serde_json::to_vec(&self.manifest()).map_err(|e| Error::Manifest(e.to_string()))?;
        if manifest.len() > MAX_MANIFEST_LEN {
            return Err(Error::PayloadTooLarge);
        }
        let total = 4 + manifest.len() + self.files.iter().map(|f| f.bytes.len()).sum::<usize>();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
        out.extend_from_slice(&manifest);
        for file in &self.files {
            out.extend_from_slice(&file.bytes);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let prefix: [u8; 4] = bytes
            .get(..4)
            .and_then(|p| p.try_into().ok())
            .ok_or(Error::Corrupt("payload too short"))?;
        let manifest_len = u32::from_be_bytes(prefix) as usize;
        if manifest_len > MAX_MANIFEST_LEN {
            return Err(Error::Corrupt("manifest too large"));
        }
        let manifest_bytes = bytes
            .get(4..4 + manifest_len)
            .ok_or(Error::Corrupt("manifest length exceeds payload"))?;
        let manifest: Manifest =
            serde_json::from_slice(manifest_bytes).map_err(|e| Error::Manifest(e.to_string()))?;
        if manifest.v != MANIFEST_VERSION {
            return Err(Error::Manifest(format!(
                "unsupported manifest version {}",
                manifest.v
            )));
        }
        if manifest.text.is_none() && manifest.files.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let mut rest = &bytes[4 + manifest_len..];
        let mut files = Vec::with_capacity(manifest.files.len());
        for meta in manifest.files {
            let size =
                usize::try_from(meta.size).map_err(|_| Error::Corrupt("file size overflow"))?;
            let (content, tail) = rest
                .split_at_checked(size)
                .ok_or(Error::Corrupt("file sizes exceed payload"))?;
            files.push(File {
                name: meta.name,
                mime: meta.mime,
                bytes: content.to_vec(),
            });
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(Error::Corrupt("trailing bytes after the last file"));
        }
        Ok(Self {
            text: manifest.text,
            files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Payload {
        Payload {
            text: Some("hi".into()),
            files: vec![
                File {
                    name: "a.txt".into(),
                    mime: "text/plain".into(),
                    bytes: b"one".to_vec(),
                },
                File {
                    name: "b.bin".into(),
                    mime: "application/octet-stream".into(),
                    bytes: vec![0, 1, 2, 3],
                },
            ],
        }
    }

    #[test]
    fn round_trips() {
        let payload = sample();
        let bytes = payload.encode().unwrap();
        assert_eq!(Payload::decode(&bytes).unwrap(), payload);

        let files_only = Payload {
            text: None,
            ..sample()
        };
        assert_eq!(
            Payload::decode(&files_only.encode().unwrap()).unwrap(),
            files_only
        );
    }

    #[test]
    fn manifest_is_compact_json_in_spec_order() {
        let json = serde_json::to_string(&sample().manifest()).unwrap();
        assert_eq!(
            json,
            r#"{"v":1,"text":"hi","files":[{"name":"a.txt","type":"text/plain","size":3},{"name":"b.bin","type":"application/octet-stream","size":4}]}"#
        );
    }

    #[test]
    fn rejects_bad_structure() {
        assert_eq!(Payload::default().encode(), Err(Error::EmptyPayload));

        let mut bytes = sample().encode().unwrap();
        bytes.push(0);
        assert_eq!(
            Payload::decode(&bytes),
            Err(Error::Corrupt("trailing bytes after the last file"))
        );

        let bytes = sample().encode().unwrap();
        assert!(matches!(
            Payload::decode(&bytes[..bytes.len() - 1]),
            Err(Error::Corrupt(_))
        ));
        assert!(matches!(
            Payload::decode(&[0, 0, 0, 2, b'{', b'}']),
            Err(Error::Manifest(_))
        ));
    }
}
