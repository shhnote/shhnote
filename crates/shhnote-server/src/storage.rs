use std::{
    collections::HashSet,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::body::{Body, Bytes};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{Stream, TryStreamExt, stream};
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::{BodyDataStream, BodyExt, Empty, StreamBody, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    client::conn::http1,
    header,
};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use shhnote_core::{config::ExternalStorage, padding::blob_len};
use shhnote_store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::clock::{amz_date, now};

// The external tier: where padded blobs above `SHH_INLINE_MAX` live. Handlers only see
// spool / put / get / delete; they never touch the filesystem or S3 themselves.
pub struct Blobs {
    tier: Tier,
    ledger: Mutex<Ledger>,
}

enum Tier {
    Local(Local),
    S3(S3),
}

// What the ceiling counts (SPEC §6.1, D-20): bytes the rows account for, plus bytes uploads
// in flight have reserved. One process owns the tier, so this needs no database round trip.
#[derive(Default)]
struct Ledger {
    // Loaded from the rows on first use; `None` again after anything changes the tier
    // behind the ledger's back (orphan collection).
    stored: Option<u64>,
    reserved: u64,
}

const KEY_PREFIX: &str = "blobs/";
const CHUNK: usize = 64 * 1024;

impl Blobs {
    // Opens the tier and runs the startup checks: the local root must be writable, the S3
    // bucket reachable with the given credentials and not versioned (SPEC §6).
    pub async fn open(config: &ExternalStorage) -> Result<Self, String> {
        let tier = match config {
            ExternalStorage::Local {
                path,
                max_total_bytes,
            } => Local::open(path, *max_total_bytes).await.map(Tier::Local)?,
            ExternalStorage::S3 {
                bucket,
                region,
                endpoint,
                access_key_id,
                secret_access_key,
                max_total_bytes,
                spool_path,
            } => S3::open(
                bucket,
                region,
                endpoint.as_deref(),
                access_key_id,
                secret_access_key.expose(),
                *max_total_bytes,
                spool_path,
            )
            .await
            .map(Tier::S3)?,
        };
        Ok(Self {
            tier,
            ledger: Mutex::new(Ledger::default()),
        })
    }

    // The hard ceiling for everything stored in this tier, pending deletes included.
    pub fn max_total_bytes(&self) -> u64 {
        match &self.tier {
            Tier::Local(local) => local.max_total_bytes,
            Tier::S3(s3) => s3.max_total_bytes,
        }
    }

    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.ledger.lock().unwrap_or_else(|e| e.into_inner())
    }

    // Reserves `bytes` against the ceiling for an upload in flight, or returns `None` when
    // they would cross it. The check and the bookkeeping happen under one lock, so concurrent
    // creates cannot jointly exceed the ceiling (SPEC §6.1).
    pub async fn reserve(
        self: &Arc<Self>,
        store: &Store,
        bytes: u64,
    ) -> io::Result<Option<Reservation>> {
        if self.ledger().stored.is_none() {
            let stored = store.external_bytes().await.map_err(io::Error::other)?;
            self.ledger().stored.get_or_insert(stored);
        }
        let mut ledger = self.ledger();
        let stored = ledger.stored.unwrap_or(0);
        if stored + ledger.reserved + bytes > self.max_total_bytes() {
            return Ok(None);
        }
        ledger.reserved += bytes;
        Ok(Some(Reservation {
            blobs: self.clone(),
            bytes,
            committed: false,
        }))
    }

    // The scrubber confirmed an object is gone: it no longer counts.
    pub fn release_stored(&self, bytes: u64) {
        let mut ledger = self.ledger();
        if let Some(stored) = &mut ledger.stored {
            *stored = stored.saturating_sub(bytes);
        }
    }

    // Deletes every object no row references (SPEC §6.1): what a crash between the object
    // write and the row write, or a failed cleanup, leaves behind. Returns how many went.
    pub async fn collect_orphans(&self, store: &Store) -> io::Result<usize> {
        let referenced: HashSet<String> = store
            .external_refs()
            .await
            .map_err(io::Error::other)?
            .into_iter()
            .collect();
        let mut removed = 0;
        for key in self.list().await? {
            if !referenced.contains(&key) {
                self.delete(&key).await?;
                removed += 1;
            }
        }
        // Whatever the ledger believed, the tier has just been reconciled with the rows.
        self.ledger().stored = None;
        Ok(removed)
    }

    async fn list(&self) -> io::Result<Vec<String>> {
        match &self.tier {
            Tier::Local(local) => local.list().await,
            Tier::S3(s3) => s3.list().await,
        }
    }

    // A fresh object key. Server-generated, never derived from anything the client sent.
    pub fn new_key() -> io::Result<String> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(format!("{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(random)))
    }

    // Incoming blobs are written here first, so a request never holds a large blob in memory.
    pub async fn spool(&self) -> io::Result<Spool> {
        let dir = match &self.tier {
            Tier::Local(local) => local.root.join("tmp"),
            Tier::S3(s3) => s3.spool_dir.clone(),
        };
        Spool::create(&dir).await
    }

    // Stores a finished spool under `key`. The spool file is gone afterwards either way.
    pub async fn put(&self, key: &str, spooled: Spooled) -> io::Result<()> {
        match &self.tier {
            Tier::Local(local) => local.put(key, spooled).await,
            Tier::S3(s3) => s3.put(key, spooled).await,
        }
    }

    pub async fn get(&self, key: &str) -> io::Result<Body> {
        match &self.tier {
            Tier::Local(local) => local.get(key).await,
            Tier::S3(s3) => s3.get(key).await,
        }
    }

    // Idempotent: an object that is already gone counts as deleted.
    pub async fn delete(&self, key: &str) -> io::Result<()> {
        match &self.tier {
            Tier::Local(local) => local.delete(key).await,
            Tier::S3(s3) => s3.delete(key).await,
        }
    }
}

// Bytes an upload holds against the ceiling. Dropped unconfirmed, they are given back; once
// the row is written, `commit` moves them into the stored total.
pub struct Reservation {
    blobs: Arc<Blobs>,
    bytes: u64,
    committed: bool,
}

impl Reservation {
    // The exact object size is only known once the blob has arrived; it never grows.
    pub fn shrink_to(&mut self, bytes: u64) {
        if bytes < self.bytes {
            self.blobs.ledger().reserved -= self.bytes - bytes;
            self.bytes = bytes;
        }
    }

    pub fn commit(mut self) {
        let mut ledger = self.blobs.ledger();
        ledger.reserved -= self.bytes;
        if let Some(stored) = &mut ledger.stored {
            *stored += self.bytes;
        }
        self.committed = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            self.blobs.ledger().reserved -= self.bytes;
        }
    }
}

// Keeps the number of bytes an object takes in the tier (SPEC §6.1).
pub fn object_bytes(bucket: u64) -> u64 {
    blob_len(bucket)
}

// The part of a key after `blobs/`, only if it is one of ours: rejects anything that could
// escape the directory, since keys come back from the database.
fn object_name(key: &str) -> io::Result<&str> {
    let name = key.strip_prefix(KEY_PREFIX).unwrap_or("");
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if valid {
        Ok(name)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad object key",
        ))
    }
}

// A blob being received: bytes go straight to a temp file.
pub struct Spool {
    path: PathBuf,
    file: Option<tokio::fs::File>,
    len: u64,
}

// A fully received blob waiting to be stored or discarded. Removes its file when dropped,
// so a failed request never leaves anything behind.
pub struct Spooled {
    path: PathBuf,
    pub len: u64,
}

impl Spool {
    async fn create(dir: &Path) -> io::Result<Self> {
        tokio::fs::create_dir_all(dir).await?;
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
        let path = dir.join(format!("{}.part", URL_SAFE_NO_PAD.encode(random)));
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await?;
        Ok(Self {
            path,
            file: Some(file),
            len: 0,
        })
    }

    pub async fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        if let Some(file) = &mut self.file {
            file.write_all(chunk).await?;
            self.len += chunk.len() as u64;
        }
        Ok(())
    }

    pub fn bytes_written(&self) -> u64 {
        self.len
    }

    pub async fn finish(mut self) -> io::Result<Spooled> {
        if let Some(mut file) = self.file.take() {
            file.flush().await?;
            file.sync_all().await?;
        }
        Ok(Spooled {
            path: std::mem::take(&mut self.path),
            len: self.len,
        })
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for Spooled {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn file_stream(file: tokio::fs::File) -> impl Stream<Item = io::Result<Bytes>> {
    stream::try_unfold(file, |mut file| async move {
        let mut buf = vec![0u8; CHUNK];
        let n = file.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok(Some((Bytes::from(buf), file)))
    })
}

// --- local disk

pub struct Local {
    root: PathBuf,
    max_total_bytes: u64,
}

impl Local {
    async fn open(root: &Path, max_total_bytes: u64) -> Result<Self, String> {
        let describe = |e: io::Error| format!("SHH_LOCAL_PATH {}: {e}", root.display());
        tokio::fs::create_dir_all(root.join("blobs"))
            .await
            .map_err(describe)?;
        // Spool files from an earlier run are partial uploads nobody will finish.
        let tmp = root.join("tmp");
        let _ = tokio::fs::remove_dir_all(&tmp).await;
        tokio::fs::create_dir_all(&tmp).await.map_err(describe)?;
        let probe = tmp.join(".write-check");
        tokio::fs::write(&probe, b"").await.map_err(describe)?;
        tokio::fs::remove_file(&probe).await.map_err(describe)?;
        Ok(Self {
            root: root.to_path_buf(),
            max_total_bytes,
        })
    }

    fn path_of(&self, key: &str) -> io::Result<PathBuf> {
        Ok(self.root.join("blobs").join(object_name(key)?))
    }

    async fn put(&self, key: &str, spooled: Spooled) -> io::Result<()> {
        // Same filesystem as the spool, so this is an atomic move, never a copy.
        tokio::fs::rename(&spooled.path, self.path_of(key)?).await
    }

    async fn get(&self, key: &str) -> io::Result<Body> {
        let file = tokio::fs::File::open(self.path_of(key)?).await?;
        Ok(Body::from_stream(file_stream(file)))
    }

    async fn delete(&self, key: &str) -> io::Result<()> {
        match tokio::fs::remove_file(self.path_of(key)?).await {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    async fn list(&self) -> io::Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut entries = tokio::fs::read_dir(self.root.join("blobs")).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                keys.push(format!("{KEY_PREFIX}{name}"));
            }
        }
        Ok(keys)
    }
}

// --- S3

// Hand-written SigV4 over hyper: a few hundred lines instead of the AWS SDK's dependency tree.
pub struct S3 {
    region: String,
    host: String,
    port: u16,
    tls: Option<Arc<rustls::ClientConfig>>,
    // Path before the object key: "" for virtual-hosted AWS buckets, "/<bucket>" for custom endpoints.
    prefix: String,
    access_key_id: String,
    secret_access_key: String,
    max_total_bytes: u64,
    spool_dir: PathBuf,
}

type RequestBody = BoxBody<Bytes, io::Error>;

const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const UNSIGNED: &str = "UNSIGNED-PAYLOAD";

// A hung object store must not hang the server (SPEC §6.1): bounds on reaching the endpoint,
// on getting a response, and on each piece of a streamed body.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// Uploads get longer, since the response only comes once the whole object has been sent.
const UPLOAD_MIN_BYTES_PER_SEC: u64 = 128 * 1024;

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("S3 {what} timed out"))
}

impl S3 {
    async fn open(
        bucket: &str,
        region: &str,
        endpoint: Option<&str>,
        access_key_id: &str,
        secret_access_key: &str,
        max_total_bytes: u64,
        spool_dir: &Path,
    ) -> Result<Self, String> {
        let (tls, host, port, prefix) = match endpoint {
            None => (
                true,
                format!("{bucket}.s3.{region}.amazonaws.com"),
                443,
                String::new(),
            ),
            Some(endpoint) => {
                let (tls, host, port) = parse_endpoint(endpoint)?;
                (tls, host, port, format!("/{bucket}"))
            }
        };
        let tls = tls.then(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring supports the default TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        });
        let s3 = Self {
            region: region.to_string(),
            host,
            port,
            tls,
            prefix,
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_access_key.to_string(),
            max_total_bytes,
            spool_dir: spool_dir.to_path_buf(),
        };
        // Spool files from an earlier run are partial uploads nobody will finish.
        let _ = tokio::fs::remove_dir_all(&s3.spool_dir).await;
        tokio::fs::create_dir_all(&s3.spool_dir)
            .await
            .map_err(|e| format!("SHH_SPOOL_PATH {}: {e}", s3.spool_dir.display()))?;
        s3.check_versioning().await?;
        Ok(s3)
    }

    // Versioned buckets keep "deleted" objects around, which breaks the destruction promise.
    async fn check_versioning(&self) -> Result<(), String> {
        let path = format!("{}/", self.prefix);
        let response = self
            .send(Method::GET, &path, "versioning", &[], None)
            .await
            .map_err(|e| format!("S3 bucket check failed: {e}"))?;
        let status = response.status();
        let body = read_small(response).await.unwrap_or_default();
        if status == StatusCode::OK {
            if body.contains("<Status>Enabled</Status>") {
                return Err("S3 bucket versioning is enabled; turn it off (SPEC §6)".into());
            }
            if body.contains("<Status>Suspended</Status>") {
                crate::log_error!(
                    "warning: S3 bucket versioning is suspended; versions created earlier still exist"
                );
            }
            Ok(())
        } else if status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND {
            Err(format!("S3 bucket check failed: {status}"))
        } else {
            // Some S3-compatible services don't implement the versioning API at all.
            crate::log_error!(
                "warning: could not check S3 bucket versioning ({status}); make sure it is off"
            );
            Ok(())
        }
    }

    fn object_path(&self, key: &str) -> io::Result<String> {
        Ok(format!("{}/{KEY_PREFIX}{}", self.prefix, object_name(key)?))
    }

    async fn put(&self, key: &str, spooled: Spooled) -> io::Result<()> {
        let path = self.object_path(key)?;
        let file = tokio::fs::File::open(&spooled.path).await?;
        let body = StreamBody::new(file_stream(file).map_ok(Frame::data)).boxed();
        let allowance =
            RESPONSE_TIMEOUT + Duration::from_secs(spooled.len / UPLOAD_MIN_BYTES_PER_SEC);
        let response = self
            .send_within(
                allowance,
                Method::PUT,
                &path,
                "",
                &[],
                Some((body, spooled.len)),
            )
            .await?;
        expect_success(response).await
    }

    async fn get(&self, key: &str) -> io::Result<Body> {
        let path = self.object_path(key)?;
        let response = self.send(Method::GET, &path, "", &[], None).await?;
        if !response.status().is_success() {
            return Err(status_error(response).await);
        }
        // Each piece of the object must keep arriving, or the download is cut.
        let frames = BodyDataStream::new(response.into_body());
        let timed = stream::unfold(Some(frames), |frames| async move {
            let mut frames = frames?;
            match tokio::time::timeout(
                BODY_IDLE_TIMEOUT,
                futures_util::StreamExt::next(&mut frames),
            )
            .await
            {
                Ok(Some(Ok(bytes))) => Some((Ok(bytes), Some(frames))),
                Ok(Some(Err(e))) => Some((Err(io::Error::other(e)), None)),
                Ok(None) => None,
                Err(_) => Some((Err(timed_out("download")), None)),
            }
        });
        Ok(Body::from_stream(timed))
    }

    async fn delete(&self, key: &str) -> io::Result<()> {
        let path = self.object_path(key)?;
        let response = self.send(Method::DELETE, &path, "", &[], None).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        expect_success(response).await
    }

    // ListObjectsV2 under `blobs/`, page by page. Keys are base64url, so no XML unescaping.
    async fn list(&self) -> io::Result<Vec<String>> {
        let path = format!("{}/", self.prefix);
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        loop {
            // Already in canonical (sorted, encoded) form, as the signature needs it.
            let query = match &token {
                Some(token) => format!(
                    "continuation-token={}&list-type=2&prefix=blobs%2F",
                    uri_encode(token)
                ),
                None => "list-type=2&prefix=blobs%2F".to_string(),
            };
            let response = self.send(Method::GET, &path, &query, &[], None).await?;
            if !response.status().is_success() {
                return Err(status_error(response).await);
            }
            let body = read_page(response).await?;
            keys.extend(between_all(&body, "<Key>", "</Key>").map(str::to_string));
            if !body.contains("<IsTruncated>true</IsTruncated>") {
                return Ok(keys);
            }
            match between_all(&body, "<NextContinuationToken>", "</NextContinuationToken>").next() {
                Some(next) => token = Some(next.to_string()),
                None => return Ok(keys),
            }
        }
    }

    // One signed request on its own connection; S3 traffic here is a few calls per secret.
    async fn send(
        &self,
        method: Method,
        path: &str,
        query: &str,
        extra_headers: &[(&str, &str)],
        body: Option<(RequestBody, u64)>,
    ) -> io::Result<Response<Incoming>> {
        self.send_within(RESPONSE_TIMEOUT, method, path, query, extra_headers, body)
            .await
    }

    // `allowance` bounds the wait for the response headers once the connection is up.
    async fn send_within(
        &self,
        allowance: Duration,
        method: Method,
        path: &str,
        query: &str,
        extra_headers: &[(&str, &str)],
        body: Option<(RequestBody, u64)>,
    ) -> io::Result<Response<Incoming>> {
        let default_port = if self.tls.is_some() { 443 } else { 80 };
        let host_header = if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let payload_hash = if body.is_some() { UNSIGNED } else { EMPTY_HASH };
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host_header),
            ("x-amz-content-sha256".into(), payload_hash.into()),
            ("x-amz-date".into(), amz_date(now())),
        ];
        headers.extend(
            extra_headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string())),
        );
        let authorization = authorization(
            &self.access_key_id,
            &self.secret_access_key,
            &self.region,
            method.as_str(),
            path,
            query,
            &headers,
            payload_hash,
        );

        let uri = if query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{query}")
        };
        let mut request = Request::builder().method(method).uri(uri);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request = request.header(header::AUTHORIZATION, authorization);
        let (body, len) = match body {
            Some((body, len)) => (body, Some(len)),
            None => (Empty::<Bytes>::new().map_err(|e| match e {}).boxed(), None),
        };
        if let Some(len) = len {
            request = request.header(header::CONTENT_LENGTH, len);
        }
        let request = request.body(body).map_err(io::Error::other)?;

        let connect = async {
            let stream = tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await?;
            let sender = match &self.tls {
                Some(config) => {
                    let name = rustls::pki_types::ServerName::try_from(self.host.clone())
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    let tls = tokio_rustls::TlsConnector::from(config.clone())
                        .connect(name, stream)
                        .await?;
                    let (sender, conn) = http1::handshake(TokioIo::new(tls))
                        .await
                        .map_err(io::Error::other)?;
                    tokio::spawn(conn);
                    sender
                }
                None => {
                    let (sender, conn) = http1::handshake(TokioIo::new(stream))
                        .await
                        .map_err(io::Error::other)?;
                    tokio::spawn(conn);
                    sender
                }
            };
            Ok::<_, io::Error>(sender)
        };
        let mut sender = tokio::time::timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| timed_out("connect"))??;
        tokio::time::timeout(allowance, sender.send_request(request))
            .await
            .map_err(|_| timed_out("request"))?
            .map_err(io::Error::other)
    }
}

fn parse_endpoint(endpoint: &str) -> Result<(bool, String, u16), String> {
    let (tls, rest) = if let Some(rest) = endpoint.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("SHH_S3_ENDPOINT must start with http:// or https://".into());
    };
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() || rest.contains('/') {
        return Err("SHH_S3_ENDPOINT must be a scheme and host only, no path".into());
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse()
                .map_err(|_| "SHH_S3_ENDPOINT has an invalid port".to_string())?,
        ),
        None => (rest.to_string(), if tls { 443 } else { 80 }),
    };
    Ok((tls, host, port))
}

async fn read_small(response: Response<Incoming>) -> io::Result<String> {
    read_up_to(response, 64 * 1024).await
}

// A listing page: up to 1000 keys of XML.
async fn read_page(response: Response<Incoming>) -> io::Result<String> {
    read_up_to(response, 1024 * 1024).await
}

async fn read_up_to(response: Response<Incoming>, limit: usize) -> io::Result<String> {
    let body = http_body_util::Limited::new(response.into_body(), limit)
        .collect()
        .await
        .map_err(io::Error::other)?
        .to_bytes();
    Ok(String::from_utf8_lossy(&body).into_owned())
}

// Every stretch of `text` between `open` and `close`, in order.
fn between_all<'a>(text: &'a str, open: &'a str, close: &'a str) -> impl Iterator<Item = &'a str> {
    text.split(open)
        .skip(1)
        .filter_map(move |rest| rest.split(close).next())
}

async fn expect_success(response: Response<Incoming>) -> io::Result<()> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(status_error(response).await)
    }
}

// Only the status and S3's error code make it into the error, which ends up in a log line.
// The body names the object key, and the key maps to a secret's row (CLAUDE.md: nothing
// request-specific is ever logged).
async fn status_error(response: Response<Incoming>) -> io::Error {
    let status = response.status();
    let body = read_small(response).await.unwrap_or_default();
    let code = between_all(&body, "<Code>", "</Code>")
        .next()
        .filter(|c| c.len() <= 64 && c.chars().all(|ch| ch.is_ascii_alphanumeric()))
        .unwrap_or("no code");
    io::Error::other(format!("S3 answered {status} ({code})"))
}

// AWS Signature Version 4 for S3 (the "Authorization" header value). `headers` must
// contain host, x-amz-date and x-amz-content-sha256; all of them are signed.
#[allow(clippy::too_many_arguments)]
fn authorization(
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
) -> String {
    let mut sorted: Vec<(String, &str)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim()))
        .collect();
    sorted.sort();
    let canonical_headers: String = sorted.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = sorted
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_query = if query.is_empty() {
        String::new()
    } else if query.contains('=') {
        query.to_string()
    } else {
        format!("{query}=")
    };
    let canonical_request = format!(
        "{method}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        uri_encode_path(path)
    );

    let amz_date = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-date"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let date = &amz_date[..amz_date.len().min(8)];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );

    let mut key = hmac(
        format!("AWS4{secret_access_key}").as_bytes(),
        date.as_bytes(),
    );
    for part in [region, "s3", "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    let signature = hex(&hmac(&key, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

// Each path segment percent-encoded as SigV4 wants it; `/` stays.
fn uri_encode_path(path: &str) -> String {
    encode(path, true)
}

// A query value percent-encoded as SigV4 wants it; `/` is encoded too.
fn uri_encode(value: &str) -> String {
    encode(value, false)
}

fn encode(text: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The worked example from the S3 SigV4 documentation ("GET object", example bucket).
    #[test]
    fn signs_like_the_aws_example() {
        let headers = vec![
            (
                "Host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("Range".to_string(), "bytes=0-9".to_string()),
            ("x-amz-content-sha256".to_string(), EMPTY_HASH.to_string()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
        ];
        let auth = authorization(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "GET",
            "/test.txt",
            "",
            &headers,
            EMPTY_HASH,
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn rejects_keys_that_are_not_ours() {
        assert!(object_name("blobs/abc-DEF_123").is_ok());
        for bad in [
            "",
            "blobs/",
            "blobs/../x",
            "other/abc",
            "blobs/a/b",
            "blobs/a.b",
        ] {
            assert!(object_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn extracts_keys_and_tokens_from_a_listing() {
        let page = "<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>blobs/a</Key></Contents>\
                    <Contents><Key>blobs/b-c_D</Key></Contents><NextContinuationToken>t/k+1=</NextContinuationToken></ListBucketResult>";
        assert_eq!(
            between_all(page, "<Key>", "</Key>").collect::<Vec<_>>(),
            ["blobs/a", "blobs/b-c_D"]
        );
        assert_eq!(
            between_all(page, "<NextContinuationToken>", "</NextContinuationToken>").next(),
            Some("t/k+1=")
        );
        assert_eq!(uri_encode("t/k+1="), "t%2Fk%2B1%3D");
    }

    #[test]
    fn parses_endpoints() {
        assert_eq!(
            parse_endpoint("http://127.0.0.1:9000/").unwrap(),
            (false, "127.0.0.1".to_string(), 9000)
        );
        assert_eq!(
            parse_endpoint("https://s3.example.com").unwrap(),
            (true, "s3.example.com".to_string(), 443)
        );
        assert!(parse_endpoint("s3.example.com").is_err());
        assert!(parse_endpoint("https://s3.example.com/bucket").is_err());
    }

    #[tokio::test]
    async fn local_tier_stores_streams_and_deletes() {
        let root =
            std::env::temp_dir().join(format!("shhnote-storage-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&root).await;
        let blobs = Blobs::open(&ExternalStorage::Local {
            path: root.clone(),
            max_total_bytes: 1_000_000,
        })
        .await
        .unwrap();

        let mut spool = blobs.spool().await.unwrap();
        spool.write(&[1u8; 70_000]).await.unwrap();
        spool.write(&[2u8; 30_000]).await.unwrap();
        let spooled = spool.finish().await.unwrap();
        assert_eq!(spooled.len, 100_000);
        let key = Blobs::new_key().unwrap();
        blobs.put(&key, spooled).await.unwrap();
        assert!(
            tokio::fs::read_dir(root.join("tmp"))
                .await
                .unwrap()
                .next_entry()
                .await
                .unwrap()
                .is_none()
        );

        let body = blobs.get(&key).await.unwrap();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        assert_eq!(bytes.len(), 100_000);
        assert_eq!((bytes[0], bytes[99_999]), (1, 2));

        blobs.delete(&key).await.unwrap();
        blobs.delete(&key).await.unwrap();
        assert!(blobs.get(&key).await.is_err());

        // A spool that is dropped unfinished leaves nothing behind.
        let mut spool = blobs.spool().await.unwrap();
        spool.write(b"partial").await.unwrap();
        drop(spool);
        assert!(
            tokio::fs::read_dir(root.join("tmp"))
                .await
                .unwrap()
                .next_entry()
                .await
                .unwrap()
                .is_none()
        );
        let _ = tokio::fs::remove_dir_all(&root).await;
    }
}
