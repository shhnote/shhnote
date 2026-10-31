// Regression tests from the security review (docs/security-review/findings/SUMMARY.md) for
// resource bounds, the storage ceiling, spooling and the single-view race at the API level.
// Ignored tests are waiting for the step that fixes their finding; un-ignore them with the fix.
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::stream;
use serde_json::{Value, json};
use shhnote_core::{config::Config, padding::blob_len, secret, settings::Settings};
use shhnote_server::{api::ApiState, app, scheduler, storage::Blobs};
use shhnote_store::{Store, sqlite_path_for_tests};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tower::ServiceExt;

const BOUNDARY: &str = "----spec-resources";
const LARGE: u64 = 131_072;

fn base_vars() -> HashMap<String, String> {
    [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
        ("SHH_INLINE_MAX", "65536"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

// Generous rate limits so the tests measure resources, not the limiter.
const LOOSE: &[(&str, &str)] = &[
    ("rate_create_per_hour", "100000"),
    ("rate_reveal_per_hour", "100000"),
    ("rate_confirm_per_hour", "100000"),
    ("rate_burn_per_hour", "100000"),
];

async fn build(name: &str, tier: &[(&str, &str)]) -> (Router, Store, Option<Arc<Blobs>>) {
    let mut vars = base_vars();
    vars.extend(tier.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let config = Config::from_vars(&vars).unwrap();
    let blobs = match &config.storage.external {
        Some(external) => Some(Arc::new(Blobs::open(external).await.unwrap())),
        None => None,
    };
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let overrides: HashMap<String, String> = LOOSE
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (settings, warnings) = Settings::with_overrides(&overrides);
    assert!(warnings.is_empty(), "{warnings:?}");
    let app = app::router(
        &config,
        ApiState::new(store.clone(), settings, &config, blobs.clone()),
    );
    (app, store, blobs)
}

async fn local(name: &str, ceiling: &str) -> (Router, Store, Arc<Blobs>, PathBuf) {
    let root = std::env::temp_dir().join(format!("shhnote-spec-resources-{name}"));
    let _ = tokio::fs::remove_dir_all(&root).await;
    let (app, store, blobs) = build(
        name,
        &[
            ("SHH_STORAGE", "local"),
            ("SHH_LOCAL_PATH", root.to_str().unwrap()),
            ("SHH_LOCAL_MAX_TOTAL_BYTES", ceiling),
        ],
    )
    .await;
    (app, store, blobs.unwrap(), root)
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

struct Keys {
    lookup: [u8; 32],
    burn_token: [u8; 32],
}

fn keys() -> Keys {
    Keys {
        lookup: random32(),
        burn_token: random32(),
    }
}

fn meta(keys: &Keys, lifetime: &str) -> Value {
    json!({
        "lookup_key": b64(&secret::credential_hash(&keys.lookup)),
        "burn_key": b64(&secret::credential_hash(&keys.burn_token)),
        "lifetime": lifetime,
        "ttl_seconds": 86400,
    })
}

fn raw_blob(bucket: u64) -> Vec<u8> {
    let mut blob = vec![0u8; blob_len(bucket) as usize];
    getrandom::fill(&mut blob).unwrap();
    blob
}

fn meta_part(meta: &str) -> String {
    format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{meta}\r\n"
    )
}

fn blob_head() -> String {
    format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"blob\"; filename=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
}

fn closing() -> String {
    format!("\r\n--{BOUNDARY}--\r\n")
}

fn multipart(body: Body) -> Request<Body> {
    Request::post("/api/v1/secrets")
        .header(header::HOST, "localhost")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(body)
        .unwrap()
}

fn create_body(meta: &Value, blob: &[u8]) -> Vec<u8> {
    let mut body = meta_part(&meta.to_string()).into_bytes();
    body.extend_from_slice(blob_head().as_bytes());
    body.extend_from_slice(blob);
    body.extend_from_slice(closing().as_bytes());
    body
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn code(&self) -> String {
        serde_json::from_slice::<Value>(&self.body)
            .ok()
            .and_then(|v| v["error"]["code"].as_str().map(str::to_string))
            .unwrap_or_default()
    }
}

async fn send(app: &Router, req: Request<Body>) -> Reply {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_else(|e| format!("<body error: {e}>").into_bytes());
    Reply {
        status,
        headers,
        body,
    }
}

async fn create(app: &Router, keys: &Keys, lifetime: &str, blob: &[u8]) -> Reply {
    let body = create_body(&meta(keys, lifetime), blob);
    let mut req = multipart(Body::from(body.clone()));
    req.headers_mut()
        .insert(header::CONTENT_LENGTH, body.len().into());
    send(app, req).await
}

async fn reveal(app: &Router, keys: &Keys) -> Reply {
    let req = Request::post("/api/v1/secrets/reveal")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({"lookup": b64(&keys.lookup)}).to_string()))
        .unwrap();
    send(app, req).await
}

// A request body fed by the test through a channel; dropping the sender ends it early,
// which is what a client disconnect looks like to the handler.
fn channel_body() -> (mpsc::Sender<Bytes>, Body) {
    let (tx, rx) = mpsc::channel::<Bytes>(4);
    let stream = stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|c| (Ok::<Bytes, io::Error>(c), rx))
    });
    (tx, Body::from_stream(stream))
}

fn dir_stats(dir: &Path) -> (usize, u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut count = 0;
    let mut bytes = 0;
    for entry in entries.flatten() {
        count += 1;
        bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
    }
    (count, bytes)
}

async fn wait_until(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

// --- item 1: multipart shapes

// SPEC §4: `meta` precedes `blob`; other shapes are refused and leave no spool behind. A third
// part after the blob is ignored, which the spec does not forbid.
#[tokio::test]
async fn spec_multipart_shapes() {
    let (app, _store, _blobs, root) = local("shapes", "1000000000").await;
    let blob = raw_blob(65536);

    // Blob first.
    let mut body = blob_head().into_bytes();
    body.extend_from_slice(&blob);
    body.extend_from_slice(
        format!("\r\n{}", meta_part(&meta(&keys(), "ttl").to_string())).as_bytes(),
    );
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    let wrong_order = send(&app, multipart(Body::from(body))).await;

    // A third part after the blob.
    let k = keys();
    let mut body = meta_part(&meta(&k, "ttl").to_string()).into_bytes();
    body.extend_from_slice(blob_head().as_bytes());
    body.extend_from_slice(&blob);
    body.extend_from_slice(
        format!("\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"extra\"\r\n\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(&vec![b'x'; 1024 * 1024]);
    body.extend_from_slice(closing().as_bytes());
    let third_part = send(&app, multipart(Body::from(body))).await;

    // Meta only.
    let mut body = meta_part(&meta(&keys(), "ttl").to_string()).into_bytes();
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    let meta_only = send(&app, multipart(Body::from(body))).await;

    // Body cut off in the middle of the blob (client sent less than it meant to).
    let mut body = create_body(&meta(&keys(), "ttl"), &raw_blob(LARGE));
    body.truncate(body.len() / 2);
    let truncated = send(&app, multipart(Body::from(body))).await;

    assert_eq!(wrong_order.status, StatusCode::BAD_REQUEST);
    assert_eq!(meta_only.status, StatusCode::BAD_REQUEST);
    assert_eq!(truncated.status, StatusCode::BAD_REQUEST);
    assert_eq!(third_part.status, StatusCode::CREATED);
    assert_eq!(dir_stats(&root.join("tmp")).0, 0);
    let _ = tokio::fs::remove_dir_all(&root).await;
}

// --- item 2 / 3: spool versus ceiling

// D-20: bytes being spooled count toward the ceiling, and a create that would cross it is
// refused mid-stream, so N stalled uploads cannot put N x SHH_EXTERNAL_MAX_OBJECT on the disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spec_spool_bytes_count_toward_the_ceiling() {
    const CEILING: u64 = 300_000;
    let (app, store, _blobs, root) = local("spool-ceiling", &CEILING.to_string()).await;
    // Fill the tier so a new large create must get 507.
    for _ in 0..2 {
        assert_eq!(
            create(&app, &keys(), "ttl", &raw_blob(LARGE)).await.status,
            StatusCode::CREATED
        );
    }
    let used = store.external_bytes().await.unwrap();

    const UPLOADS: usize = 4;
    const SENT: usize = 4 * 1024 * 1024;
    let mut senders = Vec::new();
    let mut tasks = Vec::new();
    for _ in 0..UPLOADS {
        let (tx, body) = channel_body();
        let app = app.clone();
        tasks.push(tokio::spawn(
            async move { send(&app, multipart(body)).await },
        ));
        // A refused upload stops reading, so sends may fail; that is the point.
        let _ = tx
            .send(Bytes::from(meta_part(&meta(&keys(), "ttl").to_string())))
            .await;
        let _ = tx.send(Bytes::from(blob_head())).await;
        for _ in 0..SENT / 65536 {
            if tx.send(Bytes::from(vec![0u8; 65536])).await.is_err() {
                break;
            }
        }
        senders.push(tx);
    }
    let tmp = root.join("tmp");
    // Give the uploads time to spool whatever the server lets through.
    wait_until(|| dir_stats(&tmp).1 >= (UPLOADS * SENT) as u64).await;
    let (_, spooled) = dir_stats(&tmp);
    assert!(
        used + spooled <= CEILING,
        "tier disk use {} exceeds ceiling {CEILING}",
        used + spooled
    );

    let tx = senders.pop().unwrap();
    let _ = tx.send(Bytes::from(closing())).await;
    drop(tx);
    drop(senders);
    for t in tasks {
        let reply = t.await.unwrap();
        assert_eq!(
            reply.status,
            StatusCode::INSUFFICIENT_STORAGE,
            "{}",
            reply.code()
        );
    }
    let after = dir_stats(&tmp).0;
    let _ = tokio::fs::remove_dir_all(&root).await;
    assert_eq!(after, 0, "spool files left behind");
}

// SPEC §6.1: the ceiling check is made under one reservation, so concurrent creates cannot
// jointly exceed it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn spec_concurrent_creates_respect_the_ceiling() {
    const CEILING: u64 = 300_000; // room for two 128 KiB objects
    let (app, store, _blobs, root) = local("ceiling-race", &CEILING.to_string()).await;
    let blob = Arc::new(raw_blob(LARGE));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let app = app.clone();
        let blob = blob.clone();
        tasks.push(tokio::spawn(async move {
            create(&app, &keys(), "ttl", &blob).await.status
        }));
    }
    let mut created = 0;
    let mut full = 0;
    for t in tasks {
        match t.await.unwrap() {
            StatusCode::CREATED => created += 1,
            StatusCode::INSUFFICIENT_STORAGE => full += 1,
            other => panic!("unexpected {other}"),
        }
    }
    let used = store.external_bytes().await.unwrap();
    let (_, disk) = dir_stats(&root.join("blobs"));
    let _ = tokio::fs::remove_dir_all(&root).await;
    assert_eq!((created, full), (2, 14));
    assert!(used <= CEILING, "ceiling crossed: {used} > {CEILING}");
    assert!(disk <= CEILING, "disk use {disk} > {CEILING}");
}

// --- item 2: aborted uploads

// SPEC §6.1: 100 uploads that stop mid-blob, half by the body ending early (client gone) and
// half by the request future being dropped (what hyper does on disconnect). No spool survives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spec_aborted_uploads_leave_no_spool_files() {
    let (app, _store, _blobs, root) = local("aborts", "1000000000").await;
    let tmp = root.join("tmp");
    for i in 0..100 {
        let (tx, body) = channel_body();
        let app2 = app.clone();
        let task = tokio::spawn(async move { send(&app2, multipart(body)).await });
        tx.send(Bytes::from(meta_part(&meta(&keys(), "ttl").to_string())))
            .await
            .unwrap();
        tx.send(Bytes::from(blob_head())).await.unwrap();
        for _ in 0..4 {
            tx.send(Bytes::from(vec![0u8; 65536])).await.unwrap();
        }
        assert!(
            wait_until(|| dir_stats(&tmp).0 >= 1).await,
            "upload {i} never spooled"
        );
        if i % 2 == 0 {
            drop(tx);
            let reply = task.await.unwrap();
            assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        } else {
            task.abort();
            let _ = task.await;
            drop(tx);
        }
    }
    let left = dir_stats(&tmp).0;
    let _ = tokio::fs::remove_dir_all(&root).await;
    assert_eq!(left, 0, "{left} spool files left after 100 aborted uploads");
}

// --- item 5: claim race through the API

// SPEC §5.1: exactly one concurrent reveal wins, on the inline and the local tier.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn spec_fifty_concurrent_reveals_have_one_winner() {
    for tier in ["inline", "local"] {
        let (app, root) = if tier == "inline" {
            let (app, _, _) = build("race-inline", &[]).await;
            (app, None)
        } else {
            let (app, _, _, root) = local("race-local", "1000000000").await;
            (app, Some(root))
        };
        let bucket = if tier == "inline" { 65536 } else { LARGE };
        let k = Arc::new(keys());
        assert_eq!(
            create(&app, &k, "single_view", &raw_blob(bucket))
                .await
                .status,
            StatusCode::CREATED
        );
        let mut tasks = Vec::new();
        for _ in 0..50 {
            let app = app.clone();
            let k = k.clone();
            tasks.push(tokio::spawn(async move { reveal(&app, &k).await }));
        }
        let mut winners = 0;
        let mut negatives = 0;
        let mut other = Vec::new();
        for t in tasks {
            let r = t.await.unwrap();
            match r.status {
                StatusCode::OK => {
                    assert!(r.headers.contains_key("x-shh-claim-token"));
                    assert_eq!(r.body.len() as u64, blob_len(bucket));
                    winners += 1;
                }
                StatusCode::NOT_FOUND if r.code() == "not_found" => negatives += 1,
                s => other.push(s),
            }
        }
        if let Some(root) = root {
            let _ = tokio::fs::remove_dir_all(&root).await;
        }
        assert_eq!((winners, negatives, other.len()), (1, 49, 0));
    }
}

// --- item 8: external tier serving

// SPEC §5.1: a row whose object is gone yields the uniform negative, and a single-view row is
// left untouched by the attempt (the object is opened before the claim is committed).
#[tokio::test]
#[ignore = "S-30"]
async fn spec_missing_object_is_the_uniform_negative() {
    let (app, _store, _blobs, root) = local("missing-object", "1000000000").await;
    let ttl = keys();
    let single = keys();
    for (k, lifetime) in [(&ttl, "ttl"), (&single, "single_view")] {
        assert_eq!(
            create(&app, k, lifetime, &raw_blob(LARGE)).await.status,
            StatusCode::CREATED
        );
    }
    for entry in std::fs::read_dir(root.join("blobs")).unwrap().flatten() {
        std::fs::remove_file(entry.path()).unwrap();
    }
    let ttl_reply = reveal(&app, &ttl).await;
    let single_reply = reveal(&app, &single).await;
    let single_again = reveal(&app, &single).await;
    let never = reveal(&app, &keys()).await;
    let _ = tokio::fs::remove_dir_all(&root).await;
    assert_eq!(never.status, StatusCode::NOT_FOUND);
    for (label, r) in [
        ("ttl", &ttl_reply),
        ("single-view", &single_reply),
        ("single-view again", &single_again),
    ] {
        assert_eq!((r.status, &r.body), (never.status, &never.body), "{label}");
    }
}

// The real accept loop, with its timeouts.
async fn serve(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(shhnote_server::serve::serve(
        listener,
        app,
        Arc::new(shhnote_server::drain::Drain::default()),
        std::future::pending(),
        Duration::from_secs(1),
    ));
    addr
}

// Reads until the server closes or `limit` passes; returns everything received.
async fn read_all(stream: &mut TcpStream, limit: Duration) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    let closed = tokio::time::timeout(limit, async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await
    .is_ok();
    (out, closed)
}

fn split_response(raw: &[u8]) -> (String, Vec<u8>) {
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4);
    (
        String::from_utf8_lossy(&raw[..at]).into_owned(),
        raw[at..].to_vec(),
    )
}

// SPEC §6.1: Content-Length comes from the bucket; a damaged object never delivers more than
// that, and a short one leaves the client with a truncated body it will reject.
#[tokio::test]
async fn spec_object_shorter_or_longer_than_bucket() {
    let (app, _store, _blobs, root) = local("object-size", "1000000000").await;
    let addr = serve(app.clone()).await;
    let expected = blob_len(LARGE) as usize;
    for (label, change) in [("shorter", -1000i64), ("longer", 1000)] {
        let k = keys();
        assert_eq!(
            create(&app, &k, "ttl", &raw_blob(LARGE)).await.status,
            StatusCode::CREATED
        );
        let object = std::fs::read_dir(root.join("blobs"))
            .unwrap()
            .flatten()
            .next()
            .unwrap()
            .path();
        let mut bytes = std::fs::read(&object).unwrap();
        bytes.resize((bytes.len() as i64 + change) as usize, 7);
        std::fs::write(&object, &bytes).unwrap();

        let body = json!({"lookup": b64(&k.lookup)}).to_string();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!(
                    "POST /api/v1/secrets/reveal HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let (raw, closed) = read_all(&mut stream, Duration::from_secs(5)).await;
        let (head, body) = split_response(&raw);
        assert!(head.starts_with("HTTP/1.1 200"), "{label}: {head}");
        if label == "shorter" {
            // The server cannot deliver what it promised, so it drops the connection.
            assert!(closed, "{label}: the server did not end the response");
            assert!(body.len() < expected, "{label}: body not truncated");
        } else {
            assert_eq!(body.len(), expected, "{label}: not cut at Content-Length");
        }
        std::fs::remove_file(&object).unwrap();
    }
    let _ = tokio::fs::remove_dir_all(&root).await;
}

// --- item 4: slow clients

// SPEC §7.1: header, idle and request timeouts close a connection that sends half a request
// line and one that stalls mid-upload, and the stalled upload's spool goes with it.
#[tokio::test]
async fn spec_stalled_clients_are_timed_out() {
    let (app, _store, _blobs, root) = local("slow", "1000000000").await;
    let addr = serve(app).await;

    let mut headers_only = TcpStream::connect(addr).await.unwrap();
    headers_only
        .write_all(b"POST /api/v1/secrets HTTP/1.1\r\nHost: local")
        .await
        .unwrap();

    let mut upload = TcpStream::connect(addr).await.unwrap();
    let mut body = meta_part(&meta(&keys(), "ttl").to_string()).into_bytes();
    body.extend_from_slice(blob_head().as_bytes());
    body.extend_from_slice(&vec![0u8; 1024 * 1024]);
    upload
        .write_all(
            format!(
                "POST /api/v1/secrets HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary={BOUNDARY}\r\nContent-Length: {}\r\n\r\n",
                blob_len(4 * 1024 * 1024) + 1024
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    upload.write_all(&body).await.unwrap();

    tokio::time::sleep(Duration::from_secs(35)).await;
    let spool = dir_stats(&root.join("tmp"));
    let (_, h_closed) = read_all(&mut headers_only, Duration::from_millis(500)).await;
    let (_, u_closed) = read_all(&mut upload, Duration::from_millis(500)).await;
    drop(upload);
    drop(headers_only);
    let _ = tokio::fs::remove_dir_all(&root).await;
    assert!(h_closed, "the header stall was not closed after 35 s");
    assert!(u_closed, "the upload stall was not closed after 35 s");
    assert_eq!(spool.0, 0, "the stalled upload's spool file survived");
}

// --- item 9: S3 client

// A minimal S3 stand-in: answers 200 with an empty body until `hang` is set, then accepts
// connections and never answers.
async fn fake_s3(hang: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let hang = hang.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if socket.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                let _ = socket.read_exact(&mut body).await;
                if hang.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    return;
                }
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    addr
}

async fn s3(name: &str, hang: Arc<AtomicBool>) -> (Router, Store, Arc<Blobs>, PathBuf) {
    let addr = fake_s3(hang).await;
    let spool = std::env::temp_dir().join(format!("shhnote-spec-resources-{name}-spool"));
    let endpoint = format!("http://{addr}");
    let (app, store, blobs) = build(
        name,
        &[
            ("SHH_STORAGE", "s3"),
            ("SHH_S3_BUCKET", "review"),
            ("SHH_S3_REGION", "us-east-1"),
            ("SHH_S3_ENDPOINT", &endpoint),
            ("SHH_S3_ACCESS_KEY_ID", "AKIDREVIEW"),
            ("SHH_S3_SECRET_ACCESS_KEY", "review-secret"),
            ("SHH_S3_MAX_TOTAL_BYTES", "1000000000"),
            ("SHH_SPOOL_PATH", spool.to_str().unwrap()),
        ],
    )
    .await;
    (app, store, blobs.unwrap(), spool)
}

// SPEC §6.1: the S3 client has timeouts, so a hung endpoint cannot hang the scrubber, a
// reveal or a create.
#[tokio::test]
async fn spec_hung_s3_does_not_hang_scheduler_reveal_or_create() {
    let hang = Arc::new(AtomicBool::new(false));
    let (app, store, blobs, spool) = s3("s3-hang", hang.clone()).await;
    let parked = keys();
    let served = keys();
    for k in [&parked, &served] {
        assert_eq!(
            create(&app, k, "ttl", &raw_blob(LARGE)).await.status,
            StatusCode::CREATED
        );
    }
    let req = Request::post("/api/v1/secrets/burn")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"burn_token": b64(&parked.burn_token)}).to_string(),
        ))
        .unwrap();
    assert_eq!(send(&app, req).await.status, StatusCode::NO_CONTENT);

    hang.store(true, Ordering::SeqCst);
    // The S3 client gives a response 10 s (plus upload time for a PUT) before giving up.
    let limit = Duration::from_secs(20);
    let scrub = tokio::time::timeout(limit, scheduler::scrub(&store, Some(&blobs)))
        .await
        .is_ok();
    let reveal_done = tokio::time::timeout(limit, reveal(&app, &served))
        .await
        .is_ok();
    let create_done = tokio::time::timeout(limit, create(&app, &keys(), "ttl", &raw_blob(LARGE)))
        .await
        .is_ok();
    let _ = tokio::fs::remove_dir_all(&spool).await;
    assert!(
        scrub && reveal_done && create_done,
        "S3 calls have no timeout"
    );
}

// --- item 9 / 10: configuration

// SPEC §6.1: an http:// S3 endpoint is refused in production unless it is loopback or private.
#[test]
#[ignore = "S-32"]
fn spec_production_refuses_plain_http_s3_endpoint() {
    let mut vars = base_vars();
    for (k, v) in [
        ("SHH_ENV", "production"),
        ("SHH_URL", "https://example.com"),
        ("SHH_STORAGE", "s3"),
        ("SHH_S3_BUCKET", "b"),
        ("SHH_S3_REGION", "r"),
        ("SHH_S3_ENDPOINT", "http://s3.example.com"),
        ("SHH_S3_ACCESS_KEY_ID", "a"),
        ("SHH_S3_SECRET_ACCESS_KEY", "s"),
        ("SHH_S3_MAX_TOTAL_BYTES", "1000"),
    ] {
        vars.insert(k.into(), v.into());
    }
    assert!(
        Config::from_vars(&vars).is_err(),
        "plain-http S3 endpoint accepted in production"
    );
    for private in [
        "http://127.0.0.1:9000",
        "http://10.0.0.5:9000",
        "http://[::1]:9000",
    ] {
        vars.insert("SHH_S3_ENDPOINT".into(), private.into());
        assert!(Config::from_vars(&vars).is_ok(), "{private} refused");
    }
}

// SPEC §7.1: only `*.part` files are removed from SHH_SPOOL_PATH at start.
#[tokio::test]
#[ignore = "S-31"]
async fn spec_spool_path_is_not_wiped_recursively() {
    let dir = std::env::temp_dir().join("shhnote-spec-resources-spool-wipe");
    let _ = tokio::fs::remove_dir_all(&dir).await;
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("shhnote.db"), b"pretend database").unwrap();
    std::fs::write(dir.join("stale.part"), b"left by a crash").unwrap();
    let hang = Arc::new(AtomicBool::new(false));
    let addr = fake_s3(hang).await;
    let mut vars = base_vars();
    let endpoint = format!("http://{addr}");
    for (k, v) in [
        ("SHH_STORAGE", "s3"),
        ("SHH_S3_BUCKET", "b"),
        ("SHH_S3_REGION", "r"),
        ("SHH_S3_ENDPOINT", endpoint.as_str()),
        ("SHH_S3_ACCESS_KEY_ID", "a"),
        ("SHH_S3_SECRET_ACCESS_KEY", "s"),
        ("SHH_S3_MAX_TOTAL_BYTES", "1000"),
        ("SHH_SPOOL_PATH", dir.to_str().unwrap()),
    ] {
        vars.insert(k.into(), v.into());
    }
    let config = Config::from_vars(&vars).unwrap();
    Blobs::open(config.storage.external.as_ref().unwrap())
        .await
        .unwrap();
    let survived = dir.join("shhnote.db").exists();
    let stale = dir.join("stale.part").exists();
    let _ = tokio::fs::remove_dir_all(&dir).await;
    assert!(survived, "a file in SHH_SPOOL_PATH was deleted at startup");
    assert!(!stale, "a stale .part file was kept");
}

// --- item 3: drift

// SPEC §6.1: at startup the tier is listed and objects no row references are deleted; the
// ceiling counts what the tier holds (`blob_len(bucket)`, not `bucket`).
#[tokio::test]
async fn spec_orphan_objects_are_collected_at_startup() {
    let (app, store, _blobs, root) = local("orphans", "1000000000").await;
    let k = keys();
    assert_eq!(
        create(&app, &k, "ttl", &raw_blob(LARGE)).await.status,
        StatusCode::CREATED
    );
    let orphan = root.join("blobs").join("AAAAAAAAAAAAAAAAAAAAAA");
    std::fs::write(&orphan, vec![0u8; 500_000]).unwrap();
    // Restart the tier.
    let mut vars = base_vars();
    for (k, v) in [
        ("SHH_STORAGE", "local"),
        ("SHH_LOCAL_PATH", root.to_str().unwrap()),
        ("SHH_LOCAL_MAX_TOTAL_BYTES", "1000000000"),
    ] {
        vars.insert(k.into(), v.into());
    }
    let config = Config::from_vars(&vars).unwrap();
    let reopened = Blobs::open(config.storage.external.as_ref().unwrap())
        .await
        .unwrap();
    // What `main` does right after opening the tier.
    reopened.collect_orphans(&store).await.unwrap();
    let counted = store.external_bytes().await.unwrap();
    let (objects, on_disk) = dir_stats(&root.join("blobs"));
    let survived = orphan.exists();
    let _ = tokio::fs::remove_dir_all(&root).await;
    assert!(!survived, "the orphan survived the restart");
    assert_eq!(objects, 1);
    assert_eq!(
        counted, on_disk,
        "ceiling count differs from what the tier holds"
    );
}

// --- item 10: shutdown

// SPEC §7.1: shutdown is bounded; a stalled upload cannot keep the process alive past the
// grace period, and its spool is removed on the way out.
#[tokio::test]
async fn spec_stalled_upload_does_not_block_shutdown() {
    use shhnote_server::drain::{Drain, track};
    let (app, _store, _blobs, root) = local("shutdown", "1000000000").await;
    let drain = Arc::new(Drain::default());
    let app = app.layer(axum::middleware::from_fn_with_state(drain.clone(), track));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(shhnote_server::serve::serve(
        listener,
        app,
        drain,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_secs(1),
    ));

    let mut upload = TcpStream::connect(addr).await.unwrap();
    let mut body = meta_part(&meta(&keys(), "ttl").to_string()).into_bytes();
    body.extend_from_slice(blob_head().as_bytes());
    body.extend_from_slice(&vec![0u8; 256 * 1024]);
    upload
        .write_all(
            format!(
                "POST /api/v1/secrets HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary={BOUNDARY}\r\nContent-Length: {}\r\n\r\n",
                blob_len(4 * 1024 * 1024) + 1024
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    upload.write_all(&body).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    stop_tx.send(()).unwrap();
    let stopped = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .is_ok();
    let spool = dir_stats(&root.join("tmp"));
    drop(upload);
    let _ = tokio::fs::remove_dir_all(&root).await;
    assert!(
        stopped,
        "graceful shutdown waits forever on a stalled upload"
    );
    assert_eq!(
        spool.0, 0,
        "the stalled upload's spool file survived shutdown"
    );
}
