// Regression tests from the security review (docs/security-review/findings/SUMMARY.md) for
// memory bounds, measured with a counting allocator. They live in their own binary so nothing
// else disturbs the counters, and take a lock so they never run at the same time. Ignored
// tests are waiting for the step that fixes their finding; un-ignore them with the fix.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicIsize, Ordering},
    },
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use shhnote_core::{config::Config, settings::Settings};
use shhnote_server::{api::ApiState, app, storage::Blobs};
use shhnote_store::{Store, sqlite_path_for_tests};
use tower::ServiceExt;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let size = isize::try_from(layout.size()).unwrap_or(isize::MAX);
            let now = LIVE.fetch_add(size, Ordering::Relaxed) + size;
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        let size = isize::try_from(layout.size()).unwrap_or(isize::MAX);
        LIVE.fetch_sub(size, Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const BOUNDARY: &str = "----spec-memory";
const MIB: isize = 1024 * 1024;

async fn app(name: &str, env: &[(&str, &str)], overrides: &[(&str, &str)]) -> Router {
    let mut vars: HashMap<String, String> = [
        ("SHH_ENV", "local"),
        ("SHH_URL", "http://localhost:3000"),
        ("SHH_SECRET_KEY", &"s".repeat(44)),
        ("SHH_DB", "sqlite"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    vars.extend(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let config = Config::from_vars(&vars).unwrap();
    let overrides: HashMap<String, String> = overrides
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (settings, _) = Settings::with_overrides(&overrides);
    let blobs = match &config.storage.external {
        Some(ext) => Some(Arc::new(Blobs::open(ext).await.unwrap())),
        None => None,
    };
    let path = sqlite_path_for_tests(name);
    let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    app::router(&config, ApiState::new(store, settings, &config, blobs))
}

async fn status(app: &Router, req: Request<Body>) -> StatusCode {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let _ = axum::body::to_bytes(res.into_body(), usize::MAX).await;
    status
}

fn get_config() -> Request<Body> {
    Request::get("/api/v1/config")
        .header(header::HOST, "localhost")
        .body(Body::empty())
        .unwrap()
}

fn create_with(meta: &[u8], blob: &[u8]) -> Request<Body> {
    let mut body = Vec::with_capacity(meta.len() + blob.len() + 512);
    body.extend_from_slice(
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"meta\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(meta);
    body.extend_from_slice(
        format!("\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"blob\"\r\n\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(blob);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    Request::post("/api/v1/secrets")
        .header(header::HOST, "localhost")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        // Delivered in 64 KiB frames with a yield before each, like a socket, so the multipart
        // parser cannot drain the whole body into its own buffer in one go.
        .body(Body::from_stream(futures_util::stream::unfold(
            (body, 0usize),
            |(body, at)| async move {
                if at >= body.len() {
                    return None;
                }
                tokio::task::yield_now().await;
                let end = (at + 64 * 1024).min(body.len());
                let frame = axum::body::Bytes::copy_from_slice(&body[at..end]);
                Some((Ok::<_, std::io::Error>(frame), (body, end)))
            },
        )))
        .unwrap()
}

// Peak live heap above the level at the start of the request.
async fn peak_during(app: &Router, req: Request<Body>) -> (StatusCode, isize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let status = status(app, req).await;
    (status, PEAK.load(Ordering::Relaxed) - base)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// SPEC §4 / Principle 7: `GET /config` is never rate-limited, so it must not retain anything
// per request.
#[test]
fn spec_config_retains_nothing_per_request() {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    runtime().block_on(async {
        let site_name = "x".repeat(64 * 1024);
        for (name, overrides) in [
            ("spec-memory-config-default", vec![]),
            (
                "spec-memory-config-big",
                vec![("site_name", site_name.as_str())],
            ),
        ] {
            let app = app(name, &[], &overrides).await;
            for _ in 0..50 {
                assert_eq!(status(&app, get_config()).await, StatusCode::OK);
            }
            let before = LIVE.load(Ordering::Relaxed);
            for _ in 0..1000 {
                assert_eq!(status(&app, get_config()).await, StatusCode::OK);
            }
            let grown = LIVE.load(Ordering::Relaxed) - before;
            assert!(
                grown < 64 * 1024,
                "{name}: 1000 x GET /config left {grown} bytes live ({} per request)",
                grown / 1000
            );
        }
    });
}

// SPEC §4: the `meta` part is read in bounded chunks and refused past 4 KiB, so an oversized
// one costs no more memory than a blob of the same size, which is spooled.
#[test]
fn spec_meta_part_is_bounded_before_it_is_buffered() {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    runtime().block_on(async {
        let root = std::env::temp_dir().join(format!("spec-memory-meta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let app = app(
            "spec-memory-meta",
            &[
                ("SHH_INLINE_MAX", "65536"),
                ("SHH_STORAGE", "local"),
                ("SHH_LOCAL_PATH", root.to_str().unwrap()),
                ("SHH_LOCAL_MAX_TOTAL_BYTES", "1000000000"),
            ],
            &[],
        )
        .await;
        let big = vec![b'a'; 32 * 1024 * 1024];
        let small_meta = br#"{"lookup_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","burn_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB","lifetime":"ttl","ttl_seconds":3600}"#;

        let (code, meta_peak) = peak_during(&app, create_with(&big, b"")).await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        let (_, blob_peak) = peak_during(&app, create_with(small_meta, &big)).await;
        assert!(
            meta_peak < 8 * MIB,
            "a 32 MiB meta part peaked at +{} MiB",
            meta_peak / MIB
        );
        assert!(
            blob_peak < 8 * MIB,
            "a 32 MiB blob peaked at +{} MiB (it should spool)",
            blob_peak / MIB
        );
        let _ = std::fs::remove_dir_all(&root);
    });
}
