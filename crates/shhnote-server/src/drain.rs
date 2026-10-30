use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

// Counts requests in flight so a stop can wait for them. Hyper's own graceful shutdown
// stalls a request whose body is still arriving, so the draining happens here instead.
#[derive(Default)]
pub struct Drain {
    stopping: AtomicBool,
    in_flight: AtomicUsize,
    changed: tokio::sync::Notify,
}

impl Drain {
    // Once the signal arrives, new requests are refused and this waits (bounded) for the
    // running ones to finish. When it returns, axum closes the then-idle connections.
    pub async fn wait_for(self: Arc<Self>, signal: impl Future<Output = ()>, grace: Duration) {
        signal.await;
        self.stopping.store(true, Ordering::SeqCst);
        let drained = async {
            while self.in_flight.load(Ordering::SeqCst) > 0 {
                self.changed.notified().await;
            }
        };
        if tokio::time::timeout(grace, drained).await.is_err() {
            crate::log_warn!(
                "{} request(s) still running after {}s; closing anyway",
                self.in_flight.load(Ordering::SeqCst),
                grace.as_secs()
            );
        }
    }
}

struct InFlight(Arc<Drain>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}

pub async fn track(State(drain): State<Arc<Drain>>, req: Request, next: Next) -> Response {
    if drain.stopping.load(Ordering::SeqCst) {
        let mut response = (StatusCode::SERVICE_UNAVAILABLE, "shutting down").into_response();
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
        return response;
    }
    drain.in_flight.fetch_add(1, Ordering::SeqCst);
    let _guard = InFlight(drain);
    next.run(req).await
}
