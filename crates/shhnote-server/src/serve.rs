use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, extract::ConnectInfo};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::graceful::GracefulShutdown,
};
use tokio::{net::TcpListener, task::JoinSet};
use tower::ServiceExt;

use crate::drain::Drain;

// Time a connection may spend sending request headers, or sitting idle between requests.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
// After the drain, idle connections close at once; whatever is still stuck is cut when this passes.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

// Hyper's accept loop instead of `axum::serve`, which wires no timer and so leaves even hyper's
// default header timeout off (SPEC §7.1). `signal` starts the shutdown: `drain` refuses new
// requests and gives running ones `grace`, then every connection is closed, stuck ones cut.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    drain: Arc<Drain>,
    signal: impl Future<Output = ()>,
    grace: Duration,
) {
    let graceful = GracefulShutdown::new();
    let mut connections = JoinSet::new();
    let mut shutdown = std::pin::pin!(drain.wait_for(signal, grace));
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    crate::log_warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        // Finished connections are reaped as new ones arrive, so the set stays small.
        while connections.try_join_next().is_some() {}
        let app = app.clone();
        let service = service_fn(move |mut req: hyper::Request<Incoming>| {
            // What rate limiting keys on (behind SHH_TRUSTED_PROXIES, the forwarded address).
            req.extensions_mut().insert(ConnectInfo::<SocketAddr>(peer));
            app.clone().oneshot(req)
        });
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT)
            .serve_connection(TokioIo::new(stream), service);
        let conn = graceful.watch(conn);
        // Connection-level failures (resets, timeouts) are the client's; nothing to log.
        connections.spawn(async move {
            let _ = conn.await;
        });
    }
    if tokio::time::timeout(CLOSE_GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        crate::log_warn!("connections still open after the close grace; cutting them");
    }
    // Dropping a stalled upload's task runs its cleanup (the spool file goes with it).
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}
