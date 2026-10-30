use std::io;

use axum::body::Bytes;
use http_body_util::Empty;
use hyper::{Request, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use shhnote_core::config::Config;

// `shhnote health`: asks the server on this machine whether it and its database are fine.
// Containers built from `scratch` have no curl, so the binary probes itself.
pub async fn probe(config: &Config) -> io::Result<()> {
    // The API is routed by Host header, so the probe must present the API's own host.
    let (authority, prefix) = split_url(&config.api_url);
    let path = format!("{prefix}/v1/health");
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", config.bind_addr.port())).await?;
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(conn);
    let request = Request::get(&path)
        .header(header::HOST, authority)
        .body(Empty::<Bytes>::new())
        .map_err(io::Error::other)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{path} answered {}",
            response.status()
        )))
    }
}

// "https://host:port/api" -> ("host:port", "/api"); "https://api.host" -> ("api.host", "").
fn split_url(url: &str) -> (&str, &str) {
    let rest = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .trim_end_matches('/');
    match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_api_urls() {
        assert_eq!(
            split_url("http://localhost:3000/api"),
            ("localhost:3000", "/api")
        );
        assert_eq!(
            split_url("https://api.example.com"),
            ("api.example.com", "")
        );
        assert_eq!(
            split_url("https://api.example.com/"),
            ("api.example.com", "")
        );
    }
}
