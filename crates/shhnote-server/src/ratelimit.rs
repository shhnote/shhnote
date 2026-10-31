use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{ConnectInfo, FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;
use shhnote_core::{
    config::Cidr,
    secret::credential_hash,
    settings::{RateLimits, SettingsCell},
};
use shhnote_store::Scope;

use crate::api::ApiState;

// Each API operation has its own bucket per client (SPEC §7.2, principle 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Create,
    Reveal,
    Confirm,
    Burn,
    Report,
    Login,
}

// Who is being limited. IPs are never stored: only their keyed hash under the current salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subject {
    Ip([u8; 32]),
    // SHA-256 of an API key; set once API keys exist.
    ApiKey([u8; 32]),
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

struct Table {
    salt: [u8; 32],
    rotated_at: Instant,
    buckets: HashMap<(Endpoint, Subject), Bucket>,
}

pub struct RateLimiter {
    settings: Arc<SettingsCell>,
    trusted_proxies: Vec<Cidr>,
    table: Mutex<Table>,
}

// Bounded memory without tracking anyone: past this, individual buckets are evicted (SPEC §4).
const MAX_BUCKETS: usize = 200_000;

// What a 429 says to wait. A constant: the real wait would give away the threshold (SPEC §4).
pub const RETRY_AFTER_SECS: u64 = 60;

impl RateLimiter {
    pub fn new(settings: Arc<SettingsCell>, trusted_proxies: Vec<Cidr>) -> Self {
        Self {
            settings,
            trusted_proxies,
            table: Mutex::new(Table {
                salt: fresh_salt(),
                rotated_at: Instant::now(),
                buckets: HashMap::new(),
            }),
        }
    }

    // The address rate limiting sees: the socket peer, unless that peer is a trusted proxy,
    // in which case the nearest untrusted hop in X-Forwarded-For.
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        // A dual-stack listener reports IPv4 peers as `::ffff:a.b.c.d`; they are IPv4 clients.
        let peer = peer.to_canonical();
        if !self.is_proxy(peer) {
            return peer;
        }
        // Every X-Forwarded-For line, joined: a proxy that appends its own line rather than
        // merging must not leave the client's line to be read alone.
        let hops: Vec<IpAddr> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|line| line.split(','))
            .filter_map(|hop| hop.trim().parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical())
            .collect();
        hops.into_iter()
            .rev()
            .find(|&ip| !self.is_proxy(ip))
            .unwrap_or(peer)
    }

    fn is_proxy(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.trusted_proxies.iter().any(|range| range.contains(ip))
    }

    // Returns `Ok(())` to proceed, or the number of seconds until a token is available.
    pub fn check(&self, endpoint: Endpoint, ip: IpAddr) -> Result<(), u64> {
        let now = Instant::now();
        let rotation = Duration::from_secs(self.settings.load().salt_rotation_secs.max(60) as u64);
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        if now.duration_since(table.rotated_at) >= rotation {
            // Rotation drops every key at once: nothing from before can be correlated with anything after.
            table.salt = fresh_salt();
            table.rotated_at = now;
            table.buckets.clear();
        }
        self.bound(&mut table, now);
        let subject = Subject::Ip(keyed_hash(&table.salt, &ip_prefix(ip)));
        self.take(&mut table, endpoint, subject, self.per_hour(endpoint), now)
    }

    pub fn check_key(&self, endpoint: Endpoint, key_hash: [u8; 32]) -> Result<(), u64> {
        let now = Instant::now();
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        self.bound(&mut table, now);
        let per_hour = self
            .per_hour(endpoint)
            .saturating_mul(self.limits().user_multiplier);
        self.take(
            &mut table,
            endpoint,
            Subject::ApiKey(key_hash),
            per_hour,
            now,
        )
    }

    fn limits(&self) -> RateLimits {
        self.settings.load().rate_limits
    }

    fn per_hour(&self, endpoint: Endpoint) -> u32 {
        per_hour_of(&self.limits(), endpoint)
    }

    // Keeps the table under its bound by evicting individual buckets, never by clearing it:
    // a flood of fresh addresses must not reset anyone else's limit. Full buckets carry no
    // state and go first; then the newest, so the flood pays with its own entries while
    // established buckets stay.
    fn bound(&self, table: &mut Table, now: Instant) {
        if table.buckets.len() <= MAX_BUCKETS {
            return;
        }
        let limits = self.limits();
        table.buckets.retain(|(endpoint, subject), bucket| {
            let capacity = f64::from(capacity_of(&limits, *endpoint, subject));
            let refilled = bucket.tokens
                + now.duration_since(bucket.updated).as_secs_f64() * capacity / 3600.0;
            refilled < capacity
        });
        let target = MAX_BUCKETS / 2;
        if table.buckets.len() > target {
            let mut by_age: Vec<(Instant, (Endpoint, Subject))> = table
                .buckets
                .iter()
                .map(|(key, bucket)| (bucket.updated, *key))
                .collect();
            by_age.sort_unstable_by_key(|(updated, _)| std::cmp::Reverse(*updated));
            let surplus = by_age.len() - target;
            for (_, key) in by_age.into_iter().take(surplus) {
                table.buckets.remove(&key);
            }
        }
    }

    // Token bucket: `per_hour` capacity, refilled continuously at `per_hour` tokens an hour.
    fn take(
        &self,
        table: &mut Table,
        endpoint: Endpoint,
        subject: Subject,
        per_hour: u32,
        now: Instant,
    ) -> Result<(), u64> {
        if per_hour == 0 {
            return Ok(());
        }
        let capacity = f64::from(per_hour);
        let rate = capacity / 3600.0;
        let bucket = table.buckets.entry((endpoint, subject)).or_insert(Bucket {
            tokens: capacity,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(capacity);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(RETRY_AFTER_SECS)
        }
    }
}

fn per_hour_of(limits: &RateLimits, endpoint: Endpoint) -> u32 {
    match endpoint {
        Endpoint::Create => limits.create_per_hour,
        Endpoint::Reveal => limits.reveal_per_hour,
        Endpoint::Confirm => limits.confirm_per_hour,
        Endpoint::Burn => limits.burn_per_hour,
        Endpoint::Report => limits.report_per_hour,
        Endpoint::Login => limits.login_per_hour,
    }
}

fn capacity_of(limits: &RateLimits, endpoint: Endpoint, subject: &Subject) -> u32 {
    let base = per_hour_of(limits, endpoint);
    match subject {
        Subject::Ip(_) => base,
        Subject::ApiKey(_) => base.saturating_mul(limits.user_multiplier),
    }
}

fn fresh_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    // If the OS generator fails we keep the zero salt rather than refuse service; the limiter
    // still works, it is just linkable within this rotation.
    let _ = getrandom::fill(&mut salt);
    salt
}

fn keyed_hash(salt: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// IPv6 users usually hold a whole /64, so limiting per address would be no limit at all.
fn ip_prefix(ip: IpAddr) -> Vec<u8> {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets()[..8].to_vec(),
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: &'static str,
}

// The socket peer of a request. Requests built in tests carry no socket address; they all
// count as one anonymous client.
pub struct Peer(pub IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(peer_of(&parts.extensions)))
    }
}

pub(crate) fn peer_of(extensions: &axum::http::Extensions) -> IpAddr {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::from([127, 0, 0, 1]), |info| {
            info.0.ip().to_canonical()
        })
}

// Middleware: identifies the caller, consumes a token for this endpoint, or answers 429.
// A valid `user` API key in `Authorization: Bearer` gets its own, larger bucket (SPEC §4).
pub async fn limit(
    State((state, endpoint)): State<(ApiState, Endpoint)>,
    req: Request,
    next: Next,
) -> Response {
    let key_hash = match bearer_key(req.headers()) {
        Some(hash) => match state.store.find_api_key(&hash).await {
            Ok(Some(key)) if key.scope == Scope::User => {
                let _ = state.store.touch_api_key(&hash, crate::api::now()).await;
                Some(hash)
            }
            _ => None,
        },
        None => None,
    };
    if endpoint == Endpoint::Create
        && state.settings.load().require_api_key_for_create
        && key_hash.is_none()
    {
        return error(
            StatusCode::UNAUTHORIZED,
            "api_key_required",
            "This instance only accepts secrets from API key holders.",
        );
    }

    let result = match key_hash {
        Some(hash) => state.limiter.check_key(endpoint, hash),
        None => {
            let ip = state
                .limiter
                .client_ip(peer_of(req.extensions()), req.headers());
            state.limiter.check(endpoint, ip)
        }
    };
    match result {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            let mut response = error(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many requests from your connection. Please wait a little and try again.",
            );
            if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
    }
}

fn bearer_key(headers: &HeaderMap) -> Option<[u8; 32]> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    // Keys are 32 random bytes in base64url, always 43 characters.
    if token.len() != 43 {
        return None;
    }
    Some(credential_hash(token.as_bytes()))
}

fn error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    let body = ErrorBody {
        error: ErrorDetail { code, message },
    };
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(create_per_hour: u32) -> RateLimiter {
        let settings = shhnote_core::settings::Settings {
            rate_limits: RateLimits {
                create_per_hour,
                ..RateLimits::default()
            },
            ..Default::default()
        };
        RateLimiter::new(
            Arc::new(SettingsCell::new(settings)),
            vec!["10.0.0.1".parse().unwrap()],
        )
    }

    #[test]
    fn buckets_run_out_and_report_a_wait() {
        let limiter = limiter(2);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(limiter.check(Endpoint::Create, ip), Ok(()));
        assert_eq!(limiter.check(Endpoint::Create, ip), Ok(()));
        let wait = limiter.check(Endpoint::Create, ip).unwrap_err();
        assert_eq!(wait, RETRY_AFTER_SECS);
        // Other endpoints and other clients are unaffected.
        assert_eq!(limiter.check(Endpoint::Reveal, ip), Ok(()));
        assert_eq!(
            limiter.check(Endpoint::Create, "203.0.113.6".parse().unwrap()),
            Ok(())
        );
    }

    #[test]
    fn ipv6_is_limited_per_64() {
        let limiter = limiter(1);
        assert_eq!(
            limiter.check(Endpoint::Create, "2001:db8:1:2::1".parse().unwrap()),
            Ok(())
        );
        assert!(
            limiter
                .check(Endpoint::Create, "2001:db8:1:2::ffff".parse().unwrap())
                .is_err()
        );
        assert_eq!(
            limiter.check(Endpoint::Create, "2001:db8:1:3::1".parse().unwrap()),
            Ok(())
        );
    }

    #[test]
    fn rotation_forgets_everyone() {
        let limiter = limiter(1);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(limiter.check(Endpoint::Create, ip), Ok(()));
        assert!(limiter.check(Endpoint::Create, ip).is_err());
        let old_salt = {
            let mut table = limiter.table.lock().unwrap();
            table.rotated_at = Instant::now() - Duration::from_secs(4000);
            table.salt
        };
        assert_eq!(limiter.check(Endpoint::Create, ip), Ok(()));
        let table = limiter.table.lock().unwrap();
        assert_ne!(table.salt, old_salt);
        assert_eq!(table.buckets.len(), 1);
    }

    #[test]
    fn forwarded_headers_count_only_behind_trusted_proxies() {
        let limiter = limiter(10);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.7, 10.0.0.1"),
        );
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let stranger: IpAddr = "192.0.2.9".parse().unwrap();
        assert_eq!(
            limiter.client_ip(proxy, &headers),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        // A direct client claiming a forwarded address is ignored.
        assert_eq!(limiter.client_ip(stranger, &headers), stranger);
        // Garbage behind a trusted proxy falls back to the proxy itself.
        headers.insert("x-forwarded-for", HeaderValue::from_static("not an ip"));
        assert_eq!(limiter.client_ip(proxy, &headers), proxy);
    }

    #[test]
    fn api_keys_get_their_own_larger_bucket() {
        let limiter = limiter(1);
        let key = [7u8; 32];
        for _ in 0..RateLimits::default().user_multiplier {
            assert_eq!(limiter.check_key(Endpoint::Create, key), Ok(()));
        }
        assert!(limiter.check_key(Endpoint::Create, key).is_err());
    }
}
