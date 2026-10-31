# Reverse proxies

shhnote speaks plain HTTP and expects a proxy in front for TLS. What the proxy must do:

- **Pass the request body through, up to the largest blob.** The server accepts blobs up to `SHH_EXTERNAL_MAX_OBJECT` (64 MiB by default) when an external tier is enabled, otherwise up to `SHH_INLINE_MAX` (2 MiB). Raise the proxy's body limit to match, or uploads fail at the proxy with an error the page cannot explain.
- **Forward the client address** in `X-Forwarded-For`, and list the proxy's address or range in `SHH_TRUSTED_PROXIES`. Without that every visitor looks like the proxy and shares one rate-limit bucket, including the admin login limit: a stranger's failed logins would then lock you out of the panel for an hour. The address is used for rate limiting only and is never stored.
- **Forward the Host header** unchanged. With `SHH_API_ROUTING=subdomain` the API is chosen by it, and `api.<domain>` needs its own site block.
- **Leave headers alone.** The app sets its own security headers (CSP, HSTS in production, referrer policy, frame denial). Don't add a second CSP.
- **Don't cache.** Blob responses carry `Cache-Control: no-store`; pages vary by `Accept-Language`. Caching nothing is the simplest correct setting.
- **Give stops time.** The server drains in-flight requests for up to 30 s on SIGTERM; the proxy's upstream timeouts should allow a large upload to complete (a few minutes for 64 MiB on a slow link).

## Caddy

```caddyfile
secrets.example.com {
	encode zstd gzip
	reverse_proxy 127.0.0.1:3000
}
```

Caddy sets `X-Forwarded-For`, keeps the Host header and has no default body limit. In Docker the upstream is `shhnote:3000` (see `deploy/docker/Caddyfile`).

## nginx

Guide to follow. The essentials: `client_max_body_size 70m;`, `proxy_set_header Host $host;`, `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`, `proxy_request_buffering off;` for large uploads, and `proxy_read_timeout` generous enough for them.

## Traefik

Guide to follow. Traefik forwards `X-Forwarded-For` and Host by default; set `SHH_TRUSTED_PROXIES` to the Docker network and add the router labels for the domain (and the `api.` host if used).
