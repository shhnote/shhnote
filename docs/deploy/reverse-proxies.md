# Reverse proxies

shhnote speaks plain HTTP and expects a proxy in front for TLS. What the proxy must do:

- **Pass the request body through, up to the largest blob.** `SHH_EXTERNAL_MAX_OBJECT` (64 MiB by default, with an external tier) and `SHH_INLINE_MAX` (2 MiB, without) are padded sizes; the blob for that size is a little longer (a 95-byte header plus a 16-byte tag per 64 KiB chunk, about 16 KiB at 64 MiB) and the upload adds up to 16 KiB of multipart framing. Set the proxy's body limit a little above the padded size (`70m` is comfortable for 64 MiB), or the largest uploads fail at the proxy with an error the page cannot explain.
- **Forward the client address** in `X-Forwarded-For`, and list the proxy's address or range in `SHH_TRUSTED_PROXIES`. Without that every visitor looks like the proxy and shares one rate-limit bucket, including the admin login limit: a stranger's failed logins would then exhaust it for everyone, and it refills at one attempt per `3600 / rate_login_per_hour` seconds (one every three minutes at the default of 20). The address is used for rate limiting only and is never stored.
- **Forward the Host header** unchanged. With `SHH_API_ROUTING=subdomain` the API is chosen by it, and `api.<domain>` needs its own site block; the same goes for `admin.<domain>` with `SHH_ADMIN_ROUTING=subdomain`, which is also where to put an IP allow-list or client-certificate rule for the panel.
- **Leave headers alone.** The app sets its own security headers (CSP, HSTS in production, referrer policy, frame denial). Don't add a second CSP.
- **Don't cache.** Blob responses carry `Cache-Control: no-store`; pages vary by `Accept-Language`. Caching nothing is the simplest correct setting.
- **Give stops time.** On SIGTERM the server drains in-flight requests for up to 30 s and then takes up to 5 s more to close connections, so a stop budget of 45 s is right; the proxy's upstream timeouts should allow a large upload to complete (a few minutes for 64 MiB on a slow link).

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
