# Running your own frontend

The built-in website is a minimal reference. An operator who wants a different site runs
their own frontend against the API, built on the [`@shhnote/client`](../../client/README.md)
package (or the `/static/shh.js` and `/static/shh-ui.js` bundles the instance serves), and
turns the built-in pages off with `SHH_WEB=api`. In that mode the instance serves only the
API, the admin panel and `/static/*`; every other route is 404. The frontend must meet the
[frontend conformance checklist](../frontend-conformance.md).

Two shapes work. Pick by whether the frontend and the instance share an origin.

## Shape 1: same origin, one proxy

The frontend's static files and the instance sit behind one Caddy (or nginx) on one
hostname. The proxy sends the instance's paths upstream and serves everything else from the
frontend's build directory. Nothing needs CORS; the admin panel keeps its path form.

```caddyfile
secrets.example.com {
	encode zstd gzip
	# The instance: API, admin panel, embedded assets (shh.js, shh-ui.js, argon2.wasm).
	handle /api/* {
		reverse_proxy 127.0.0.1:3000
	}
	handle /static/* {
		reverse_proxy 127.0.0.1:3000
	}
	@admin path_regexp ^/[a-z]{2}/admin(/.*)?$
	handle @admin {
		reverse_proxy 127.0.0.1:3000
	}
	# Everything else is your frontend.
	handle {
		root * /srv/frontend
		try_files {path} {path}.html /index.html
		file_server
		header {
			Content-Security-Policy "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; font-src 'self'; img-src 'self' data: blob:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
			Strict-Transport-Security "max-age=31536000; includeSubDomains"
			X-Frame-Options DENY
			X-Content-Type-Options nosniff
			Referrer-Policy no-referrer
			Permissions-Policy "camera=(), microphone=(), geolocation=()"
		}
	}
}
```

Instance settings for this shape: `SHH_WEB=api`, `SHH_API_ROUTING=path`,
`SHH_ADMIN_ROUTING=path`, `SHH_URL=https://secrets.example.com`, `SHH_TRUSTED_PROXIES` set to
the proxy's address. The frontend's API base is `https://secrets.example.com/api/v1`; the
admin panel is at `https://secrets.example.com/en/admin` (there is no locale redirect in
`api` mode, so link the full path). `allowed_origins` stays empty: same origin.

If the frontend bundles the package, serve `argon2.wasm` from your own build output with
`Content-Type: application/wasm` (Caddy's file server does that by extension). If it uses
the instance's bundles instead, `/static/argon2.wasm` is on the same origin and works as is.

## Shape 2: split origins

The frontend lives wherever static sites live (an object store, a CDN, another host); the
instance answers on `api.secrets.example.com` and the panel on `admin.secrets.example.com`.

Instance settings: `SHH_WEB=api`, `SHH_API_ROUTING=subdomain`, `SHH_ADMIN_ROUTING=subdomain`,
`SHH_URL=https://secrets.example.com` (the site origin, even though the instance serves no
page there), and in the admin panel `allowed_origins = https://secrets.example.com` — the
origin the browser sends in `Origin` when the frontend calls the API. The proxy in front of
the instance needs a site block per host (`api.` and `admin.`); the `admin.` block is the
place for an IP allow-list or client certificates.

The frontend's API base is `https://api.secrets.example.com/v1`. Its CSP must allow that
origin in `connect-src` (`connect-src 'self' https://api.secrets.example.com`). It must
serve `argon2.wasm` from its own origin (the package asset): the instance's `/static/*` is
not covered by CORS, so a cross-origin fetch of the module from the instance is blocked.
Requests never carry credentials; `user` API keys go in `Authorization`, which the preflight
allows.

Both shapes keep the properties the instance guarantees: identifiers travel only in request
bodies and fragments, the interstitial is static, and the instance learns nothing more about
a visitor than it did with the built-in pages.

## Behind Cloudflare (proxied DNS)

Putting either shape behind Cloudflare's proxy works, with settings that keep the pages
self-contained and the metadata path honest:

- **Turn off everything that rewrites pages or injects scripts**: Rocket Loader, Auto
  Minify, Email Address Obfuscation, Mirage, Polish, Web Analytics / Browser Insights
  (its beacon is an external script the CSP would block anyway), and "Always Online". Leave
  caching at its default for static files, but add a Cache Rule that bypasses the cache for
  `/api/*`, `/v1/*` and the admin paths, or rely on the `Cache-Control: no-store` the
  instance sends on those.
- **Onion Routing on** (Network → Onion Routing), so Tor users reach the site over Tor
  rather than through a CAPTCHA or a block.
- **Firewall the origin** to Cloudflare's published ranges, so nothing reaches the instance
  except through the proxy, and enable **Authenticated Origin Pulls** so the proxy must
  present Cloudflare's client certificate to your Caddy. Without both, a visitor who learns
  the origin address bypasses every Cloudflare setting.
- **Client addresses**: Cloudflare sends the visitor's address in `CF-Connecting-IP` and
  appends its own to `X-Forwarded-For`. Have Caddy put the former into the latter and trust
  only Caddy in `SHH_TRUSTED_PROXIES`:

  ```caddyfile
  reverse_proxy 127.0.0.1:3000 {
  	header_up X-Forwarded-For {http.request.header.CF-Connecting-IP}
  }
  ```

  The address is used for rate limiting only and never stored.
- **Say so on the privacy page.** Cloudflare sees every request's metadata (addresses,
  times, sizes), though not secrets, which are encrypted before upload. Add a sentence to the
  instance's privacy policy along these lines: *"This site is served through Cloudflare,
  which sees the metadata of every request (your address, the time, the size of what is
  sent) but not the secret itself, which is encrypted before it leaves your browser."*
