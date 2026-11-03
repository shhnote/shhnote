# Running your own frontend

The built-in website is a minimal reference. An operator who wants a different site runs
their own frontend against the API, built on the [`@shhnote/client`](../../client/README.md)
package (or, when it shares the instance's origin, the `/static/shh.js` and
`/static/shh-ui.js` bundles the instance serves), and turns the built-in pages off with
`SHH_WEB=api`. In that mode the instance serves only the API, the admin panel and
`/static/*`; every other route is 404. The frontend must meet the
[frontend conformance checklist](../frontend-conformance.md).

**The frontend owns the root of the site.** In `api` mode the instance serves no `/`, `/s`,
`/burn` or `/report`, and no locale redirect. Share and burn links point at
`<SHH_URL>/s#…` and `<SHH_URL>/burn#…`, so the frontend must serve those paths at the root
of the `SHH_URL` origin, whichever shape below it uses. If its pages live under a language
prefix (`/en/s`, `/de/s`), it must also send visitors there itself; see
[Locale redirect](#locale-redirect).

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
`api` mode, so link the full path). `allowed_origins` stays empty: same origin. The
frontend's build directory must answer `/`, `/s`, `/burn` and `/report`, either directly or
through the [locale redirect](#locale-redirect) placed before the catch-all `handle`.

If the frontend bundles the package, serve `argon2.wasm` from your own build output with
`Content-Type: application/wasm` (Caddy's file server does that by extension). If it uses
the instance's bundles instead, `/static/argon2.wasm` is on the same origin and works as is.

## Shape 2: split origins

The frontend lives wherever static sites live (an object store, a CDN, another host); the
instance answers on `api.secrets.example.com` and the panel on `admin.secrets.example.com`.

Instance settings: `SHH_WEB=api`, `SHH_API_ROUTING=subdomain`, `SHH_ADMIN_ROUTING=subdomain`,
`SHH_URL=https://secrets.example.com` (the site origin, even though the instance serves no
page there). `allowed_origins` stays empty: the API always answers CORS requests from the
`SHH_URL` origin. Add an entry only for a frontend on some other origin, such as a preview
deployment or a second domain. The proxy in front of the instance needs a site block per
host (`api.` and `admin.`); the `admin.` block is the place for an IP allow-list or client
certificates. The static host serving the frontend at `secrets.example.com` must answer
`/`, `/s`, `/burn` and `/report` itself, directly or through the
[locale redirect](#locale-redirect).

The frontend's API base is `https://api.secrets.example.com/v1`. Its CSP must allow that
origin in `connect-src` (`connect-src 'self' https://api.secrets.example.com`). It must
serve `argon2.wasm` from its own origin (the package asset): the instance's `/static/*` is
not covered by CORS, so a cross-origin fetch of the module from the instance is blocked.
For the same reason the instance's `/static/shh.js` and `/static/shh-ui.js` cannot be used
in this shape: browsers load module scripts with CORS, and the frontend's
`script-src 'self'` would refuse them anyway. Bundle the package, or copy those files into
the frontend's own build.
Requests never carry credentials; `user` API keys go in `Authorization`, which the preflight
allows.

## Locale redirect

The built-in site answers `/`, `/s`, `/burn` and `/report` with a `307` to the same path
under the visitor's language (`/s` → `/de/s`), chosen from `Accept-Language`, keeping the
query string. Browsers carry the `#fragment` of a share or burn link across a redirect, so
the secret survives it. A frontend with a single language can skip this and serve its pages
at those paths directly. A frontend with language prefixes performs the redirect itself; in
Caddy, inside the frontend's site block and before its catch-all `handle`:

```caddyfile
	# The browser's first listed language if offered, otherwise the default.
	map {header.Accept-Language} {shh_locale} {
		~^\s*de\b  de
		default    en
	}
	@unprefixed path / /s /burn /report
	handle @unprefixed {
		# The target depends on the request's language: caches must key on it.
		header Vary Accept-Language
		# `*` first: a target starting with `/` would otherwise be read as a matcher.
		redir * /{shh_locale}{uri} 307
	}
```

Add a `map` line per further language. This looks only at the first language the browser
lists, not at the `q=` weights; browsers list the preferred language first, so the result is
usually the same, but a visitor whose first language is not offered gets the default even
when a later one is (the built-in site would pick the later one). The redirect
depends on a request header, so a CDN in front must not cache it for everyone: either it
honours `Vary: Accept-Language`, or its cache is bypassed for these four paths (with
Cloudflare, add them to the Cache Rule described below). With another server or a static
host, do the same: answer those four paths with a `307` (or `302`) to the same path under
the chosen prefix, keep the query string, add no fragment of your own (the browser keeps
the original), and send `Vary: Accept-Language`.

## Developing a frontend

Run an instance locally (`cargo run -p shhnote-server` or the image) with `SHH_ENV=local`,
which always uses path routing, and `SHH_WEB=api`. Finish its setup first (an admin key, a
site name and a contact address in the panel at `http://localhost:3000/en/admin`), or every
API call answers `503 not_configured`.

Then let the frontend's dev server proxy `/api/*` and `/static/*` to
`http://localhost:3000` (Vite's `server.proxy`, for example), so the page and the API share
an origin as in shape 1 and nothing needs CORS. If the dev server cannot proxy, add its
origin (for example `http://localhost:5173`; `http://` origins are accepted only when
`SHH_ENV=local`) to `allowed_origins` in the panel, and point the frontend's API base at
`http://localhost:3000/api/v1`. Never carry a development origin into production settings.

## What both shapes keep

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
  instance sends on those. If the frontend redirects by language, bypass the cache for `/`,
  `/s`, `/burn` and `/report` as well.
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
