Everything the website does goes through this API, and anything else can use it the same way: scripts, bots, password managers, your own client. This instance runs shhnote {{version}}. The server only ever handles encrypted blobs, so a client has to do the cryptography itself. The protocol is small and pinned by test vectors; the [specification]({{spec_url}}) describes it, and the `shh.js` library and `vectors/v1.json` in the source repository implement and verify it.

Base URL: `{{api_url}}/v1`. Requests and responses are JSON unless noted. Secret identifiers travel only in request bodies and never in paths or query strings.

## Errors

Every error is a JSON object:

```json
{"error": {"code": "invalid_ttl", "message": "The request is not valid."}}
```

Every operation that takes a secret credential answers **404 `not_found`** with an identical body for every failure, whether the secret never existed, has expired, was already opened, was burned or the credential is malformed. Nothing distinguishes those cases, on purpose.

Rate limits answer **429 `rate_limited`** with a `Retry-After` header in seconds. Limits are per endpoint and per client; the header is a constant, so nothing about the threshold is revealed.

Until the operator has finished setting the instance up, every endpoint except `GET /health` answers **503 `not_configured`**.

## `GET /health`

Readiness for monitoring, no authentication:

```json
{"status": "ok", "version": "{{version}}", "configured": true}
```

`status` is `ok` when the database answers, otherwise `degraded` with **503**. `version` is the server version. `configured` is `false` until the operator has finished setting the instance up; until then every other endpoint answers `not_configured`. `GET /` (the API root) answers `{"name": "shhnote", "version": "v1"}` once the instance is set up, and `not_configured` before; use `/health` for monitoring.

## `GET /config`

Instance policy, no authentication. Read it before creating a secret: the padding policy decides which blob lengths the server accepts.

```json
{
  "fragment_version": 1,
  "padding": {"mode": "padme", "min": 65536},
  "inline_max": 2097152,
  "max_blob_bytes": 67108864,
  "claim_window_secs": 900,
  "min_ttl_secs": 60,
  "max_ttl_secs": 1209600,
  "default_ttl_secs": 86400,
  "ttl_presets": [900, 1800, 3600, 21600, 43200, 86400, 259200, 604800, 1209600],
  "text_max_bytes": 65536,
  "files_enabled": true,
  "regions": [],
  "server_version": "{{version}}",
  "web_mode": "full"
}
```

`padding.mode` is `padme` (with a minimum) or `buckets` (with a `ladder` of allowed sizes). `max_blob_bytes` is the largest padded size this instance stores. `text_max_bytes` and `files_enabled` are hints for user interfaces; the server enforces sizes only. `regions` lists the operator's sibling instances as `{"code", "name", "url"}` objects, empty when there are none. `server_version` is the server version, and `web_mode` is `full` when the instance serves its own website or `api` when it serves only the API.

## `POST /secrets`

Stores a secret. The body is `multipart/form-data` with two parts in this order:

1. `meta`, JSON:

   ```json
   {
     "lookup_key": "<base64url of SHA-256(lookup)>",
     "burn_key": "<base64url of SHA-256(burn_token)>",
     "lifetime": "single_view",
     "ttl_seconds": 86400
   }
   ```

   `lifetime` is `single_view` or `ttl`. `ttl_seconds` must be within `min_ttl_secs` and `max_ttl_secs`; a single-view secret also expires after it if nobody opens it. Both keys are 32-byte SHA-256 hashes, base64url without padding: `lookup_key` is `SHA-256(lookup)` and `burn_key` is `SHA-256(burn_token)`, computed by the client. The server stores them as sent and never sees `lookup` or the burn token at creation; reveal, confirm, report and burn send the unhashed values, and the server hashes them to find the secret.

2. `blob`, the encrypted blob as bytes. Its length must correspond exactly to a padded size the instance accepts.

Send a `Content-Length`. With it the server checks the blob's length against its policy and its ceilings before reading the blob; a chunked upload without one is checked only as the bytes arrive, and on an instance with an external tier it reserves room for the largest blob the instance accepts until it ends, so it can be refused with `storage_full` on a nearly full tier. The upload must keep an overall rate of 32 KiB/s after a 60-second grace period, or it is cut with `request_timeout`.

Responds **201** with an empty body, also when a secret with that `lookup_key` already exists (nothing is written then; a different answer would tell anyone holding a hash whether the secret is still there). Errors: `invalid_meta`, `invalid_lookup_key`, `invalid_burn_key`, `invalid_lifetime`, `invalid_ttl`, `invalid_blob_length`, `invalid_multipart` (400, the body is not two parts named `meta` and `blob` in that order); `files_disabled` (400, the instance accepts only text-sized secrets); `too_large` (413); `request_timeout` (408, the body arrived too slowly); `too_busy` (503 with `Retry-After`, too many uploads in progress); `storage_full` (507, the instance has no room for large secrets right now); `api_key_required` (401, see below).

## `POST /secrets/reveal`

```json
{"lookup": "<base64url of the lookup value>"}
```

Returns the blob as `application/octet-stream` with `Cache-Control: no-store`.

For a **single-view** secret the first successful call consumes it and returns a `X-Shh-Claim-Token` header. Within `claim_window_secs` the same client may fetch the blob again by sending `{"lookup": …, "claim_token": "<that header>"}`, so an interrupted download can be retried. Nobody else can.

For a **TTL** secret the response is the blob and nothing else: no claim token, and nothing about the remaining lifetime.

## `POST /secrets/confirm`

```json
{"lookup": "<base64url>", "claim_token": "<token from reveal>"}
```

Tells the server the client has decrypted a single-view secret, which destroys it before the claim window ends. **204** on success. Optional but polite.

## `POST /secrets/burn`

```json
{"burn_token": "<base64url of the burn token>"}
```

Destroys an active secret. Only the creator holds the burn token; the share link carries no burn authority. **204** on success.

## `POST /reports`

```json
{"lookup": "<base64url of the lookup value>"}
```

Anyone holding a link may report it. If the secret is active it is removed immediately. Always **200** with `{"status": "received"}`, whatever happened. The report is counted in that day's statistics; no record of which secret was reported exists.

## API keys

Requests may carry `Authorization: Bearer <key>`. A key with the `user` scope moves rate limiting from your network address to the key, with higher limits, and is required to create secrets on instances that are configured that way. Keys are issued by the operator in the admin panel and are never associated with any secret.

## Building a client

The quickest route is the `shh.js` module served by every instance at `/static/shh.js`, which also runs under Node. It wraps the whole flow in four calls and takes a fetch implementation of your choice:

```js
import { Argon2, createSecret, revealSecret, burnSecret } from "./shh.js";

const api = { apiBase: "{{api_url}}/v1" };
const { fragment, burnFragment } = await createSecret({
  ...api,
  payload: { text: "the password is hunter2", files: [] },
  lifetime: "single_view",
  ttlSeconds: 86400,
});
console.log(`{{site_url}}/s#${fragment}`);

const { payload } = await revealSecret(`#${fragment}`, api);
await burnSecret(`#${burnFragment}`, api); // 404 now: it was single-view
```

Passphrase-protected secrets additionally need `argon2: await Argon2.load(wasmBytes)` with the module from `/static/argon2.wasm`. A passphrase is a non-empty string: `""` is refused (`empty_passphrase`), and omitting the option is the only way to mean no passphrase. A failure after a single-view secret was claimed (a wrong passphrase, a dropped connection) carries a `claimToken`; pass it as `claimToken` on the retry and the secret is downloaded again instead of being lost, and `confirm: false` returns it on success for the same purpose.

Derive the values the API expects from the 32-byte seed in the share link: `lookup = HKDF-SHA-256(seed, info "shhnote/lookup/v1")`, send it base64url-encoded. The burn token is a separate random 32 bytes the creator keeps. When creating, send their hashes instead: `lookup_key = SHA-256(lookup)` and `burn_key = SHA-256(burn_token)`. Blob layout, key wrapping, chunking and padding are specified in the [protocol specification]({{spec_url}}) and pinned byte for byte by its conformance vectors; a client that reproduces them is compatible with every instance. To run an instance of your own, start at [the project]({{project_url}}).
