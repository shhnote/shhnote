Everything the website does goes through this API, and anything else can use it the same way: scripts, bots, password managers, your own client. The server only ever handles encrypted blobs, so a client has to do the cryptography itself. The protocol is small and pinned by test vectors; the [technical details]({{site_url}}/how-it-works#technical) page describes it, and the `shh.js` library and `vectors/v1.json` in the source repository implement and verify it.

Base URL: `{{api_url}}/v1`. Requests and responses are JSON unless noted. Secret identifiers travel only in request bodies and never in paths or query strings.

## Errors

Every error is a JSON object:

```json
{"error": {"code": "invalid_ttl", "message": "The request is not valid."}}
```

Every operation that takes a secret credential answers **404 `not_found`** with an identical body for every failure, whether the secret never existed, has expired, was already opened, was burned or the credential is malformed. Nothing distinguishes those cases, on purpose.

Rate limits answer **429 `rate_limited`** with a `Retry-After` header in seconds. Limits are per endpoint and per client; nothing about the threshold is revealed.

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
  "regions": []
}
```

`padding.mode` is `padme` (with a minimum) or `buckets` (with a `ladder` of allowed sizes). `max_blob_bytes` is the largest padded size this instance stores. `text_max_bytes` and `files_enabled` are hints for user interfaces; the server enforces sizes only.

## `POST /secrets`

Stores a secret. The body is `multipart/form-data` with two parts in this order:

1. `meta`, JSON:

   ```json
   {
     "lookup_key": "<base64url of the lookup value>",
     "burn_key": "<base64url of the burn token>",
     "lifetime": "single_view",
     "ttl_seconds": 86400
   }
   ```

   `lifetime` is `single_view` or `ttl`. `ttl_seconds` must be within `min_ttl_secs` and `max_ttl_secs`; a single-view secret also expires after it if nobody opens it. Both keys are 32 bytes, base64url without padding. The server stores only their SHA-256.

2. `blob`, the encrypted blob as bytes. Its length must correspond exactly to a padded size the instance accepts.

Responds **201** with an empty body. Errors: `invalid_meta`, `invalid_lookup_key`, `invalid_burn_key`, `invalid_lifetime`, `invalid_ttl`, `invalid_blob_length`, `duplicate_key` (400); `files_disabled` (400, the instance accepts only text-sized secrets); `too_large` (413); `storage_full` (507, the instance has no room for large secrets right now); `api_key_required` (401, see below).

## `POST /secrets/reveal`

```json
{"lookup": "<base64url of the lookup value>"}
```

Returns the blob as `application/octet-stream` with `Cache-Control: no-store`.

For a **single-view** secret the first successful call consumes it and returns a `X-Shh-Claim-Token` header. Within `claim_window_secs` the same client may fetch the blob again by sending `{"lookup": …, "claim_token": "<that header>"}`, so an interrupted download can be retried. Nobody else can.

For a **TTL** secret the response carries `X-Shh-Expires-In-Hours`, whole hours rounded up, never an absolute time.

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

Anyone holding a link may report it. If the secret is active it is removed immediately. Always **200** with `{"status": "received"}`, whatever happened, and a ledger row that a report was received is kept.

## API keys

Requests may carry `Authorization: Bearer <key>`. A key with the `user` scope moves rate limiting from your network address to the key, with higher limits, and is required to create secrets on instances that are configured that way. Keys are issued by the operator in the admin panel and are never associated with any secret.

## Building a client

Derive the values the API expects from the 32-byte seed in the share link: `lookup = HKDF-SHA-256(seed, info "shhnote/lookup/v1")`, send it base64url-encoded. The burn token is a separate random 32 bytes the creator keeps. Blob layout, key wrapping, chunking and padding are specified on the [technical details]({{site_url}}/how-it-works#technical) page and pinned byte for byte by the conformance vectors; a client that reproduces them is compatible with every instance.
