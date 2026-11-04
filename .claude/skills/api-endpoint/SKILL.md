---
name: api-endpoint
description: Add or change a public JSON API endpoint in shhnote-server. Use when creating routes under /api, request/response types, or API error handling.
---

# Adding a public API endpoint

The API is public, so treat its shape as a contract. Changing a field name or status code can break other people's clients. The endpoints, bodies and headers are defined in `SPEC.md` §4; implement those, don't invent new ones.

## Conventions

- All API routes live under `/api/v1`. A breaking change goes in a new version, never in place.
- Request and response bodies are JSON, using `serde` structs with `#[serde(rename_all = "snake_case")]`. Never return database row types directly; map them to response structs.
- Errors use one shared error type that implements `IntoResponse` and always returns the same JSON shape, for example `{"error": {"code": "not_found", "message": "..."}}`. `code` is stable and machine-readable; `message` is fixed English for humans and is never translated (clients show their own text keyed on `code`).
- Secret identifiers (lookup, claim and burn tokens) travel only in request bodies or multipart fields, never in paths, query strings or custom request headers.
- **Uniform negatives.** Every endpoint that takes a secret credential returns the same `404` with the same body for every failure: not found, expired, already consumed, wrong token, malformed input. Malformed input is replaced by fresh random bytes and run through the full path so timing matches. Never return early, never distinguish the cases.
- Every endpoint that takes a secret credential sits behind the rate limiter (`ratelimit.rs`): add `.layer(limited(Endpoint::X))` to the route and a `rate_x_per_hour` setting. Limits are per client (HMAC of the IP under a salt rotated every `salt_rotation_secs`, hourly by default; IPv6 by /64) and per endpoint; the 429 body is generic and `Retry-After` never reveals the threshold. `GET /config` is never limited.
- Elsewhere use the right status code: 400 bad input, 401 not signed in (admin), 413 too large, 429 rate limited, 500 our bug. Never put internal error details in a 500 response; log them instead.
- Validate input at the edge, in the handler or an extractor, before it reaches the database.
- Handlers stay thin: parse input, call a function that does the work, map the result to a response.

If the shared error type or `/api/v1` router doesn't exist yet, create it following these rules rather than inventing a one-off.

## Testing

Test each endpoint by building the router and sending requests to it in-process with `tower::ServiceExt::oneshot`. Cover the success case and each error status the endpoint can return. Endpoint tests run in-process on SQLite only; the store crate's tests also run on Postgres when `SHH_TEST_PG_URL` is set (see the `database` skill), so keep engine-specific SQL in the store.
