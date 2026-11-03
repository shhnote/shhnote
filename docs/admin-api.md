# Admin API

The admin panel's operations are available as JSON, for operators who script their instance.

**Base path:** `/api/v1/admin` on the site's host (`SHH_API_ROUTING=path`, and always with `SHH_ENV=local`), or `/v1/admin` on the `api.` host (`SHH_API_ROUTING=subdomain`). The paths below are relative to it. `SHH_ADMIN_ROUTING` moves only the panel, not this API. The API answers before setup is complete (D-29), so a first admin key can be provisioned with the bootstrap token without opening the panel.

Every request needs `Authorization: Bearer <key>` with an **admin**-scoped key; on a fresh install the bootstrap token from `SHH_ADMIN_TOKEN` is accepted instead, until the first admin key exists. Anything else gets **401 `unauthorized`**, and repeated failures from one client are rate-limited like panel logins (**429 `rate_limited`**). Responses carry `Cache-Control: no-store`.

| Request | Body | Response |
|---|---|---|
| `GET /stats?days=30` | – | lifetime totals (`created`, `viewed`, `burned`, `expired`, `removed`, `reports`), the live `active` count (active and claimed secrets) and `days`: the last `days` days (1–400, default 30), newest first, each with `day` (`YYYY-MM-DD`, UTC) and the same six counters |
| `GET /settings` | – | `values`, `defaults` and the list of `overridden` keys, all values as strings |
| `PATCH /settings` | `{key: value, …}` | the same shape after saving; strings, numbers, booleans and lists of scalars are accepted, `null` resets a key to its default |
| `GET /keys` | – | `{"keys": [...]}`, each with `id` (hex of the key's hash), `name`, `scope` (`admin` or `user`), `created_at` and `last_used_on` |
| `POST /keys` | `{"name": …, "scope": "admin" \| "user"}` | **201** with `key` (the key itself, shown this once), `id`, `name`, `scope` and `created_at` |
| `POST /keys/delete` | `{"id": …}` | **204**; deleting the key you are using ends your access |

Timestamps are unix seconds. `created_at` is the moment the key was made. `last_used_on` is 00:00 UTC of the day the key was last used, or `null` if it never was: keys record the day of use, never the time (D-23).

There are no report records to fetch: reports are counted per day (D-19), and the counts are the `reports` fields of `GET /stats`.

Ending a key's sessions without deleting it ("End sessions", which sets the key's `sessions_valid_after`) is a panel action only. The API has no sessions: every request carries the key itself, so deleting the key is what ends its access here.

## Errors

Errors use the same JSON shape as the public API, `{"error": {"code": …, "message": …}}`.

| Status | Code | When |
|---|---|---|
| 400 | `invalid_json` | the body is not valid JSON of the shape the endpoint expects |
| 400 | `invalid_key` | `POST /keys` without a name of 1–80 characters or with a scope other than `admin` or `user`; `POST /keys/delete` with an `id` that is not a key hash in hex |
| 401 | `unauthorized` | no key, an unknown key, a `user` key, or the bootstrap token once an admin key exists |
| 404 | `no_such_key` | `POST /keys/delete` with a well-formed `id` that matches no key |
| 422 | `invalid_settings` | a settings patch failed validation; nothing changed, and `details` lists the problems |
| 429 | `rate_limited` | too many failed authentications from this client |
| 500 | `internal` | a database error |

A settings patch is merged over the current values and validated as a whole; on any problem nothing changes and the answer is **422 `invalid_settings`** with a `details` list. Changes apply immediately, without a restart.

The admin panel's operations are also available in the panel itself; this API exists for
operators who script their instance. It is not part of the public API documented on every
instance at `/{locale}/docs`. Authentication, rate limiting and `no-store` are as described
in `SPEC.md` §8.
