# Admin API

The admin panel's operations are available as JSON under `/admin`, for operators who script their instance. Every request needs `Authorization: Bearer <key>` with an **admin**-scoped key; on a fresh install the bootstrap token from `SHH_ADMIN_TOKEN` is accepted instead, until the first admin key exists. Anything else gets **401 `unauthorized`**, and repeated failures from one client are rate-limited like panel logins. Responses carry `Cache-Control: no-store`.

| Request | Body | Response |
|---|---|---|
| `GET /admin/stats?days=30` | – | lifetime totals, the live `active` count and the last `days` days (1–400), daily report counts included |
| `GET /admin/settings` | – | `values`, `defaults` and the list of `overridden` keys, all values as strings |
| `PATCH /admin/settings` | `{key: value, …}` | the same shape after saving; strings, numbers, booleans and lists of scalars are accepted, `null` resets a key to its default |
| `GET /admin/keys` | – | keys with `id` (hex of the key's hash), `name`, `scope`, `created_at`, `last_used_at` |
| `POST /admin/keys` | `{"name": …, "scope": "admin" \| "user"}` | **201** with the key itself, shown this once |
| `POST /admin/keys/delete` | `{"id": …}` | **204**; deleting the key you are using ends your access |

A settings patch is merged over the current values and validated as a whole; on any problem nothing changes and the answer is **422 `invalid_settings`** with a `details` list. Changes apply immediately, without a restart.

The admin panel's operations are also available in the panel itself; this API exists for
operators who script their instance. It is not part of the public API documented on every
instance at `/{locale}/docs`. Authentication, rate limiting and `no-store` are as described
in `SPEC.md` §8.
