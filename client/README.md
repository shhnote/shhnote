# @shhnote/client

The client side of [shhnote](https://github.com/shhnote/shhnote): secrets are encrypted in
the browser, the server only ever sees ciphertext. This package is what the built-in website
and other frontends are made of.

Three entry points, take the layer you need:

- `@shhnote/client/crypto` — the protocol (SPEC §2): fragments, key derivation, the blob
  format, padding, chunked AES-GCM, the streaming decoder. No `fetch`, no DOM; pinned by the
  conformance vectors.
- `@shhnote/client` — the protocol plus the `Api` client, `createSecret` / `revealSecret` /
  `burnSecret` (claim-token retry, body-length cap), the Argon2 loader, `sanitiseFileName`,
  `isUserActivation` and the wipe helpers. No DOM; runs in browsers, Node and workers.
- `@shhnote/client/ui` — the reference page controllers (`wireCreate`, `wireReveal`,
  `wireBurn`, `wireReport`, …). They bind to `data-shh-*` attributes inside a root element
  you give them and take their strings as a `{ t }` object; no CSS, no markup of their own.

`@shhnote/client/argon2.wasm` is the Argon2id module (the same Rust crate the server uses),
to serve from your own origin; passphrase secrets need it.

```js
import { createSecret, revealSecret, Argon2 } from "@shhnote/client";

const api = { apiBase: "https://secrets.example.com/api/v1" };
const { fragment, burnFragment } = await createSecret({
  ...api,
  payload: { text: "the password is hunter2", files: [] },
  lifetime: "single_view",
  ttlSeconds: 86400,
});
const { payload } = await revealSecret(`#${fragment}`, api);
```

Every instance also serves the root and `/ui` entries as `/static/shh.js` and
`/static/shh-ui.js`, with `/static/argon2.wasm`, for frontends without a build step.

A frontend built on this package should meet the frontend conformance checklist in the
repository (`docs/frontend-conformance.md`). The package is versioned in lockstep with the
server: `@shhnote/client` x.y.z is released together with shhnote x.y.z. Compatibility with an
instance is by `fragment_version` in `GET /config`. AGPL-3.0-only.
