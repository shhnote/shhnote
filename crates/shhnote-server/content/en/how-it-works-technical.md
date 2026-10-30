> This describes the protocol in `SPEC.md`, the document the code is built from. Where the two disagree, the spec is right and the code is a bug.

## Creating a secret

Everything below happens in your browser, using the built-in [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). The server never runs any of it.

1. Your browser generates a random 256-bit **seed** and a separate random 256-bit **content key**.
2. Your text and files are packed into one payload: a small manifest (file names, types and sizes) followed by the file bytes.
3. The payload is **padded** to a size class, so the server learns only a rough size, never the exact one. The default scheme (Padmé) adds at most 12% and rounds every secret up to at least 64 KiB, so a password and a small file look the same.
4. The padded payload is encrypted in 64 KiB chunks with **AES-256-GCM** under the content key. Every chunk has its own nonce and authentication tag, and the final chunk is marked, so any tampering, reordering or truncation is detected.
5. The content key is **wrapped** (encrypted) with a key derived from the seed using HKDF-SHA-256. With a passphrase, the wrapping key is derived from the seed *and* an Argon2id stretch of the passphrase, so both are needed to unwrap it.
6. Only the encrypted blob is uploaded. It has exactly the same layout whether or not a passphrase was set, so the server can't tell which.

## The seed stays in the link

The share link looks like `/s#<version><seed>`. Everything after `#` is the **fragment**, which browsers never send to any server, so the seed doesn't appear in requests, server logs or the referrer. The `/s` page itself is identical for every secret.

To find the secret, your browser derives a separate **lookup value** from the seed (again with HKDF, so it can't be reversed) and sends that. The server stores only a SHA-256 hash of it. The same goes for every credential the server holds: a copy of the database contains nothing that can read, consume or destroy a secret.

## Passphrases

A passphrase is stretched with **Argon2id** (64 MiB of memory, 3 passes by default), using a random salt stored in the blob. The result is combined with the seed to form the wrapping key. The passphrase is never sent anywhere. Your browser first tries to unwrap the content key without a passphrase; only if that fails does it ask you for one, which is why the page has no passphrase box until it's needed.

## What the server stores

The encrypted blob, when it expires, whether it is single-view or timed, and hashes of the lookup and burn credentials. Blobs up to a few megabytes live in the database; larger ones on disk or in S3-compatible storage, depending on how the instance is run. There is no creation timestamp, no record of who created or opened anything, and no view counter. Only aggregate totals are kept, never linked to a secret.

## Opening a secret

The page fetches nothing until you press the button, so link previews and email scanners can't consume a one-time secret. A **single-view** secret is consumed the moment its bytes are served: if your download drops, your browser can fetch it again within fifteen minutes, but nobody else can, and after that it's gone. A **timed** secret can be opened until it expires. Either way the blob is decrypted locally, using the seed from the fragment.

## Burning

When you create a secret you also get a **burn link**, built from a separate random token the server only knows by its hash. Opening the burn link does nothing by itself; confirming destroys the secret. Only the creator holds it. Anyone with the share link can report a secret, which also removes it.

## Browser protections

Every page is sent with a strict Content Security Policy: scripts and styles only from our own server, no inline scripts. Pages can't be embedded in other sites, the referrer is never sent, and the reveal page is never cached. All assets are self-hosted; the client makes no requests to other origins.

## What the server can see

The server can't read your secrets, but like any website it sees each request as it happens: the moment, the size class of the blob, and the IP address it came from. It keeps none of that. If even that matters to you, use a VPN or Tor.
