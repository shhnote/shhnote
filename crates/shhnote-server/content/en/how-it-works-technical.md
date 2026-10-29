> This describes how secrets are designed to be protected. It will be kept in sync with the code as the features are built.

## Encryption

When you create a secret, your browser uses the built-in [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API):

1. It generates a random 256-bit key with a cryptographically secure random number generator.
2. It encrypts your note and each file with **AES-256-GCM**, using a fresh random nonce for each one. GCM also detects any change to the encrypted data.
3. It uploads only the encrypted data (the ciphertext), along with the expiry and burn-after-reading settings.

## The key stays in the link

The key is placed in the link's **fragment**, the part after `#`, for example `/s/abc123#key`. Browsers never send the fragment to the server, so the key doesn't appear in requests, server logs, or the referrer header. The server only ever sees the secret's ID.

## Passphrases

If you set a passphrase, a second key is derived from it with **PBKDF2-SHA-256**, using a random salt and a high number of iterations to slow down guessing. The secret can only be decrypted with both the key from the link and the passphrase. The passphrase is never sent to the server.

## Storage

The server stores the ciphertext, the expiry time and the settings. Small secrets are stored in the database; larger files may be stored on disk or in S3-compatible storage, depending on how the server is set up. Expired secrets are deleted, and burn-after-reading secrets are deleted as soon as they are fetched.

## Opening a secret

The secret page doesn't fetch anything until the recipient presses **Reveal secret**, so link previews can't use up a one-time secret. The browser then downloads the ciphertext, reads the key from the fragment, and decrypts it locally.

## Browser protections

Every page is sent with a strict Content Security Policy: scripts and styles can only come from our own server, and inline scripts are blocked. Pages can't be embedded in other sites, and the referrer policy stops the secret's address from being sent anywhere else. Secret pages are marked so browsers and proxies never cache them.

## What the server can see

The server can't read your secrets, but like any website it can see some details: when a secret was created and opened, its approximate size, and the IP addresses involved. If that's a concern, use a VPN or Tor.
