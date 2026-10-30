# Conformance vectors

`v1.json` pins the exact bytes the fragment version `0x01` protocol in `SPEC.md` §2 must produce. The Rust and TypeScript test suites both load it; any implementation that passes it interoperates with ours.

Every "random" input (seed, content key, salt, IVs, nonce prefix, burn token) is fixed in the file, so an implementation under test must inject those values instead of drawing from its CSPRNG and then reproduce the full blob byte for byte.

## Contents

- `constants`: chunk size, header length, HKDF info strings, Argon2 defaults and client bounds.
- `vectors[]`: `inputs` (everything needed to encrypt) and `expected` (derived values, header, full blob). Decrypting `expected.blob_base64` with `inputs.seed` and `inputs.passphrase` must recover `inputs.text` and `inputs.files`.
- `reject[]`: blobs derived from a vector that must fail, with the reason.

Cases cover: direct and passphrase mode on identical content (same blob length, same layout), text + files with UTF-8 names, files only, Argon2 at the production defaults and at reduced cost, the `padme` and `buckets` policies, a payload exactly on a padding boundary and one byte over, a single full chunk, and a multi-chunk payload with a short final chunk.

## Regenerating

The generator is deliberately independent of both implementations: HKDF is written out from RFC 5869; AES-GCM and Argon2id come from OpenSSL via `cryptography`.

```
python3 -m venv .venv && .venv/bin/pip install cryptography
.venv/bin/python vectors/generate.py
```

Regenerate only for a deliberate protocol change, which also means a new fragment version and a new file (`v2.json`), never an edit to `v1.json`.
