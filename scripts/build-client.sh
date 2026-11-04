#!/usr/bin/env bash
# Builds everything the server embeds from the client: the Argon2id module and the three
# JavaScript bundles (app.js, shh.js, shh-ui.js). Run before `cargo build`; CI and the Docker image do the same.
set -euo pipefail
cd "$(dirname "$0")/.."
out=crates/shhnote-server/static
./scripts/build-wasm.sh
cp target/wasm32-unknown-unknown/wasm/shhnote_argon2_wasm.wasm "$out/argon2.wasm"
(
  cd client
  # Always the lockfile, exactly, with install scripts off: esbuild's binary comes from its
  # platform package in the lockfile, so nothing downloads anything at install time.
  npm ci --ignore-scripts --no-audit --no-fund --silent
  npm run --silent typecheck
  npm run --silent build:lib
  npm run --silent build:app
  npm run --silent build:ui
)
# What the bundles were built from, so `build.rs` can refuse stale ones. Keep the input
# list in step with `crates/shhnote-server/build.rs`.
{
  find client/src crates/shhnote-argon2-wasm/src -type f
  printf '%s\n' client/package-lock.json client/tsconfig.json \
    crates/shhnote-argon2-wasm/Cargo.toml scripts/build-client.sh scripts/build-wasm.sh
} | LC_ALL=C sort -u | while IFS= read -r f; do printf '%s\n' "$f"; cat "$f"; done \
  | sha256sum | cut -d' ' -f1 > "$out/.stamp"
echo "built $out/shh.js, $out/shh-ui.js, $out/app.js, $out/argon2.wasm"
