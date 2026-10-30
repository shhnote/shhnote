#!/usr/bin/env bash
# Builds everything the server embeds from the client: the Argon2id module and the two
# JavaScript bundles. Run before `cargo build`; CI and the Docker image do the same.
set -euo pipefail
cd "$(dirname "$0")/.."
out=crates/shhnote-server/static
./scripts/build-wasm.sh
cp target/wasm32-unknown-unknown/wasm/shhnote_argon2_wasm.wasm "$out/argon2.wasm"
cd client
[ -d node_modules ] || npm ci
npm run --silent typecheck
npm run --silent build:lib
npm run --silent build:app
echo "built $out/shh.js, $out/app.js, $out/argon2.wasm"
