#!/usr/bin/env bash
# Builds the npm package (`@shhnote/client`): JavaScript plus declarations from the
# TypeScript sources, the Argon2 module as a package asset, then `npm pack`. The tarball
# lands in target/npm/. Release publishes it; by hand it is `npm publish <tarball>`.
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/build-wasm.sh
mkdir -p target/npm
(
  cd client
  rm -rf dist
  npm ci --ignore-scripts --no-audit --no-fund --silent
  npm run --silent typecheck
  npm run --silent build:package
  cp ../target/wasm32-unknown-unknown/wasm/shhnote_argon2_wasm.wasm argon2.wasm
  cp ../LICENSE LICENSE
  npm pack --pack-destination ../target/npm --silent
)
ls -1 target/npm/shhnote-client-*.tgz | tail -1
