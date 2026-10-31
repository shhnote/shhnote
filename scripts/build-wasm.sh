#!/usr/bin/env bash
# Builds the Argon2id WebAssembly module from the same Rust crate the server uses.
set -euo pipefail
cd "$(dirname "$0")/.."
rustup target list --installed | grep -q wasm32-unknown-unknown || rustup target add wasm32-unknown-unknown
cargo build --quiet --locked --profile wasm --target wasm32-unknown-unknown -p shhnote-argon2-wasm
out=target/wasm32-unknown-unknown/wasm/shhnote_argon2_wasm.wasm
echo "built $out ($(stat -c %s "$out") bytes)"
