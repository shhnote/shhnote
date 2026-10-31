# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Builds the Argon2 WASM module, the client bundles and a static musl binary, then ships
# only the binary. `docker buildx build --target binary --output type=local,dest=out .`
# extracts the same binary for bare-metal installs.
#
# Every image is pinned by digest (the tag is a reminder of what the digest is). To move
# one: `docker buildx imagetools inspect <image:tag>` prints the new index digest.

# Rust 1.99.1, the same as rust-toolchain.toml.
FROM rust:1.99-alpine@sha256:7e9e2d068a107a2adafd19930011178d14a78326053cd4c3a9f7ad3fd049557d AS builder
RUN apk add --no-cache build-base bash
# Node 24 for the TypeScript build; taken from the official image rather than Alpine's
# packages so the exact version is pinned.
COPY --from=node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 /usr/local/bin/node /usr/local/bin/node
COPY --from=node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && rustup target add wasm32-unknown-unknown
WORKDIR /src
COPY . .
ARG TARGETPLATFORM
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=target-${TARGETPLATFORM},target=/src/target \
    scripts/build-client.sh \
    && cargo build --release --locked -p shhnote-server \
    && cp target/release/shhnote /shhnote \
    && mkdir -p /data && chown 65532:65532 /data

# Just the binary, for release archives.
FROM scratch AS binary
COPY --from=builder /shhnote /shhnote

FROM scratch
LABEL org.opencontainers.image.title="shhnote" \
      org.opencontainers.image.description="Zero-knowledge secret sharing" \
      org.opencontainers.image.source="https://github.com/zbcdo/shhnote" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=builder /shhnote /shhnote
COPY --from=builder --chown=65532:65532 /data /data
# Relative defaults (storage/shhnote.db, storage/blobs, storage/spool) resolve under /data,
# so one volume holds everything. TLS roots are compiled in; no CA bundle is needed.
WORKDIR /data
VOLUME ["/data"]
USER 65532:65532
ENV SHH_HOST=0.0.0.0 \
    SHH_PORT=3000
EXPOSE 3000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/shhnote", "health"]
ENTRYPOINT ["/shhnote"]
