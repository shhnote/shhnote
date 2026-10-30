# syntax=docker/dockerfile:1.7
# Builds the Argon2 WASM module, the client bundles and a static musl binary, then ships
# only the binary. `docker buildx build --target binary --output type=local,dest=out .`
# extracts the same binary for bare-metal installs.

ARG RUST_VERSION=1.99

FROM rust:${RUST_VERSION}-alpine AS builder
RUN apk add --no-cache build-base
# Node 24 for the TypeScript build; taken from the official image rather than Alpine's
# packages so the version is pinned.
COPY --from=node:24-alpine /usr/local/bin/node /usr/local/bin/node
COPY --from=node:24-alpine /usr/local/lib/node_modules /usr/local/lib/node_modules
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
