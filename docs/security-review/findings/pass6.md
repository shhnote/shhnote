# Pass 6 — Supply chain, build and deployment — findings

Reviewed: Cargo.toml (root and 4 crates), Cargo.lock (232 packages), client/package.json and package-lock.json, scripts/build-client.sh, scripts/build-wasm.sh, crates/shhnote-server/build.rs, Dockerfile, .dockerignore, deploy/{caddy,docker,fly,systemd}/*, .github/workflows/{ci,release}.yml, docs/deploy/*.md, .env.example, deploy/docker/.env.example, deploy/systemd/env.example, KNOWN list in crates/shhnote-core/src/config.rs; 2026-10-30. `.env` was not read.

Tooling run:
- `cargo 1.99.1`. `cargo install cargo-deny --locked` succeeded (cargo-deny 0.20.2).
- `cargo install cargo-audit --locked` FAILED twice (default features and `--no-default-features --features fix`): `aws-lc-sys v0.40.0` build script exits 1 in this sandbox. Not retried further. Coverage of advisories comes from `cargo deny check advisories`, which reads the same RustSec database (advisory-db commit dated Fri Oct 30 2026 12:12 +0100, fetched during the run). An operator should still run `cargo audit` once.
- No deny.toml exists in the repo, so one was written (outside the repo, config pasted below) and run: `cargo deny --config <deny.toml> check`. Result: advisories ok, sources ok, licenses: only the 4 workspace crates fail (no licence field, F-6-7), bans: only `wildcard` errors on the same crates (path deps without `publish = false`) plus 9 duplicate-version warnings.
- `cargo tree --duplicates --locked`: base64 0.22/0.23, sha2 0.10/0.11, digest/block-buffer/crypto-common/cpufeatures (0.10 vs 0.11 RustCrypto generations; the old ones come from sqlx-core and sqlx-postgres), getrandom 0.2 (ring) / 0.4, hashbrown 0.16/0.17, syn 2/3. All are consequences of sqlx 0.9 pinning older RustCrypto; no action except noting that sha2 and base64 are compiled twice.
- `cargo tree -e features -p shhnote-server --locked` (analysed in F-6-8). 191 distinct normal+build crates reach the server binary. No `openssl`, `native-tls`, `aws-lc-rs` or `tracing-subscriber` in the lock.
- `npm audit --package-lock-only` in client/: found 0 vulnerabilities (npm 11.19.1, node v24.22.1). Lockfile: 50 packages, every one with `resolved` on registry.npmjs.org and an `integrity` hash; direct deps pinned exactly (esbuild 0.28.2, typescript 7.0.2, @types/node 26.6.6). Only `esbuild` has an install script.
- `docker build .` of the root Dockerfile: succeeded (exit 0; most layers served from cache). Image 17.0 MB, `User=65532:65532`, `WorkingDir=/data`, `Entrypoint=[/shhnote]`, `EXPOSE 3000`, `HEALTHCHECK CMD /shhnote health`, only env SHH_HOST/SHH_PORT, one `VOLUME /data`. Ran it with `--read-only --cap-drop ALL --security-opt no-new-privileges` and a named volume: started, listed on 0.0.0.0:3000, `/shhnote health` returned `ok`, container reported `healthy`. Image, container and volume were removed afterwards. The file modes of scripts/*.sh are 100755 in the index and in the working tree (no "Permission denied").

deny.toml used (adopt as `deny.toml` in the repo root after fixing F-6-7; note: with the four workspace crates fixed, `cargo deny check` passes with warnings only):

```toml
[graph]
targets = [
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu",
]

[advisories]
unmaintained = "all"
yanked = "deny"

[licenses]
# Permissive licences that are compatible with distributing under AGPL-3.0-only.
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
    "CC0-1.0",
    "MPL-2.0",
    "CDLA-Permissive-2.0",
    "AGPL-3.0-only",
]
confidence-threshold = 0.9

[bans]
multiple-versions = "warn"
wildcards = "deny"
allow-wildcard-paths = true
# One TLS stack only: ring via rustls. aws-lc and native-tls/openssl would add C code.
deny = [
    { crate = "openssl" },
    { crate = "openssl-sys" },
    { crate = "native-tls" },
    { crate = "aws-lc-rs" },
    { crate = "aws-lc-sys" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

## Findings

### F-6-1: Release workflow: third-party actions pinned to mutable tags, write token for every job
Severity: Medium
Location: .github/workflows/release.yml:7-9 (workflow-level `permissions: contents: write, packages: write`), :23-24, :45, :49, :72-88 (`actions/checkout@v4`, `docker/*@v3|v5|v6`, `softprops/action-gh-release@v2`, `actions/upload-artifact@v4`); .github/workflows/ci.yml:25-40 (`dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`)
Violates: Principle 11 (minimal, auditable dependencies), Principle 12 (secure by default); CLAUDE.md "privacy- and security-focused" supply-chain stance
What: Every action is referenced by a floating tag (`@v4`, `@stable`), not a commit SHA. The release workflow grants `contents: write` and `packages: write` at workflow level, so the `binaries` job (which only builds and uploads artefacts) and every third-party action in it holds a token that can push images to ghcr.io and edit releases. A compromised or retagged action in any job can therefore ship a trojaned binary or image under the project's name. `softprops/action-gh-release` is a single-maintainer action that handles the signing-less release assets.
Reproduction: `grep -nE 'uses:|permissions' -A2 .github/workflows/release.yml` shows no 40-hex pins and one workflow-level permission block.
Fix: pin every `uses:` to a full commit SHA (comment with the tag; let Dependabot bump), set `permissions: {}` at workflow level and grant `contents: write` only to the `release` job and `packages: write` only to the `image` job. Not a spec conflict.

### F-6-2: Releases are not gated, scanned, signed or reproducible
Severity: Medium
Location: .github/workflows/release.yml:3-5 (trigger on any `v*` tag, no `needs` on tests), :35-45 (tar/gzip packaging), :55-62; .github/workflows/ci.yml (no audit/deny step)
Violates: Principle 11; Principle 12
What: (a) The release workflow runs on a tag push without depending on the CI test job, so a tag on an untested or red commit publishes binaries and a `latest` image. (b) Neither workflow runs `cargo audit`/`cargo deny` or `npm audit`; there is no deny.toml in the repo, so a new RustSec advisory is never surfaced automatically. (c) `SHA256SUMS` is uploaded to the same release as the files it covers, with no signature, provenance attestation (`actions/attest-build-provenance`, cosign) or SBOM, so it only detects corruption, not tampering. (d) The tarball is made with plain `tar -czf` (file mtimes, owner, gzip header timestamp vary), and the binary embeds a C-compiled bundled SQLite built by a floating Alpine gcc, so two builds of the same tag will not match bit for bit.
Reproduction: read the workflows; `grep -rn 'audit\|deny' .github` returns nothing.
Fix: make `release` call the CI workflow (`workflow_call`) or add a test job with `needs:`; add a CI job running `cargo deny check` with the deny.toml above and `npm audit --audit-level=high`; build tarballs with `tar --sort=name --mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner | gzip -n`; add build provenance attestation for binaries and image. No spec change.

### F-6-3: Dockerfile and compose use floating base images, no digests
Severity: Medium
Location: Dockerfile:1 (`# syntax=docker/dockerfile:1.7`), :6-9 (`rust:${RUST_VERSION}-alpine`, `node:24-alpine` twice), :13 (`rustup target add wasm32-unknown-unknown` at build time); deploy/docker/docker-compose.yml:12 (`ghcr.io/shhnote/shhnote:latest`), :32 (`caddy:2`), :50 (`postgres:17-alpine`); .github/workflows/ci.yml:21
Violates: Principle 11 (auditable), Principle 12; Dockerfile comment at :8-9 claims the Node version is "pinned"
What: Builder images are selected by tag (`1.99`, `24`), so the compiler, Node, Alpine gcc and musl change underneath an unchanged commit and the produced binary, including the WASM Argon2 module and JS bundles served to users, is not a function of the repo alone. The comment on the Node COPY says the version is pinned, but only the major is. The default compose file runs `:latest` of the app and an unpinned `caddy:2`, which is the process terminating TLS in front of the secrets.
Reproduction: `grep -nE '^(FROM|COPY --from)|image:' Dockerfile deploy/docker/docker-compose.yml` shows no `@sha256:`.
Fix: pin `FROM`/`COPY --from` to `tag@sha256:digest` (Dependabot/Renovate can bump), pin the dockerfile frontend by digest, pin compose images by digest and let `latest` in compose become the release version. No spec change.

### F-6-4: CI does not test what is released
Severity: Low
Location: .github/workflows/ci.yml:25-27 (`dtolnay/rust-toolchain@stable`), :44-52 (`cargo clippy`, `cargo test --workspace` without `--release` or `--locked`); Dockerfile:5 (`RUST_VERSION=1.99`), Cargo.toml:`[profile.release]` (`lto="thin"`, `strip`)
Violates: Principle 12
What: CI tests with whatever "stable" is that day, in the debug profile, on glibc; the release is built with Rust 1.99, thin LTO, on musl, on both x86_64 and aarch64 (the latter under QEMU, never tested). Overflow checks and `debug_assert!` are therefore active in tests and absent in the shipped binary. `--locked` is only used in the Dockerfile, so CI can pass on a lock file that the release build rejects (or silently update it).
Reproduction: compare the files above; no `--locked`, no `--release`, no musl target in ci.yml.
Fix: use the same toolchain version as the Dockerfile (one place, e.g. `rust-toolchain.toml`, which does not exist), add `--locked`, and run the test suite (at least the vectors and API tests) once with `--release`, ideally on the musl image.

### F-6-5: Build scripts are not locked and trust whatever is on disk
Severity: Low
Location: scripts/build-wasm.sh:6, scripts/build-client.sh:9-10, :14
Violates: Principle 11; SPEC §10 (build via these scripts, "one implementation serves both sides")
What: `build-wasm.sh` runs `cargo build` without `--locked`, and this script produces the `argon2.wasm` served to browsers (the Docker build calls it through `build-client.sh`; only the later server `cargo build` has `--locked`). If Cargo.toml and Cargo.lock ever disagree, the browser KDF is built from freshly resolved crates. `build-client.sh` runs `npm ci` only if `client/node_modules` is absent, so a stale or hand-edited node_modules is bundled without checking it against the lock file. `npm ci` also runs esbuild's install script (the only one in the lock) with network access. There is no `rust-toolchain.toml` and no `engines` pin tighter than `node >=24`.
Reproduction: read the scripts; `grep -c locked scripts/*.sh` is 0.
Fix: add `--locked` in build-wasm.sh, run `npm ci --ignore-scripts` unconditionally in CI/Docker (esbuild works without postinstall, it ships a platform package), add `rust-toolchain.toml`. A .gitattributes with `*.sh text eol=lf` is also advisable: none exists, and a Windows checkout with autocrlf produces `bash\r` failures in these scripts (the working tree here is LF, 100755, so no failure was seen).

### F-6-6: build.rs only checks that the embedded files exist
Severity: Low
Location: crates/shhnote-server/build.rs:7-17; crates/shhnote-server/src/web.rs:586-592 (`include_bytes!`), :596-614 (`asset_version`)
Violates: Principle 11 (auditable build)
What: The build script panics if `app.js`, `shh.js` or `argon2.wasm` is missing, but accepts an empty, truncated, stale or different file; nothing ties the embedded bytes to the current sources. A developer or a poisoned build cache (the Docker build uses a `target` cache mount) could embed an old `argon2.wasm`; the server then serves it with a hash that changes consistently, so nothing flags it. The vector tests do not run against the embedded files. The `.dockerignore` correctly excludes the three generated files so Docker always rebuilds them.
Reproduction: `: > crates/shhnote-server/static/shh.js && cargo build -p shhnote-server` compiles (not run in this checkout to avoid touching other passes' builds; follows from build.rs).
Fix: have build.rs assert the wasm starts with the `\0asm` magic and each JS file is non-empty, and ideally compare mtimes with `client/src` and the wasm crate; or build the artefacts from build.rs. Low value beyond hygiene.

### F-6-7: Workspace crates have no licence field (cargo deny licences fail)
Severity: Low
Location: Cargo.toml:`[workspace.package]`; crates/*/Cargo.toml
Violates: Principle 11 (AGPL-3.0 stated); README of the review (licence compatibility check)
What: client/package.json declares `AGPL-3.0-only` and the image label says the same, but none of the four crates sets `license`, and none sets `publish = false`. `cargo deny check licenses` reports "shhnote-core/-store/-server/-argon2-wasm is unlicensed", and the wildcard ban fires on path dependencies of crates that are treated as publishable.
Reproduction: `cargo deny --config <deny.toml> check licenses bans`: 4 `error[unlicensed]`, 2 `error[wildcard]`.
Fix: add `license = "AGPL-3.0-only"` and `publish = false` to `[workspace.package]` and `license.workspace = true`, `publish.workspace = true` to each crate. All 190+ third-party licences are permissive or dual-licensed (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode-3.0, CDLA-Permissive-2.0, Unlicense, BSL-1.0 alternatives; self_cell is `Apache-2.0 OR GPL-2.0-only`, so the Apache option is used); none conflicts with AGPL-3.0 distribution.

### F-6-8: Unneeded default features and a large transitive footprint
Severity: Low
Location: Cargo.toml (workspace deps): `axum` (defaults on), `tokio = ["full"]`, `sqlx` features list; crates/shhnote-server/Cargo.toml (`serde_json`, `fluent-bundle`, `webpki-roots`, `hyper-util` defaults)
Violates: Principle 11 / 13 ("every feature must hold or reduce attack surface")
What: From `cargo tree -e features -p shhnote-server`: (1) axum default features enable `tracing` and `tower-log` (pulls `tracing`, `tracing-attributes`, `tracing-core`, `syn 2` as a second syn); no subscriber exists and CLAUDE.md forbids using it, so it is dead weight. `matched-path` and `original-uri` are not used by the code (grep finds no `MatchedPath`/`OriginalUri`). (2) tokio `full` enables `process`, `io-std` and `parking_lot` that the server does not use (it uses fs, net, signal, time, sync, io-util, macros, rt-multi-thread). (3) sqlx's `sqlite` feature turns on `sqlite-load-extension` and `sqlite-deserialize`; neither is used by shhnote-store (no `extension`/`deserialize` in the source), and loading extensions is an attack surface that should be off by default. (4) sqlx-core always depends on `url`, which brings `idna` and about 20 ICU crates (Unicode-3.0); nothing shhnote does needs them and this cannot be switched off from here, so it is an accepted cost of sqlx. (5) Both SQLite (bundled C, SQLite 3.51.3 via libsqlite3-sys 0.37.0) and Postgres plus the rustls/ring/webpki stack are always compiled in; CLAUDE.md requires both drivers, so this is by design. (6) The workspace compiles sha2 and base64 in two major versions (via sqlx), noted by `cargo tree --duplicates`. TLS is a single stack (rustls 0.23 with ring, shared by sqlx and the hand-written S3 client); no OpenSSL or aws-lc in the tree.
Reproduction: `cargo tree -p shhnote-server --locked -e features --prefix none | grep -E 'axum feature|tokio feature|sqlx(-sqlite)? feature'`.
Fix: `axum = { default-features = false, features = ["http1","tokio","form","json","query","multipart"] }`; replace tokio `full` with the list above; use `sqlx` features `sqlite-bundled`-style granular options (`sqlite` is a bundle: replace by the narrower `_sqlite` set if sqlx 0.9 exposes it, otherwise record it as accepted); verify by rebuilding and diffing `cargo tree`. Each is a Low hardening item.

### F-6-9: docker-compose runs the app container with default capabilities and no limits
Severity: Low
Location: deploy/docker/docker-compose.yml:9-23 (service `shhnote`)
Violates: Principle 12 (secure by default)
What: The service already has `read_only: true`, a non-root image user and no published port (good), but keeps Docker's default capability set and privilege escalation, and has no `pids_limit`, memory limit or `tmpfs`. I ran the image with `--cap-drop ALL --security-opt no-new-privileges --read-only` and it started and passed its health check, so the extra options cost nothing. Caddy needs ports 80/443 and the data volumes, so it is not a candidate.
Reproduction: `docker run --read-only --cap-drop ALL --security-opt no-new-privileges ...` healthy; compose file lacks these keys.
Fix: add `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]`, `pids_limit`, and a memory limit to the `shhnote` service.

### F-6-10: systemd unit is strong but leaves cheap options unset
Severity: Low
Location: deploy/systemd/shhnote.service:21-47
Violates: Principle 12
What: The unit sets DynamicUser, NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, PrivateDevices, kernel/cgroup/clock/hostname protection, ProtectProc=invisible, RestrictAddressFamilies (INET, INET6, UNIX), RestrictNamespaces/Realtime/SUIDSGID, LockPersonality, MemoryDenyWriteExecute, empty capability sets, syscall filter and UMask=0077. Not set: `ProcSubset=pid`, `PrivateUsers` is implied by DynamicUser only for some options, `RemoveIPC=yes` (implied by DynamicUser), `LimitNOFILE` (default soft limit 1024 caps concurrent sockets for a public server that also opens SQLite/S3/Postgres handles), `TasksMax`/`MemoryMax`, and `IPAddressDeny`/`IPAddressAllow` for a service that only needs its reverse proxy, its DB and the S3 endpoint. `systemd-analyze security` is not installed here, so the exposure score was not measured.
Reproduction: read the unit; run `systemd-analyze security shhnote` on a host.
Fix: add `ProcSubset=pid`, `LimitNOFILE=65536`, `TasksMax`, `MemoryMax`, and document `IPAddressDeny=any` plus allow-list as an option.

### F-6-11: Deployment examples say `SHH_DB` has a default, the code requires it
Severity: Low
Location: deploy/docker/.env.example (`# sqlite (default, stored on the shhnote-data volume) or postgres.`), deploy/systemd/env.example (`# sqlite (default) or postgres.`), crates/shhnote-core/src/config.rs:377 (`vars.required("SHH_DB")`)
Violates: SPEC §7.1 / Principle 12 (docs must match behaviour); drift check 8
What: Both example files call sqlite the default, but a container started without `SHH_DB` exits with `error: config error: SHH_DB is required but not set` (reproduced with the built image). The shipped examples do set `SHH_DB=sqlite`, so a copy-and-edit deployment works; someone trimming the file to "only what differs from default" fails at startup. docs/deploy/operations.md:18 is right (marks it required). Otherwise the env-var drift check is clean: all 31 `KNOWN` variables appear in .env.example and in docs/deploy, and no documented variable is unknown to the code (`SHH_TEST_PG_URL` is a test-only variable in README/CLAUDE.md and is not read by the server).
Reproduction: `docker run --rm <image> ` with SHH_URL and SHH_SECRET_KEY only, observed exit with the message above.
Fix: change the two comments to "required: sqlite or postgres" (or give `SHH_DB` a default in config.rs and SPEC §7.1, which is a spec decision).

## Suspicions

- **Fly volume ownership.** deploy/fly/fly.toml.example mounts a fresh Fly volume at /data, while the image runs as 65532 and relies on `COPY --chown ... /data` for write access. A new Fly volume is root-owned and the image's directory ownership is hidden by the mount, so SQLite creation under /data may fail with permission denied. Could not test without a Fly account. Confirm with `fly deploy` on a fresh volume and `fly logs`; if it fails, run the machine as root only for a chown (not possible in a scratch image) or document `fly ssh`/an init step, or set the process user to root with the existing caps dropped.
- **BREACH with Caddy `encode zstd gzip`.** Both Caddyfiles compress all responses, including admin pages that contain CSRF tokens beside attacker-influenced text. Only exploitable if an admin page reflects attacker-chosen input next to the token. Confirm by checking the admin templates for reflected request data; compressing the already-encrypted blob responses just wastes CPU. The app sends no `Content-Encoding` itself, so there is no double compression.
- **Fly trusted proxy ranges.** `SHH_TRUSTED_PROXIES = "172.16.0.0/16,fdaa::/16"` trusts a whole private /16 and the whole 6PN /48 space; any other Fly app on the same private network can then spoof X-Forwarded-For and shift rate-limit buckets (Principle 7, best-effort). Confirm against Fly's current documentation of proxy source addresses and narrow if possible.
- **Static musl and long-lived roots.** TLS roots are compiled in (webpki-roots 1.0.11), so a CA removal needs a rebuild and a new image; there is no CA bundle in the scratch image. Confirm the update path is documented in docs/deploy/operations.md.
- **Docker volume with bind mounts.** With a bind mount instead of the named volume, /data is owned by root and the non-root user cannot write. The docs use named volumes only; confirm the docs say so.

## Checked and clean

- cargo deny advisories (RustSec DB of 2026-10-30, `unmaintained = "all"`, `yanked = "deny"`): no advisory, no unmaintained crate, no yanked crate in Cargo.lock. Sources: only crates.io, no git dependencies.
- Licences: every third-party crate is permissive or an OR-choice that includes a permissive licence; no GPL/LGPL/AGPL-only dependency; compatible with AGPL-3.0-only distribution. The wasm crate depends only on `argon2` (and not on shhnote-core), as CLAUDE.md requires.
- npm: 0 advisories; exactly three dev-dependencies, nothing from npm is shipped (esbuild bundles with no external imports); lock file complete with integrity hashes and registry URLs only.
- Header handling in deploy/: neither Caddyfile adds, removes or rewrites any header, so there is no duplicate or conflicting CSP/HSTS; the app alone sets CSP, HSTS (production), X-Frame-Options, nosniff, Referrer-Policy and Permissions-Policy (crates/shhnote-server/src/web.rs:538-569). Caddy overwrites incoming X-Forwarded-For unless trusted, and the compose subnet is fixed so `SHH_TRUSTED_PROXIES` can name it.
- Dockerfile: multi-stage; final stage is `scratch` with only the static binary and an empty /data owned by 65532; no shell, no package manager, no CA bundle. `.dockerignore` excludes .env, .env.*, .git, target, storage, deploy, docs and the generated static files, so no credentials or stale bundles enter the build context; no `ARG`/`ENV` carries a secret and no build secret can land in a layer (only `TARGETPLATFORM` and `RUST_VERSION` are args). `cargo build --release --locked` is used for the server. Health check works without a shell (exec form) and does not need the database. SIGTERM is the stop signal. Port 3000 only. Works on a read-only root filesystem (tested).
- docker-compose: shhnote has no published ports except via the optional own-proxy override, which binds 127.0.0.1; Postgres is not published; `stop_grace_period` (35 s) exceeds the server's 30 s drain; `read_only: true` set.
- .env.example files: all secret fields (`SHH_SECRET_KEY`, `SHH_ADMIN_TOKEN`, `SHH_PG_PASSWORD`, S3 keys) are empty or commented; the only literal values are host names and example domains. No long high-entropy strings in .env.example, deploy/ or docs/deploy (regex scan). Fly secrets are set with `fly secrets set`, not in fly.toml. Defaults in deploy/docker/.env.example and deploy/systemd/env.example are `SHH_ENV=production`. (The root .env.example is the development file with `SHH_ENV=local`/`SHH_DEBUG=true`; docs point operators at the deploy copies.)
- systemd unit: see F-6-10 for what is set; the environment file path and mode instructions are consistent with DynamicUser.
- CI: top-level `permissions: contents: read` in ci.yml; Postgres tests run via `SHH_TEST_PG_URL`; client tests run; the image build job proves the Dockerfile builds; the same Dockerfile target produces the release binary and the image. No features/cfg differences between CI and release (no cargo features are used).
- Documentation drift: all 31 variables in `KNOWN` appear in docs/deploy/operations.md and .env.example; no documented `SHH_*` name is unknown to the code (apart from prefix mentions like `SHH_PG_*`, and the test variable above).
- Script file modes: scripts/build-client.sh and build-wasm.sh are 100755 in the index and the working tree; no Permission denied.
