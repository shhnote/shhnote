# Security policy

This page is about the shhnote **software**: the server, the browser client, the
Argon2 WebAssembly module, the protocol specification, the conformance vectors and
the release pipeline in this repository.

A problem with one particular **website running shhnote** (an instance) goes to the
people who run it: every instance has its own security page, `/<language>/security`
(for example `/en/security`), with the operator's contact. Instances are independent;
the project cannot act on an instance's behalf and holds none of its data.

## Reporting a vulnerability

Please report privately, before any public discussion:

- **GitHub:** [Report a vulnerability](https://github.com/shhnote/shhnote/security/advisories/new)
  (private vulnerability reporting on this repository; only the maintainers see it).

Include what you found, which component and version (release tag or commit), how
to reproduce it, and what an attacker gains. A proof of concept against your own
instance is welcome; see *Testing* below.

## What counts

shhnote's promise is small and precise: the server never sees plaintext or key
material, learns as little as possible about who shares what with whom, and treats
every negative answer identically. Anything that breaks that promise is in scope,
whatever its CVSS score looks like. Examples:

- plaintext, the seed, a passphrase or a content key reaching the server, logs or
  storage, or being recoverable from what the server stores;
- a way to learn whether a secret exists, has been read, or who created or opened
  it (status, body, header, timing or size differences on the uniform negatives;
  joins across stored fields; proxy or access-log correlations the design claims
  to prevent);
- reading a single-view secret without consuming it, or consuming it without a
  real user action on the reveal page;
- bypassing the padding, chunk authentication, Argon2 bounds or fragment kinds
  described in `SPEC.md`, or a conformance vector the implementations disagree on;
- cross-site scripting, CSRF, CSP or header bypasses in the pages or the admin
  panel; session or API-key handling flaws;
- resource exhaustion a single unauthenticated client can cause (memory, disk,
  connections) beyond the documented limits;
- supply-chain weaknesses in the build or release pipeline, the Docker image or the
  published binaries.

Out of scope, or better reported elsewhere:

- issues in an individual instance's configuration, hosting, TLS setup or reverse
  proxy (report them to that operator);
- vulnerabilities in dependencies with no shhnote-specific impact (report upstream;
  a note to us is still welcome so we can update);
- findings that need a compromised browser, operating system or device, or a
  malicious operator (the threat model in `SPEC.md` names the operator as a
  party you must trust for availability, never for confidentiality — a way for a
  *non-malicious* operator to read secrets is very much in scope);
- volumetric denial of service, rate-limit tuning opinions, and missing
  best-practice headers without a demonstrated effect;
- social engineering of maintainers or operators.

## Testing

Test against an instance you run yourself; `docker compose up` in `deploy/docker/`
or `cargo run` gives you one in minutes. Do not test against instances you do not
operate: you would be reading or destroying other people's secrets, and loading
their rate limits. Good-faith research that follows this policy will not be met
with legal action by the project.

## What to expect

- Acknowledgement within 3 working days of a report.
- An assessment (in scope or not, severity, planned fix) within 10 working days.
- Fixes for confirmed issues in the protocol, confidentiality or the uniform
  negatives are treated as the highest priority and released as a patch version
  with a GitHub security advisory. Lower-severity issues ship with the next
  release.
- We coordinate disclosure with you. The default is to publish once a fix is
  released, or 90 days after the report, whichever comes first; we are happy to
  agree on something else if the fix takes longer and the risk is contained.
- Credit in the advisory and the changelog, if you want it.

## Supported versions

Security fixes go to the latest release and to `main`. Older releases are not
patched; upgrading is a binary or image swap with forward-only migrations.

## Design review

The protocol and its threat model are in [`SPEC.md`](SPEC.md). A full security
review of the code against that specification, with every finding, its fix and the
accepted residual risks, is in [`docs/security-review/`](docs/security-review/)
and its [`CHANGELOG.md`](docs/security-review/CHANGELOG.md). If your finding is
listed there as an accepted residual, a report is still welcome if you think the
assessment is wrong.
