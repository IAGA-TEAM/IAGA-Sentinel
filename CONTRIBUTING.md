# Contributing to IAGA Sentinel

Thanks for considering a contribution. IAGA Sentinel is the EU AI Act conformity
evidence layer for AI agents. We optimize for: deterministic
behavior, signed audit trails, and an honest enforcement posture. Anything
that strengthens those properties is welcome.

## Quick start

```bash
git clone https://github.com/IAGA-TEAM/IAGA-Sentinel
cd IAGA-Sentinel

# Build everything
cargo build --workspace

# Run the full test suite
cargo test --workspace
cargo test --workspace --all-features
cargo test -p iaga-sentinel-reasoning --features ml

# Lint (CI runs exactly this)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The default build uses no native ML deps. To exercise the ONNX backend
locally, add `--features ml` to `cargo build` / `cargo test` for the
`iaga-sentinel-reasoning` crate.

The Postgres tests are skipped — and still report green — unless a live
database is reachable, so an unset variable looks like a pass. Point them at
one to actually run them:

```bash
docker run -d --name iaga-pg -p 5432:5432 \
  -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=sentinel \
  -e POSTGRES_DB=sentinel_test postgres:16
export IAGA_SENTINEL_TEST_PG_URL="postgres://sentinel:sentinel@localhost:5432/sentinel_test"
cargo test -p iaga-sentinel-receipts --features postgres
```

That covers the receipt store only. The core schema's Postgres migrations are
exercised by running the binary against a `postgres://` URL — `iaga migrate
--db postgres://…` with `--features postgres` — not by any test.

## What we accept

- **Bug fixes** with a regression test.
- **Documentation** improvements.
- **New features** that fit the architecture described in
  [`README.md`](README.md) and the ADRs under [`docs/adr/`](docs/adr/).
- **Performance** improvements with a reproducible benchmark.

## ADRs are required for non-trivial changes

If your change introduces a new capability, alters a public trait, or
shifts an architectural boundary, add an ADR under
[`docs/adr/`](docs/adr/) following the numbering and template of the
existing ones (0001-0023; 0009 and 0022 are intentionally unused). Keep it
short: context, decision,
consequences, what's deliberately out of scope.

A PR that touches architecture without an ADR will be asked to add one
before review.

## Code style

- `cargo fmt --all` before submitting.
- `cargo clippy --workspace --all-targets -- -D warnings` must pass.
- Public APIs need rustdoc with at least a one-line summary.
- Prefer additive feature flags over breaking changes.
- Comments explain *why*, not *what*. Code says what.

## Adding an integration adapter

Adapters put IAGA Sentinel in the loop of an agent framework. They are **thin and
dependency-light**: they speak only the public `POST /v1/inspect` contract, never
import the target framework, and declare nothing authoritative.

1. Add the adapter under `sdks/python/iaga_sentinel/adapters/<framework>.py` (or
   `sdks/typescript/src/adapters/<framework>.ts`); reuse `_common.py`
   (`governed_callable`, `inspect_sync/async`) / `inspectWithPolicy`.
2. Map the framework's tool-call event to an `InspectRequest`; enforce the three
   verdicts (allow / review / block); fail **open** on transport errors by
   default (`fail_closed` / `failClosed` to opt out).
3. Add a fake test in `sdks/python/tests/` (duck-typed, no framework needed) and,
   when the framework installs, a real test in `sdks/python/tests/e2e/` guarded by
   `pytest.importorskip(...)` and the `e2e` marker.
4. Add the integration under `plug-ins/<framework>-adapter/`
   (code + `<framework>.policy.yaml` + `README.md`) and a row in
   `plug-ins/README.md`. Promote it (drop the `-adapter` suffix) once it is a
   self-contained, tested, deployable package like `plug-ins/voltagent-plugin/`.

## Commit conventions

We don't enforce Conventional Commits, but they help. Examples that
work well in this repo:

```
feat(receipts): add Postgres backend
fix(dictum): short-circuit `or` evaluating rhs eagerly
docs(adr): clarify stricter-wins merge semantics
chore(ci): cache cargo registry across jobs
```

## Branching and PRs

- Target `main` for PRs.
- One topic per PR. Refactors and feature work go in separate PRs
  whenever possible.
- CI must be green before merge. No skipped checks.
- Squash on merge unless commits are individually meaningful.

## License and the OSS / Enterprise relationship

IAGA Sentinel (the open, source-available build in this repository) is licensed under
[Business Source License 1.1](LICENSE) with **Change License:
Apache-2.0** and a Change Date of four years from publication. By
submitting a contribution you agree to license your work under the
same terms.

We do not require a CLA. BUSL-1.1 plus the automatic Apache-2.0
conversion baked into the licence is enough to keep the project
durable for community contributors and forks.

The third-party crates statically linked into the shipped binary are attributed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), generated from `Cargo.lock`.
Regenerate it whenever dependencies change: `cargo about generate about.hbs > THIRD_PARTY_NOTICES.md`.

**IAGA Sentinel Enterprise** is the planned commercial edition, currently
in development, built on the same governance kernel. As it is built,
Enterprise-only modules will live in a separate repository under a separate
commercial license. Contributions to this repo
flow into both editions automatically when they touch the shared
kernel; the reverse is never true (Enterprise-only code never lands
here).

What this means in practice for contributors:

- A bug fix or feature in `crates/iaga-sentinel-core`, `crates/iaga-sentinel-receipts`,
  `crates/iaga-sentinel-dictum`, `crates/iaga-sentinel-reasoning`, or `crates/iaga-sentinel-kernel`
  benefits both OSS and Enterprise users. Welcome.
- We will **never** silently move open-build features behind an
  Enterprise paywall. The public boundary is documented in
  [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).
- If you want to discuss building something Enterprise-only (a
  vertical compliance pack, a SIEM connector, a notified-body
  workflow), email `info@iaga.tech` rather than
  opening a PR here.

## Security

If you find a security issue that should not be reported publicly,
email `info@iaga.tech` rather than opening a public issue.
We'll respond within a reasonable timeframe and coordinate disclosure.

## Questions

Open a GitHub Discussion or issue. Founder reads everything.
