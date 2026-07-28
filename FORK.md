# The Germ fork of mls-rs

`germ-network/mls-rs` is a fork of [`awslabs/mls-rs`](https://github.com/awslabs/mls-rs).
`main` tracks upstream verbatim and is never committed to directly — it is only
fast-forwarded. Everything Germ adds lives on branches rebased on top of it.

## Branch roles

| Kind | Purpose | Rewritten? |
| --- | --- | --- |
| `main` | Upstream mirror. Fast-forward only. | never |
| `feat/*`, `fix/*` | One self-contained change each, based on `main`. Reviewable in isolation and, where the change is not Germ-specific, submittable upstream as-is. | rebased onto `main` after a resync |
| `germ-integration` | The composition of every feature branch. What downstream builds against while a release is in development. | rebased freely |
| release pins | The exact tree a shipped release was built from. | **never** — treat as immutable |

`germ-shadow` and `germ-shadow-safe-exporter` predate this layout.
`germ-shadow-safe-exporter` is the pin for the TwoMLSPQ release currently in production
and must not be moved or deleted. New work composes onto `germ-integration` instead.

The cost of this layout is that history is not linear across an upstream resync — each
resync re-creates the feature commits on a new base, with new commit ids. The benefit is
that every change stays independently reviewable, independently upstreamable, and easy
to drop or reorder.

## Feature branches consumed by `germ-integration`

Applied in this order:

| Branch | PR | Commits | What it adds |
| --- | --- | --- | --- |
| `germ-crypto-providers` | [#1](https://github.com/germ-network/mls-rs/pull/1), [#2](https://github.com/germ-network/mls-rs/pull/2) (both merged) | 4 | ML-KEM-768 provider fix, cipher-suite comment cleanup and iOS minimum revert, `mls-rs-crypto-cryptokit` build.rs adapted to the Swift build output layout, and the missing CryptoKit bridge to ML-KEM. Carries the content of both merged PRs rebased onto `main`: #1's head branch was deleted on merge and #2's (`fix/build-tooling`) is still at the pre-resync base, so this branch is the maintained form. |
| `fix/cryptokit-build-rpath` | — | 1 | Stops the cryptokit build panicking when a toolchain reports `librariesRequireRPath` (Xcode 26), and lowers `MIN_OSX_DEPLOYMENT_TARGET` to 15.0. Previously carried only on `germ-shadow-safe-exporter`, outside any feature branch. |
| `feat/safe-extensions-exporter` | [#4](https://github.com/germ-network/mls-rs/pull/4) | 4 | draft-ietf-mls-extensions-08 Safe Extensions: the exporter tree behind `Group::safe_export_secret`, and `psk_type = application(3)`. Feature-gated on `safe_extensions`. |
| `feat/attachment-cek` | supersedes [#3](https://github.com/germ-network/mls-rs/pull/3) | 2 | draft-sullivan-mls-attachments content encryption keys, layered on the exporter tree. Stacked on `feat/safe-extensions-exporter`. |
| `ci/fork-ci` | [#8](https://github.com/germ-network/mls-rs/pull/8) | 1 | `.github/workflows/germ-ci.yml`, the fork's own credential-free CI. Applied last; touches nothing the other branches do. |

Where a merged PR's head branch has been deleted or left at an old base, the maintained
branch listed above supersedes it. Delete a feature branch only once its content is
either merged upstream or folded into another maintained branch — otherwise the audit
below loses its reference point, which is how `fix/cryptokit-build-rpath` went missing.

`feat/attachment-cek` is the only stacked branch — it needs the exporter tree, so it
carries `feat/safe-extensions-exporter`'s four commits rebased onto `main` beneath its
own two. PR #3 targeted `main` with a parallel implementation that duplicated the
exporter tree and added a second field to `EpochSecrets`; `feat/attachment-cek` replaces
it with a version that reuses the tree and adds no persisted state.

## No pull request in this fork is ever merged

`main` is a fast-forward-only mirror of upstream. Merging anything into it would put Germ
commits on the mirror and break that invariant, so **every open PR here is permanent and
for review only** — including the ones that look mergeable:

| PR | What it documents | State |
| --- | --- | --- |
| #4 `feat/safe-extensions-exporter` → `main` | the Safe Extensions diff on its own | draft |
| #5 `germ-integration` → `main` | the whole composed stack | draft |
| #6 `fix/cryptokit-build-rpath` → `main` | the recovered build fix on its own | draft |
| #7 `feat/attachment-cek` → #4 | the attachment diff on its own | draft |
| #8 `ci/fork-ci` → `main` | the fork's CI workflow on its own | draft |

They exist so each change has a reviewable diff and a discussion thread. Content leaves
this fork by being submitted upstream to `awslabs/mls-rs`, not by being merged here.
`germ-integration` reaches consumers by being pinned, not merged.

**Open every one of them as a draft, and leave it that way.** GitHub disables the merge
button on drafts, which is the only mechanical guard against someone merging a PR that
looks perfectly ordinary — #6 is a one-file build fix; nothing about it hints that
merging would corrupt the mirror. "Ready for review" here would mean "ready to merge",
which is never true. Review drafts as-is; the state carries no meaning beyond the guard.

## Reconstructing `germ-integration`

This is the whole build recipe. It takes only branch names — no commit ids — so it stays
correct as branches are rebased, and it is the definition of what `germ-integration` is:

```bash
git fetch origin
git checkout -B germ-integration origin/main

for range in \
  origin/main..origin/germ-crypto-providers \
  origin/main..origin/fix/cryptokit-build-rpath \
  origin/main..origin/feat/safe-extensions-exporter \
  origin/feat/safe-extensions-exporter..origin/feat/attachment-cek \
  origin/main..origin/ci/fork-ci
do
  git cherry-pick $(git rev-list --reverse --no-merges $range)
done

git cherry-pick <the FORK.md documentation commit>
```

Order matters and matches the feature-branch table above: crypto providers, then the
build fix, then the exporter tree, then attachments on top of it, then CI. The fourth
range is `feat/safe-extensions-exporter..feat/attachment-cek` rather than `main..`,
because #7 is stacked on #4 and carries its commits — taking `main..` would apply them
twice.

Reconstruction is deterministic: rebuilding from these five ranges reproduces the
previous `germ-integration` tree hash exactly. That is worth re-checking after a rebuild:

```bash
git diff --stat <previous germ-integration> HEAD   # expect empty
```

## After an upstream resync

```bash
git fetch upstream && git push origin upstream/main:main
```

Rebase each `feat/*`, `fix/*`, and `germ-crypto-providers` branch onto the new `main` so
they stay independently reviewable, then re-run the reconstruction above and the audit
below.

## Auditing for undocumented changes

Any commit that reaches `germ-integration` without a corresponding feature branch is a
bug in the process — that is exactly how `fix/cryptokit-build-rpath` went missing for a
release. To audit:

```bash
git fetch origin '+refs/pull/*/head:refs/remotes/pr/*'
git log --no-merges --oneline origin/main..germ-integration
```

and confirm every entry is reachable from some feature branch. Compare with
`git patch-id --stable` rather than commit id, since cherry-picking rewrites ids:

```bash
git show <commit> | git patch-id --stable
```

This document is the one legitimate exception: it describes the composition, so it
only exists on `germ-integration`. Everything else flagged is a real gap.

## Who enables `safe_extensions`

Nothing in this repo does. The feature is declared in `mls-rs/Cargo.toml` and left off;
consumers opt in, because enabling it changes the persisted group-state format (see
below).

The consumer is **TwoMLSPQ**, in `rust/Cargo.toml`:

```toml
[workspace.dependencies]
mls-rs = { version = "0.55", features = ["psk", "private_message", "serde", "safe_extensions"] }

[patch.crates-io]
mls-rs = { git = "https://github.com/germ-network/mls-rs", rev = "<pin>" }
```

That `rev` is pinned in five workspace dependency entries plus the `[patch.crates-io]`
redirect — all six move together when TwoMLSPQ takes a new pin.

TwoMLSPQ wraps `mls-rs` directly with its own uniffi layer (`rust/two-mls-pq`) and does
**not** depend on the `mls-rs-uniffi` crate in this repo, so changes there reach nobody.
Leave it alone unless that changes.

<<<<<<< Updated upstream
=======
## CI

Until recently no commit in this fork — including the shipped release pin — had
ever been checked by anything but a laptop. Actions was disabled, and several
upstream workflows cannot run here regardless: `Benchmarks on Merge` assumes an
IAM role in awslabs' AWS account, `Pull Request Slack Notifier` needs their
webhook, and `Native`'s coverage step needs their Codecov token.

`.github/workflows/germ-ci.yml` is the fork's own workflow and the only enabled
one. Every upstream workflow is **disabled via the Actions API, not deleted** —
the files stay byte-identical to upstream so they keep resyncing cleanly. Re-enable
with `gh workflow enable <id>`; list with `gh workflow list --all`.

Jobs: tests on Linux and macOS (default, `safe_extensions`, TwoMLSPQ's exact
feature set, all-features), lint, `cargo hack --each-feature`, `mls_build_async`,
a `thumbv6m-none-eabi` build, security audit, wasm, and fuzz. The last two are
gated off the push trigger — push only fires on `germ-integration`, whose content
has already been through a PR — but stay reachable via `workflow_dispatch`.

**CI runs automatically only on `germ-integration`.** For `pull_request` events
GitHub resolves workflow files from the *head* branch, so a feature-branch PR
(#4, #6, #7) gets no checks — `germ-ci.yml` is not on those branches. Making it an
ancestor of every feature branch would fix that and cost the property that makes
them worth having: being based on plain `main` and submittable upstream as-is.
Composition is validated on `germ-integration` instead, and any branch or frozen
pin can be checked on demand:

```bash
gh workflow run germ-ci.yml --repo germ-network/mls-rs -f ref=<branch-or-sha>
```

Three things that are easy to get wrong here:

- **`rustflags: ''` on every `setup-rust-toolchain` step.** The action defaults
  `RUSTFLAGS` to `-D warnings`, which promotes pre-existing upstream warnings
  (unused imports in `mls-rs` and `mls-rs-identity-x509`) into build errors and
  fails jobs for reasons unrelated to the change under test. Upstream's own wasm
  and fuzz workflows clear it the same way. Strictness belongs where the lint job
  puts it: `-D warnings` passed to clippy explicitly.
- **macOS must be `macos-26` or newer.** `mls-rs-crypto-cryptokit`'s
  `cryptokit-bridge` declares `swift-tools-version: 6.2`, so anything older
  (macos-14 ships Xcode 15.4 / Swift 5.10) fails in the build script before
  compiling. The job reports `swift --version` up front so a regression is
  visible in the log.
- **Release pins cannot run CI on a push.** A workflow file has to be in the ref
  being pushed, and adding one moves the pin. `workflow_dispatch` takes a `ref`
  input instead, so the suite can be pointed at a frozen pin on demand.

>>>>>>> Stashed changes
## Persisted-state fixtures

Cargo features in this crate can change the serialized group-state format: fields on
`EpochSecrets` are `#[cfg]`-gated, and the MLS codec is positional with no field tags
and no working version gate (`Snapshot.version` is written but never read). A feature
that adds a field silently changes the layout of both the `Snapshot` and `PriorEpoch`
blobs, and a mismatch surfaces as an opaque codec error — or, because there is no
trailing-data check, as a silent misparse.

Upstream guards this with `legacy_interop` in `mls-rs/src/group/snapshot.rs`, which is
gated off when `safe_extensions` is enabled — so that build needs its own coverage.
`mls-rs/test_data/shipped_safe_extensions_*.mls` are real blobs captured from the
release pin, asserting that state written by the shipped build still loads here.

**Capture a fresh pair for each release pin.** They are the only mechanical check that
an upstream resync, or a new feature, has not disturbed the stored format.
