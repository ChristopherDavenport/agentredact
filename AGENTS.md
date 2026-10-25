# agentredact

Redaction and publishing for agent sessions. agentredact writes
redacted sessions through the agentsession API and decides which of
them leave a store: the redactors, the pass that keeps a store's
redactions current, the TruffleHog scan, the LLM review, the manifest
and the publish. The design is `docs/plans/agentredact.md`; read it
before writing code. Issues #2–#6 track the parts.

## Module

- Module path: `github.com/ChristopherDavenport/agentredact`.
- Go 1.25 is the floor.
- Packages: `agentredact` at the root (the redactors, profiles and the
  store-wide pass); `scan`, `review` and `publish` as their issues land;
  `cmd/agentredact`, the command.
- A nested module, `github.com/ChristopherDavenport/agentredact/secrets`
  (directory `secrets`): the streaming secret redactor, every JSON
  spelling of a value, a line-bounded reader. It imports the standard
  library alone, enforced by `make deps` and `TestImportBoundary`, so
  the programs between a secret-holding process and an agent
  (agentworkspace's offered servers, dax's box host) import it without
  the rest of this module. The root's `Secrets` is built on it, and the
  root requires it at exactly the version the repository is released
  at, through `replace ... => ./secrets` (`make replaces` checks it).
- The root imports the standard library, its `secrets` module,
  `agentsession`, `openresponses` and `agentpolicy` alone. At any depth
  the build may reach only those and the two modules `agentpolicy`
  brings in, `agentturn` and `agenttool`: no third-party module, and not
  agentsession's nested modules (`agentsession/sqlite`,
  `agentsession/otel`). Every dependency is code that sees unredacted
  sessions. TruffleHog runs as the `trufflehog` binary through
  `os/exec`, not as a library. A dependency outside the rule, such as
  an upload client for a dataset host or the sqlite store, needs a
  decision in the plan first, and a change to `scripts/check-deps.sh`
  in the same commit. `make deps` enforces the rule, by module.

## Everyday commands

```sh
make check      # fmt, tidiness, vet, deps, staticcheck, govulncheck, race tests
make release VERSION=vX.Y.Z   # the whole release; see below
```

In this workspace run them as
`GOWORK=off GOFLAGS=-mod=readonly make check`. The CI workflow runs one
target per step rather than `make check`, so a target added to `check`
needs a step in `.github/workflows/ci.yml` or it never runs in CI.

## Rules every change keeps

- **The format and the store rules are agentsession's**, in its RFC
  0001 (Redaction), RFC 0002 (Redacted sessions) and
  `docs/plans/redaction.md`. Never re-derive them here: reach strings
  through `Rewriter`, references through `RemapRefs` and
  `RemapHeaderRefs`, positions through `SetRedacted`, request hashes
  through `Session.SetRequestHash`, the derived ID through
  `RedactedSessionID`. Where agentredact needs format knowledge no
  helper gives, that is an agentsession issue, not a copy here.
- **Redactors are deterministic.** Output depends on input and rules
  alone: no clock, no randomness, no map order. A fork and its origin
  must give their shared prefix the same bytes, and a rerun must write
  what it wrote before, or the store pass forks its own output.
- **Every entry a redactor writes carries `redacted`**, its positions in
  the original's file order (`[n]`, `[[from, to]]`, or `[]` for an
  added entry), set with `SetRedacted`, and no other entry does.
- **Every redacted response gets `Session.SetRequestHash`** just before
  it is committed, in the redacted session; a response made from one
  whose `request_hash` did not verify in the original has it cleared
  first. A redacted session hashes independently and verifies like any
  other; tests assert it.
- **A profile names one set of rules.** Changing a redactor's output
  under an existing profile mixes two redactions in one session; bump
  the profile.
- **Fixtures and secrets are synthetic.** Never copy a real session
  from any store or agent directory into the repository, not even a
  redacted one, and never a real key, token, username or home path.
  Write a fixture with the shape, and make secret-shaped values
  obviously fake. agentimport's audit once found a real session ID in
  a fixture; a redaction repository holding a real secret in its tests
  defeats itself.

## Releases

A pushed tag is permanent: `proxy.golang.org` and `sum.golang.org`
keep the version forever, and deleting the tag only makes it
unverifiable. A bad version is superseded and `retract`ed, never
deleted.

This repository releases two modules at one version from one commit,
tagged `vX.Y.Z` and `secrets/vX.Y.Z`. With the changelog's
*Unreleased* section written:

```sh
make release VERSION=v0.1.0
```

That points every first-party require at the version
(`scripts/versions.sh`), dates the changelog, tidies, runs `make
check`, commits, runs `scripts/release-guard.sh` on the root tag (clean
tree, tag new locally and on origin, version above the published floor,
read from origin and failing closed, the root requiring secrets at that
version), writes it as an annotated tag whose message is the changelog
section (`scripts/release-notes.sh`), guards and writes `secrets/vX.Y.Z`
the same way (the root tag of that version naming this commit), and
pushes the branch and both tags with `git push origin --atomic`.
`make extracted`, in CI, builds each module against the versions it
requires, the way a consumer gets it; a module whose first-party
dependency has never been released is skipped until it is. The release
workflow publishes each tag's message as its GitHub release notes.
Nothing is public until the push: if the guard refuses,
`git reset --hard HEAD~1` and `git tag -d` the tags written. To check a
tag alone, `make release-guard TAG=v0.1.0` (or `TAG=secrets/v0.1.0`).
The user runs releases; prepare the changelog and hand over the
command.

## Siblings

Peer repositories, each independently versioned and required by
published tag:

- `../agentsession`: the format, the stores and the redaction helpers.
  Its RFCs are normative.
- `../agentpolicy`: `guard.DefaultSecrets` and `guard.Redact`, the
  default secret patterns and how a match is written.
- `../open-responses`: the payload items, and the provider client the
  review uses.
- `../agentimport`: the sibling whose house files this repository
  mirrors.

## Conventions

Mirror `../agentimport`: a `Makefile` with `build`, `deps`, `test`,
`vet`, `fmt`, `tidy`, `tidy-check`, `lint`, `vuln`, `check`,
`release-guard` and `release` targets, the same CI workflow shape, a
`CHANGELOG.md` in Keep a Changelog form, and annotated `v*` tags whose
message becomes the release notes. `make check` must pass before any
commit.

Tests are table-driven and offline; the scan's tests do not need the
TruffleHog binary unless they say so and skip without it. Golden
outputs live under each package's `testdata/` and are regenerated with
`go test ./... -update`; review the diff.
