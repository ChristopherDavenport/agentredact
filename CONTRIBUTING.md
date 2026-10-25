# Contributing

Issues and pull requests are welcome.

## Before you start

This module writes redacted sessions in the Agent Session Format and
decides which of them leave a store. It adds nothing to the session
format and re-derives none of its rules: what a valid redacted session
is, and what a store does with one, is `agentsession`'s, and where this
module needs something the format or its helpers lack, the question
goes there. `docs/plans/agentredact.md` is the design; read it first.

For anything larger than a bug fix, or a new redactor or pipeline
stage, open an issue first so the shape of the change can be discussed
before you spend time on it.

## Development

Go 1.25 or later is required. The full local check is:

```sh
make check        # gofmt, tidy, vet, deps, staticcheck, govulncheck, race tests
```

The module depends on `agentsession`, `openresponses`, `agentpolicy`
and the standard library, and reaches no third-party module; `make
deps` fails if anything else creeps in. TruffleHog is run as an
external binary, not linked.

Redactors are deterministic: the same input and rules give the same
bytes, so a fork and its origin share a redacted prefix and a rerun
writes nothing new. Every entry a redactor writes carries `redacted`,
and every redacted response gets `Session.SetRequestHash`.

Fixtures and secrets are synthetic: write the shape you need, never a
copy of a real session, and never a real key, token, username or home
path, not even one you believe is revoked. Golden outputs are
regenerated with `go test ./... -update`; review the diff.

## Pull requests

- Keep each pull request focused on one change.
- Add or update table-driven, offline tests.
- A redactor whose output changes needs a new profile version, said in
  the changelog.
- Run `make check` before pushing.
- Note user-visible changes under *Unreleased* in `CHANGELOG.md`.

## Releases

This repository releases two modules at one version from one commit,
the root and `secrets`, tagged `vX.Y.Z` and `secrets/vX.Y.Z`. The root
requires secrets at exactly that version through an in-tree replace,
and `secrets` imports the standard library alone. With the changelog's
*Unreleased* section written:

```sh
make release VERSION=v0.1.0
```
