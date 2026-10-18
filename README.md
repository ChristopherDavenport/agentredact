# agentredact

Redaction and publishing for agent sessions, built on
[agentsession](https://github.com/ChristopherDavenport/agentsession).
agentredact writes a redacted copy of each session in a store and
decides which of those copies may leave it.

A redacted session, in agentsession's format 0.13, is a session of its
own made from an original:

- every entry the redaction writes carries `redacted`, the positions
  in the original of the entries it was made from (`[n]`, `[[from, to]]`
  for a block left out, `[]` for an added entry);
- its header carries `redacted: true` and
  `redacted_from: {session, profile}`, and its ID is derived from the
  original and the profile, so one original under one profile has one
  redacted session;
- its hashes, request hashes included, are its own, so it verifies,
  grows as the original grows, and can be resumed like any session;
- it is published by pushing it to a store set to hold only redacted
  entries, which refuses an original sent there by mistake.

agentsession owns the format, the store rules and the helpers;
agentredact holds the policy and the pipeline: deterministic redactors
named by a profile, a pass that keeps a whole store's redactions
current, a TruffleHog scan, an LLM review, a manifest, and a publish to
a redacted-only store or a dataset export. Secrets encoded in base64,
URL encoding or image bytes are not found by the redactors.

## Status

A scaffold. The design is [docs/plans/agentredact.md](docs/plans/agentredact.md);
the work is tracked in issues
[#2](https://github.com/ChristopherDavenport/agentredact/issues/2) (redactors),
[#3](https://github.com/ChristopherDavenport/agentredact/issues/3) (the store pass),
[#4](https://github.com/ChristopherDavenport/agentredact/issues/4) (scan),
[#5](https://github.com/ChristopherDavenport/agentredact/issues/5) (review) and
[#6](https://github.com/ChristopherDavenport/agentredact/issues/6) (manifest and publish).
There is no API or command yet.

## Development

Go 1.25 or later.

```sh
make build
make check        # gofmt, tidy, vet, deps, staticcheck, govulncheck, race tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## License

MIT; see [LICENSE](LICENSE).
