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

## Redacting a session

```go
p := agentredact.Profile{
	Name: "default@1",
	Strings: []agentredact.StringRedactor{
		agentredact.Secrets(apiKey),
		agentredact.HomePaths(home),
		agentredact.DefaultPatterns(),
	},
	Entries: []agentredact.EntryRedactor{
		agentredact.Environment(),
		agentredact.Images(agentredact.DefaultImagePlaceholder),
	},
}
res, err := agentredact.Redact(p, original, nil) // or the earlier redaction, to grow it
```

A profile names one set of rules; change the rules and bump the
version, or two redactions end up mixed in one session.
`ParseRules` reads a rules file in git-filter-repo's `--replace-text`
form (`literal==>replacement`, `regex:pattern==>replacement`,
`glob:pattern==>replacement`, a bare line for `***REMOVED***`).

### What is not found

The string redactors match text as it is written. They do not find:

- a secret encoded in base64, such as one inside a basic-auth header,
  a JWT payload or a base64 blob a tool printed;
- a secret in URL encoding (`%2F`, `+` for a space) or any other
  escaping the session holds as text;
- anything in an image's bytes: inline media reaches a redactor as its
  undecoded data URL, `Images` replaces an image whole or keeps it, and
  nothing reads the text in a screenshot;
- a secret split across two strings, or across an instruction part
  boundary.

Of a string that is wholly a base64 data URL, as inline media is held,
the redactors are given the media type and parameters, which can hold a
file name, and the payload is kept as it is: nothing in it could be
found as written, and a pattern that matched it by chance would only
corrupt the media. A token written as such a payload, base64 characters
alone, is kept too. A data URL that is not base64, or a line that
merely starts `data:`, is redacted like any other string.

### Member names

agentsession's Rewriter gives a redactor no member name but an env
entry's file paths, and a harness often keys a map by a file path. So
`Redact` renames, through the string redactors, every member name in
the header's members the format does not define, at any depth, and
refuses with `ErrKeyNotRedacted` an entry holding a member name the
redactors would change, in a custom entry's data, an outcome's details,
a member the format does not define or an extension entry: a profile
that would leave a matched name in place does not produce a redaction.
The check cannot tell a name the format defines from one a writer chose,
so a rule matching one, such as a literal rule for `content`, refuses
every entry holding it. When agentsession renames such names itself,
renaming replaces the refusal.

### Kept as written

Some members are kept as the original wrote them, by design, and a
profile's redactors never see them:

- an entry's `legacy_id`, which in a migrated file is its pre-0.5 ID,
  and `parents` beyond its entry and session references;
- `call_id`s, a run's pending call IDs and the header's `spawned_by`,
  which pair calls with their outputs and derive subsession IDs;
- the header's `created_at`, `payload`, `records`, `media` and
  `parent_session`;
- references into other sessions, `parent_session`, a `parents` element
  or a link naming one, which hold that session's original IDs until
  the store pass re-points them; each is reported in `Result.Findings`;
- an env entry's file hashes, when the profile has no `Environment`;
- a sidecar reference, when the profile has no `Images`; with it, each
  is reported, since replacing one needs a blob write, which comes with
  the store pass;
- an instruction part named by the hash of a text no earlier entry
  holds keeps the original's hash, which can confirm a guessed text;
  each is reported, by its id;
- inline media that is not an image, such as an input_file's PDF, and
  an image data URL inside a longer string, such as tool output or
  markdown: `Images` replaces whole-string images only; each is
  reported.

`Result.Findings` are local: they name an entry by its position in the
original and hold no value and no original hash, and they are never
published with the redacted session. The scan and the review are the
backstop for what the redactors miss, not a guarantee.

## Status

Profiles, the string redactors (`Secrets`, `HomePaths`, `Patterns`,
`ParseRules`), the entry redactors `Environment` and `Images` (inline
images), and `Redact`, which applies a profile to one session, are
here. The design is [docs/plans/agentredact.md](docs/plans/agentredact.md);
the work is tracked in issues
[#2](https://github.com/ChristopherDavenport/agentredact/issues/2) (redactors),
[#3](https://github.com/ChristopherDavenport/agentredact/issues/3) (the store pass),
[#4](https://github.com/ChristopherDavenport/agentredact/issues/4) (scan),
[#5](https://github.com/ChristopherDavenport/agentredact/issues/5) (review) and
[#6](https://github.com/ChristopherDavenport/agentredact/issues/6) (manifest and publish).
There is no command yet.

## Development

Go 1.25 or later.

```sh
make build
make check        # gofmt, tidy, vet, deps, staticcheck, govulncheck, race tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## License

MIT; see [LICENSE](LICENSE).
