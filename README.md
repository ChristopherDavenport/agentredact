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

`Result.Blobs` holds the blobs the redacted session needs beyond the
original's, such as the placeholder that replaced a sidecar image,
keyed by hash; store them beside it.

A profile names one set of rules; change the rules and bump the
version, or two redactions end up mixed in one session.
`ParseRules` reads a rules file in git-filter-repo's `--replace-text`
form (`literal==>replacement`, `regex:pattern==>replacement`,
`glob:pattern==>replacement`, a bare line for `***REMOVED***`).

### Leaving entries out

Structural redactors go in `Entries` beside the others; session
redactors in `Sessions`:

```go
// Fold reasoning items into block placeholders, deciding from the entry alone.
p.Entries = append(p.Entries, agentredact.BlockOut(func(c *agentredact.EntryContext, e agentsession.Entry) bool {
	it, ok := c.Entry().(*agentsession.ItemEntry)
	return ok && it.Item.ItemType() == openresponses.ItemTypeReasoning
}))
p.Sessions = []agentredact.SessionRedactor{agentredact.KeepLeafPath()}
```

- `LeaveOut(match)` writes nothing for a matching entry: the entries
  under it hang from the nearest entry kept above it.
- `BlockOut(match)` folds matching entries into block placeholders: a
  run of them along a path becomes one custom entry
  (`"ns":"agentredact"`, `"data":{"redacted":"block","entries":n}`)
  marked with their positions, `[[from, to]]` where they are
  consecutive. A placeholder adds nothing to the model's context, so a
  redacted session's requests are the original's less what was left
  out. A run is written once a kept entry follows it on its path; a
  run at the end of a path is withheld until one does, so a block is
  one placeholder however the original grows.
- `KeepLeafPath()` keeps only the path to the session's leaf (its head
  in a store); `DropBranches(drop)` leaves out each entry `drop`
  selects and everything under it. Session redactors run first, and
  what they leave out reaches no other redactor and needs no
  placeholder.
- Your own: a `StructureRedactor` returns the entries to write in an
  entry's place, none, or `Block()`; a `SessionRedactor` returns which
  entries to leave out, whole branches only.

What is left out never breaks the format. A call leaves with its
output, dispatches, decisions and links; a queued input with the items
drained from it, since it holds the input verbatim; a response with its
items, when every one of them is left out; a run's end with its start.
Leaving out a member of such a group while its head is kept, a config
entry, a compaction, or what a compaction's `first_kept` needs, is
refused with an error naming the position (`ErrSplitsCall`,
`ErrSplitsQueued`, `ErrSplitsResponse`, `ErrSplitsRun`,
`ErrLeavesOutConfig`, `ErrLeavesOutCompaction`, `ErrFirstKept`,
`ErrNoPlace`, `ErrGroupHead`, `ErrBreaksRecords`). Session redactors are
held to the same group rules before anything is written.
`KeepLeafPath` widens its own choice instead: it keeps the path's own
records that sit off it, where they sit, such as the dispatch of a call
on the path made on a branch a retry rewound past, or a run's end, and
nothing else of the abandoned branch. A run's end left out with its
parent, as after a rewind inside the run under any session redactor,
goes with it, and the run reads as open on the kept path, as it does in
the original. Any other record whose parent belongs to the abandoned
conversation cannot be kept in place, and the redaction is refused.

Where leaving out changes a kept entry, `Redact` carries it through. A
reference names the entry's block placeholder; with none, a label or
outcome naming it is left out too, and a `judged_by` target, a
`parents` element, a `queued_from` or an omit item is removed. A run
end's pending list and reason follow its redacted segment, a pinned
item leaves with its entry, and an omit list loses what was left out.

Some kept entries restate what was left out and cannot lose it without
changing requests. `Redact` keeps them and reports each in
`Result.Findings`, with no value:

- a branch summary of a branch left out, which `KeepLeafPath` and
  `DropBranches` leave on the kept path;
- a compaction whose summary, or a provider's encrypted compaction
  item, covers entries left out before its `first_kept`;
- an entry converging a branch left out: what it merged is in its own
  payload;
- an item's `source` or a run start's `trigger` copying the trigger of
  a queued input left out.

Resuming stays equal to a fresh redaction, byte for byte, as long as
each redactor's output rests on the entry and its path, which a fork
and its origin then share too. A resume rebuilds every entry it already
holds and refuses, with `ErrResumeDiverged` and before writing, one
that differs: a profile name reused for changed rules, or
`KeepLeafPath` after the leaf moved to another branch. Redact afresh.

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
- a sidecar reference, when the profile has no `Images`; with it, a
  sidecar image is replaced, and other sidecar media, such as a file,
  is kept and reported;
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
`ParseRules`), the entry redactors `Environment` and `Images`, the
structural redactors `LeaveOut` and `BlockOut`, the session redactors
`KeepLeafPath` and `DropBranches`, and `Redact`, which applies a
profile to one session, are here. The design is [docs/plans/agentredact.md](docs/plans/agentredact.md);
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
