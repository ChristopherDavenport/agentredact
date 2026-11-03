# agentredact

Redaction and publishing for agent sessions, built on
[agentsession](https://github.com/ChristopherDavenport/agentsession).
agentredact writes a redacted copy of each session in a store and
decides which of those copies may leave it.

A redacted session, in agentsession's format 0.19, is a session of its
own made from an original:

- every entry the redaction writes carries `redacted`, the positions
  in the original of the entries it was made from (`[n]`, `[[from, to]]`
  for a block left out, `[]` for an added entry);
- its header carries `redacted: true` and
  `redacted_from: {session, profile}`, where `session` is the
  original's pseudonym under a key only the holder of the originals
  has, and its ID is derived from that and the profile, so one original
  under one profile and key has one redacted session, and nobody holding
  the original's native ID can tell which published session came from
  it;
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
	Name: "default@2",
	Strings: []agentredact.StringRedactor{
		agentredact.Secrets(apiKey),
		agentredact.HomePaths(home),
		agentredact.DefaultPatterns(),
	},
	Entries: []agentredact.EntryRedactor{
		agentredact.Environment(),
		agentredact.Images(agentredact.DefaultImagePlaceholder),
	},
	Identity: agentredact.ClaudeCodeIdentity(), // the user's values a Claude Code import names
}
key, err := agentredact.ReadKeyFile("/path/beside/the/store/redaction.key")
res, err := agentredact.Redact(p, key, original, nil) // or the earlier redaction, to grow it
```

`Result.Blobs` holds the blobs the redacted session needs beyond the
original's, such as the placeholder that replaced a sidecar image,
keyed by hash, each with its media type; store them beside it with
that type (`PutTypedBlob`).

### The key

Since format 0.19 a redaction names sessions under a key (RFC 0001,
The redacted session): `redacted_from.session` is the original's
pseudonym, an HMAC of its ID under the key, and the redacted session's
ID and every reference to another session derive from pseudonyms. A
native session ID, which the harness's own logs and its vendor hold,
then leads to no published redaction.

- **One key per store of originals**, at least 32 random bytes.
  `GenerateKey` makes one and `WriteKeyFile` writes it to a new file,
  mode 0600, refusing a path that exists; `ReadKeyFile` reads it back
  and refuses a file its group or others may read. Keep the file beside
  the store of originals, out of any repository, dataset or log, and
  back it up with the originals.
- **No default.** `Redact` and `RedactStore` refuse the zero `Key`
  (`agentsession.ErrRedactionKey`). A `Key` never prints or marshals its
  bytes, so it does not reach a log by accident; it is in no profile,
  report or redacted session.
- **Losing the key loses the redactions' continuity.** A redaction is
  found again, and resumed, only by deriving its ID under the same key:
  under another key every original gets a new redacted session, written
  beside the old ones, which can no longer grow. `OriginalOf` finds the
  original a redacted session was made from, for the holder of the key.

A profile names one set of rules; change the rules and bump the
version, or two redactions end up mixed in one session.

### Home directories, session IDs and identity values

- `HomePaths(home)` shortens a path under home to `~`, home bounded on
  both sides (a separator or the end after it, a character that is no
  part of a path segment before it, an escaped `\n`, `\t`, `\r`, `\b`
  or `\f` included), and finds home in its dash-encoded form too, the
  directory name Claude Code gives a project (`-home-example-proj`,
  inside `/tmp/claude-<uid>/` scratchpads as well) and an agentsession
  jsonl store's key (`home-example-proj` after a separator):
  `-home-example-proj` becomes `-~-proj`. A harness's encoding writes no
  `~`, so `-~` is never a real directory's name.
- Every redaction rewrites, as text, each session ID the original
  names a session by (its own `id`, `parent_session`, a `parents`
  element's, a link's, a copied item's) to the ID of that session's
  redaction, before the profile's own rules, as RFC 0001 0.19 requires:
  a scratchpad path or a tool output quoting the session ID then names
  its redaction. The IDs come from the original alone. Other spellings
  of a session ID than the ID as written are not looked for.
- `Profile.Identity` lists the members of the originals that name the
  user (an email, an organization's ID, a login name, a home
  directory), by entry type, namespace and JSON Pointer;
  `ClaudeCodeIdentity` is agentimport v0.0.1's Claude Code list. The
  values are read from each original, never written into the profile,
  and every spelling of each is replaced with `[REDACTED identity#<n>]`
  after the profile's string redactors: as written in any ASCII case, a
  path's dash-encoded directory name, the Go module cache's escaping
  (`!example!login` for `ExampleLogin`) and its URL encodings. A value
  is replaced from the entry that names it on, since what a redaction
  writes at a position rests on the entries up to it; the redaction is
  then searched for every value the whole original names, and each
  spelling still held, in a string or a member name, is an
  `identity-value` finding with no value, which blocks `Publishable`.
  Values shorter than three bytes are not harvested.

### Placeholders

In a redaction, `Secrets` and `Patterns` number what they replace:
`[REDACTED#<n>]` for a secret value and `[REDACTED <name>#<n>]` for a
pattern match, n counting from 1 the distinct values of that kind in
the redacted session (`Placeholders`). One value is one placeholder
throughout a session and two values are two, so a reader can tell that
two redacted values were equal, and two instruction layer ids holding
different secrets stay distinct, as RFC 0001 0.18 requires
(`agentsession.ErrLayersMerged`). The numbers follow the order the
values are met, header first and then the original's entries in file
order, so a resumed redaction numbers as a fresh one does, and a fork
redacted as a fork of its origin's redaction continues its origin's
numbering at the base. Outside a redaction (a nil `*Placeholders`)
they write `[REDACTED]` and `[REDACTED <name>]`. A `StringRedactor` is
`func(s string, ph *Placeholders) string`; `Plain` adapts a function
that ignores `ph`. A rules file's replacements are written as given and
not numbered.
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

## Redacting a store

```go
rep, err := agentredact.RedactStore(ctx, store, p, key, agentredact.StoreOptions{})
```

`RedactStore` keeps one redaction per original under the profile, in
the same store: it creates the missing ones and appends to the others
what their originals appended since, and a rerun with nothing new writes
nothing. Sessions that are themselves redacted are skipped. A session
goes after those its entries hash over, its fork's origin and any
session a `parents` element names; `StoreOptions.Select` narrows the
originals, and takes their dependencies with them.

- **What is written never depends on arrival order.** A reference to a
  session, `parent_session`, a link's `session` and a `parents`
  element's session, always names the redaction the profile derives for
  it, held or not, so no original session ID is kept. The entry a
  `parents` element names in another session is re-pointed through that
  session's redaction (`WithAlongside` on `Redact`, through
  `Result.Counterparts`); a session naming an entry of one the store
  does not hold waits (`SessionReport.WaitingOn`), with nothing written,
  until it arrives, and its dependents wait with it.
- **Forks.** A fork is redacted as a fork of its origin's redaction
  (`WithOrigin`): its base is the entry standing for the original's
  base, its prefix the origin redaction's own entries, and its own
  entries count positions in the fork's file order, prefix included, as
  RFC 0001 has it. A fork whose origin the store does not hold, or whose
  base the origin's snapshot does not hold yet, waits. Only a fork whose
  base the origin's redaction left out (`ErrBaseLeftOut`) is redacted
  without a base.
- **Writing.** A new redaction is imported whole (`agentsession.Importer`,
  as the store's record); new entries are appended with `Store.Append`,
  and where the store has `SetHead` the head is set to where an
  import would put it. Blobs a redaction made go first, each with its
  media type (`agentsession.TypedBlobWriter`): every store of
  agentsession v0.0.36 takes them, a store that does not is given no
  redaction naming one (`ErrNoBlobWriter`), and the redaction is given
  the types of the blobs it names where the store holds types per
  session. An
  entry whose ancestors were all left out is appended at the universal
  root. The redaction is let go (`Release`) however a write ends.
- **The report** gives, per original, the entries and blobs written,
  whether it was up to date or waits, the findings of the whole
  redaction on every run, each with a stable `Kind`, and how many native
  entries it holds. `Publishable` is false while it holds a native
  entry, waits, or holds a finding of a kind `StoreOptions.AcceptFindings`
  does not accept; it holds for the snapshot the run read. A session
  that fails stops those that depend on it (`ErrDependency`) and no
  other. No error names an entry by a hash.

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

A member name that is data, such as a file path keying a map in a
custom entry's data, an outcome's details or a member the format does
not define, reaches the string redactors through agentsession's
Rewriter and is renamed (RFC 0001 0.14). Two names a redaction makes
one are refused (`agentsession.ErrKeyCollision`), with a message naming
neither. The names of the header's own members are the format's and
are kept as written, their values rewritten; one the string redactors
would change is reported (`FindingHeaderName`).

### Kept as written

Some members are kept as the original wrote them, by design, and a
profile's redactors never see them:

- an entry's `legacy_id`, which in a migrated file is its pre-0.5 ID,
  and `parents` beyond its entry and session references;
- `call_id`s, a run's pending call IDs and the header's `spawned_by`,
  which pair calls with their outputs and derive subsession IDs;
- the header's `created_at`, `payload`, `records` and `media`;
- nothing of the entry a `parents` element or a copied item names in
  another session whose counterparts are not given to `Redact`: the
  reference to the entry is removed, as RFC 0001 0.19 has it, and
  reported (`FindingForeignReference`). The store pass waits for such a
  session instead;
- an env entry's file hashes, when the profile has no `Environment`;
- every image, when the profile has no `Images`: each one kept whole,
  inline, sidecar under an `image_url`, or a sidecar blob the store
  types `image/*` under any item (`WithMediaTypes`, which the store
  pass sets), is reported as an `image` finding, since nothing reads
  the text in a screenshot; a publisher that accepts screenshots
  accepts the kind. With `Images` a sidecar image is replaced, and
  other sidecar media, such as a file, is kept and reported;
- an instruction part named by the hash of a text no entry the
  redaction wrote before it holds is written as `UnmetPartText` under
  its id, never under the original's hash, which can confirm a guessed
  text; a part keeping parts the redaction does not hold is refused
  (`ErrUnmetKeep`);
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
`KeepLeafPath` and `DropBranches`, `Redact`, which applies a profile
to one session, and `RedactStore`, which keeps a store's redactions
current, are here. The design is [docs/plans/agentredact.md](docs/plans/agentredact.md);
the work is tracked in issues
[#2](https://github.com/ChristopherDavenport/agentredact/issues/2) (redactors),
[#3](https://github.com/ChristopherDavenport/agentredact/issues/3) (the store pass),
[#4](https://github.com/ChristopherDavenport/agentredact/issues/4) (scan),
[#5](https://github.com/ChristopherDavenport/agentredact/issues/5) (review) and
[#6](https://github.com/ChristopherDavenport/agentredact/issues/6) (manifest and publish).
There is no command yet.

`agentredact/secrets` is a module of its own, standard library only:
the streaming secret redactor, every JSON spelling of each value
replaced with `[REDACTED NAME]`, for a program between a process that
holds secrets and an agent, such as a workspace's MCP server whose
output must not quote its token. `Secrets` above is built on it.

```go
r := secrets.New(map[string]string{"GITHUB_TOKEN": token})
out := r.Reader(server.Stdout(), func(name string, n int) { log.Printf("redacted %s ×%d", name, n) })
```

## Development

Go 1.25 or later.

```sh
make build
make check        # gofmt, tidy, vet, deps, replaces, staticcheck, govulncheck, race tests, guard tests
make extracted    # each module built against the versions it requires, as a consumer gets it
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## License

MIT; see [LICENSE](LICENSE).
