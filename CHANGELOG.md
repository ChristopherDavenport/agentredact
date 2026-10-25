# Changelog

All user-visible changes to this library. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/); before v1.0.0 minor
versions may break the API.

## Unreleased

- Added: the repository scaffold. `docs/plans/agentredact.md` is the
  design, written against agentsession v0.0.28 (format 0.13): the
  redactors (#2), the store-wide pass (#3), the scan (#4), the review
  (#5), and the manifest and publish (#6). The `agentredact` package
  holds its documentation alone; no API yet. `make deps` holds the
  module to the standard library, agentsession, openresponses and
  agentpolicy.
- Added: `Profile`, a named, versioned redactor set, and
  `ValidateProfileName` (`<name>@<version>`, version an integer from 1).
- Added: the string redactors `Secrets` (exact values, longest first);
  `HomePaths` (paths under home become `~`-relative, home bounded on
  both sides, any of `/`, `\`, `\\` and `\/` between segments, a drive
  letter in either case); `Patterns` and `DefaultPatterns`, each match
  written `[REDACTED <name>]`, over `DefaultSecretPatterns`, a copy of
  agentpolicy v0.0.17's `guard.DefaultSecrets` that a test pins; and
  `ParseRules`, git-filter-repo's `--replace-text` format, `glob:`
  included, refusing what filter-repo would silently misread, with
  errors naming the line.
- Added: a profile's joined string function (`Profile.StringFunc`,
  `Chain`) keeps a base64 data URL's payload as it is and gives its
  media type and parameters to the redactors, so a pattern matching an
  inline image's payload by chance does not corrupt it.
- Added: the `EntryRedactor` and `HeaderRedactor` interfaces;
  `Environment`, which blanks an env entry's cwd, vcs, files, tools and
  harness members, keeps workspace substitutions as placeholders
  numbered along the entry's path, and blanks the header's cwd; and
  `Images`, which replaces whole-string inline images with a placeholder
  data URL and reports sidecar ones.
- Added: `Redact`, which applies a profile to one session in memory: a
  new header with `redacted`, `redacted_from` and the derived ID, its
  unknown members' names renamed; one redacted entry per original entry
  marked `[n]`, references re-pointed, request hashes recomputed
  (cleared where the original's did not verify); an entry holding a
  member name the redactors would change refused with
  `ErrKeyNotRedacted`; and resuming an existing redaction by appending
  only the entries past its highest position. A fork is written without
  a base; writing a fork of a redaction is the store pass's (#3), which
  adds that mode.
- Added: `Finding`, local reports of what `Redact` kept: sidecar
  references, inline non-image media, image data URLs inside longer
  strings, references into other sessions, extension entries, and
  instruction parts that keep the original's hash.
- Changed: `make deps` checks what the tests import too.
- Added: structural redactors. `StructureRedactor`, an `EntryRedactor`
  that `Redact` finds by type assertion in `Profile.Entries`, returns
  the entries to write in an entry's place (`Made`, `[]` for one
  added), none to leave it out, or `Block()` to fold it into a block
  placeholder; `LeaveOut` and `BlockOut` are the built-ins, and
  `StructureRedactorFunc` the adapter. A block placeholder is a custom
  entry under `PlaceholderNS` (`agentredact`) marked with the positions
  it stands for, `[[from, to]]` where consecutive, written once a kept
  entry follows its run on the path and withheld while the run is open.
- Added: session redactors, in the new `Profile.Sessions`:
  `SessionRedactor`, `KeepLeafPath` and `DropBranches`. They leave out
  whole branches before any entry is redacted, held to the group rules
  before anything is written. `KeepLeafPath` keeps the path's own
  records that sit off it, such as a call's dispatch on a branch a retry
  rewound past, where they sit, and refuses one it cannot keep in place.
  A run's end left out with its parent leaves the run open on the kept
  path, under any session redactor.
- Added: what is left out stays valid. A call leaves with its output,
  dispatches, decisions and links, a queued input with the items drained
  from it, a response with all its items, a run's end with its start. A
  reference to an entry left out names its block placeholder; with
  none, a label or outcome naming it is left out too, and a `judged_by`
  target, a `parents` element, a `queued_from` or an omit item is
  removed. A run end's pending list and reason, a compaction's pinned
  items (failing closed) and first_kept, and omit lists are carried
  through; a resumed run whose segment is left out whole gets no
  placeholder. What would break a rule is refused by name:
  `ErrSplitsCall`, `ErrSplitsQueued`, `ErrSplitsResponse`,
  `ErrSplitsRun`, `ErrLeavesOutConfig`, `ErrLeavesOutCompaction`,
  `ErrGroupHead`, `ErrFirstKept`, `ErrNoPlace`, `ErrBreaksRecords`,
  `ErrSessionRedactor`.
- Added: findings, with no value, for what restates entries left out:
  a branch summary of a branch left out, a compaction over entries left
  out before `first_kept`, an entry converging one left out, a pinned
  item matching no entry, and a trigger copied from a queued input left
  out.
- Changed: `Redact` resumes by replaying the positions an existing
  redaction covers, ranges included, rebuilding each entry a fresh
  redaction writes there and requiring an entry of the same ID, so a
  resume equals a fresh redaction byte for byte with entries left out
  and runs withheld. One that differs, as with a profile reused for
  changed rules or after a `KeepLeafPath` leaf moved to another branch,
  is refused with `ErrResumeDiverged` before anything is written.
- Changed: `Images` replaces sidecar images too, with a sidecar
  reference to the placeholder's bytes, and `Redact` returns the blobs
  the redacted session needs in `Result.Blobs`, keyed by hash, through
  the new `EntryContext.AddBlob`. Sidecar media that is not an image is
  kept and reported.
- Added: `RedactStore`, the store-wide pass (#3). It keeps one
  redaction per original under a profile in the same store, creating
  the missing ones through the store's `agentsession.Importer` and
  appending what originals added since with `Store.Append`; a rerun
  with nothing new writes nothing. Redacted sessions are skipped. Each
  original is redacted after the sessions it hashes over (its fork's
  origin, those its `parents` name), and `StoreOptions.Select` narrows
  the originals, taking their dependencies along. Blobs a redaction
  made are written first through the store's `PutBlob` (`BlobWriter`,
  which the cas store has); in a store without one such a redaction is
  not written (`ErrNoBlobWriter`). `StoreReport` gives per session the
  entries and blobs written, whether it was up to date, the findings of
  the whole redaction on every run, its warnings and the native entries
  its redaction holds. `Publishable` is false while it holds a native
  entry, waits, or holds a finding of a kind
  `StoreOptions.AcceptFindings` does not accept. A session that fails
  stops its dependents (`ErrDependency`) and no other; sessions in a
  cycle report `ErrCycle`. A session naming an entry of a session the
  store does not hold, or a fork whose origin the store does not hold
  or whose base its snapshot lacks, waits (`WaitingOn`), with nothing
  written, and so do its dependents. A redaction that grew a new root
  is refused before writing (`ErrRootAppend`), a known limit until
  agentsession appends a root. The redaction is released however a
  write ends; after appends, where the store has `SetHead`, its head is
  set to where an import of the same file puts it. Planning reads one
  session at a time; each is read in full at its turn.
- Added: `WithOrigin` and `Origin`: `Redact` writes a fork as a fork of
  its origin's redaction, at the entry standing for its base, sharing
  its prefix, with its own entries counting positions in the fork's
  file order. The prefix's fates come from replaying the origin's
  redaction up to the base (`ErrOriginBehind` when it does not reach
  it); a base the origin's redaction dropped is `ErrBaseLeftOut`. A
  redaction resumes in the mode it was written in.
- Changed: `Redact` writes every reference to another session,
  `parent_session`, a link's `session` and a `parents` element's
  session, as the redaction the profile derives for it, whether or not
  that session is at hand, so no original session ID is kept.
- Added: `WithAlongside` and `Alongside`: the entry a `parents` element
  names in another session is re-pointed through that session's new
  `Result.Counterparts`; one left out there is removed and reported,
  one it does not hold is `ErrUnmappedRef`, and without the
  counterparts it is kept and reported.
- Added: `Finding.Kind`, a stable `FindingKind` (`sidecar-media`,
  `inline-media`, `embedded-image`, `original-hash`,
  `foreign-reference`, `extension-entry`, `restates-left-out`,
  `redactor`). `Redact` reports the findings of the whole redaction on
  every call, a resume's replayed entries included.
- Changed: no error from `Redact` names an entry of the original by its
  hash: it is named by its position, and any other hash is elided.
- Changed: a redaction whose append stopped between a block placeholder
  and the kept entry closing its run resumes, rather than reading as
  diverged.
- Added: the nested module `agentredact/secrets`, standard library
  only (`make deps` and a test hold it there): a streaming secret
  redactor for what a process holding secrets writes back. `New` takes
  the values by name and finds each in every spelling a JSON encoder
  writes it in (Go's with and without HTML escaping, `\/`, Python's and
  PHP's ASCII forms, JavaScript's); `Redact`, `String` and `Reader`
  (a line at a time, a long line in pieces that never split a value)
  replace them with `[REDACTED NAME]`, and a callback hears each by
  name; `Exact` and `WithPlaceholder` change what is matched and
  written. It is dax's box host's redactor, moved here so agentworkspace
  and the box host share one (#14). A backstop: a value encoded
  otherwise is not found.
- Changed: `Secrets` is built on `agentredact/secrets` (exact, one
  placeholder); its output is unchanged.
- Changed: the repository releases two modules at one version from one
  commit, `vX.Y.Z` and `secrets/vX.Y.Z`; the root requires secrets at
  exactly that version. `make release` bumps, guards and tags both,
  `make extracted` builds each module the way a consumer gets it, and
  `make replaces` and `make guard-test` join `make check`.
