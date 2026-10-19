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
