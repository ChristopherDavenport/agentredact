# Plan: agentredact

agentredact writes redacted sessions and decides which of them leave a
store. agentsession provides the format, the store rules and the
helpers; agentredact holds only policy and pipeline: the redactors, the
pass that keeps a store's redactions current, the scan, the review, the
manifest and the publish. It takes over agentsession#12, whose library
half agentsession closed in v0.0.27 and v0.0.28.

Written 2026-10-18, against agentsession v0.0.28 (format 0.13). It
merges the drafts on #1: the first, which described sealed snapshot
twins, is superseded by the revision for v0.0.27, which marks redaction
per entry, and by the v0.0.28 step that gives every redacted response
its own `request_hash`. Issues #2–#6 track the work; the bodies of #2,
#3, #4 and #6 still speak of twins, and where they differ from this
plan, this plan holds.

## The model it builds on

The rules are agentsession's: RFC 0001's Redaction section, RFC 0002's
Redacted sessions section and `docs/plans/redaction.md`. In short:

- **A redacted entry** carries `redacted`, the file-order positions in
  the original, prefix included and counting from 1, of the entries it
  was made from: `[n]` for an entry made from one, `[[from, to]]` for a
  placeholder standing in for a block left out, several elements for a
  merge, `[]` for an entry the redaction added. A split names one
  position twice. No other entry carries the member, so a reader always
  knows which entries a redaction made.
- **The header** carries `redacted: true` and
  `redacted_from: {session, profile}`. Its ID is
  `RedactedSessionID(original, profile)`, a UUIDv5 over
  `["redacted","<original>","<profile>"]`, so one original under one
  profile always has one redacted session, whose ID stays as it grows.
- **A redacted session hashes independently.** Every hash in it is
  computed over what it holds, `request_hash` included: the redactor
  calls `Session.SetRequestHash` on each response, and the session then
  verifies and replays like any other. A response made from one whose
  `request_hash` did not verify in the original gets none, so a
  redaction never certifies a request the original could not. The only
  original hash a redacted session can keep is a reference into a
  session not redacted alongside it.
- **It is a session like any other.** It grows as the redactor redacts
  what the original appends, anyone can resume it, and an entry
  appended natively carries no `redacted`. A store holds it beside the
  original.
- **A store set to hold only redacted entries** (`WithRedactedOnly` on
  jsonl, cas, sqlite and the remote client; persisted on disk for cas)
  refuses a header without `redacted` and every entry without the
  marker, by any path: create, append, import, push, fetch, prefix
  included. It is the fail-closed publish target.

API used: `NewRewriter`/`Rewriter.Rewrite`, `RemapRefs`/`Remap`,
`RemapHeaderRefs`, `SetRedacted`, `RedactedOf`, `RedactedSessionID`,
`Session.SetRequestHash`, `FileOrder`, `Original`, `Redactions`,
`Importer`, `GateEntry`, `Session.RaiseRefused`, `WithRedactedOnly`,
and `export.NoPassthrough` for ATIF.

## What is here and what is not

What a valid, linked redacted session is, and what a store does with
one, is agentsession's, and agentredact never re-derives it: it reaches
every string through `Rewriter`, every reference through `RemapRefs`,
every position through `SetRedacted` and every request hash through
`SetRequestHash`. Where agentredact needs format knowledge no helper
gives, the fix is a helper in agentsession, not a copy here.

What is here is choice: which values are replaced and with what, which
entries are left out, which sessions are redacted under which profile,
whether a redacted session is clean enough to leave, and where it goes.

## Layout and dependencies

One module, `github.com/ChristopherDavenport/agentredact`, Go 1.25.

| Package | What it is | Issue |
| --- | --- | --- |
| `agentredact` | the redactor contract at three levels, profiles, the built-in redactors and the store-wide pass | #2, #3 |
| `scan` | the TruffleHog gate, running the `trufflehog` binary through `os/exec` | #4 |
| `review` | the LLM review, through `openresponses` | #5 |
| `publish` | the manifest, the push to a redacted-only store and the dataset export | #6 |
| `cmd/agentredact` | the command: `redact`, `scan`, `review`, `publish` | #3–#6 |

Only the root package exists at the scaffold; the others arrive with
their issues, and may split or merge as the code asks.

**The dependency rule.** Every package imports the standard library,
this module, `agentsession`, `openresponses` and `agentpolicy` alone.
At any depth, the only modules beyond those are the ones `agentpolicy`
brings in from the same family, `agentturn` and `agenttool`
(`agentpolicy/guard` imports both); no third-party module, and not
agentsession's nested modules (`agentsession/sqlite`, which brings a
driver, and `agentsession/otel`). `make deps`
(`scripts/check-deps.sh`) enforces both halves: the direct imports by
module, and every module the build reaches.

Why: agentredact handles the most private data in the stack, and every
dependency is code that sees unredacted sessions before the gates do.
The same rule keeps agentsession's root module to `openresponses`, and
agentimport's to its two siblings. So:

- **TruffleHog runs as an external binary.** Its Go packages would
  bring hundreds of modules into the build and into govulncheck's
  surface; the binary is versioned and updated on its own, and its
  `--json` output, one finding per line, is the contract. This settles
  #4's first open question.
- **Stores** are those agentsession's root module holds: jsonl, cas
  and the remote client. A sqlite store needs `agentsession/sqlite`
  and its driver, and so a decision first (a nested module, as
  agentsession does it, is the likely shape).
- **Anything else needing a third-party module**, such as an upload
  client for a dataset host, needs a decision recorded here first,
  then a change to `scripts/check-deps.sh` in the same commit.

## Redactors (#2)

Redactors work at three levels and compose in order: every string
redactor of a profile, joined into the one function a `Rewriter`
applies; then its entry redactors; then its session redactors.

- **Strings**, applied through `Rewriter`:
  - exact secret values from a list, longest first;
  - home paths: an absolute path under the home directory becomes
    `~`-relative;
  - regexes, with agentpolicy's `guard.DefaultSecrets` as the named
    default set, each match written `[REDACTED <name>]`, as
    `guard.Redact` writes it;
  - a rules file in git-filter-repo's `--replace-text` form:
    `literal==>replacement`, `regex:pattern==>replacement`, a bare
    line meaning `***REMOVED***`.
- **Entries:**
  - blank `environment` entries and the header's `cwd`;
  - replace an image with a placeholder item, inline staying inline
    and sidecar staying sidecar, with the new blob stored under its
    own hash. No OCR;
  - leave an entry out: its children hang from what was kept in its
    place, a member that named it names that or is removed, and a
    placeholder marked `[[from, to]]` says in its body that a block
    was redacted.
- **Sessions:** leave out a branch, or keep only the leaf's path.

The `Rewriter` is the only way a string redactor reaches an entry. It
sees every string the format lets a redactor change (inline media's
base64 undecoded, the `normalised` record, an env entry's file paths),
recomputes instruction part hashes and joins, and leaves alone what is
not text: the envelope, `redacted`, hashes, sidecar URLs and
`call_id`s. A redactor that must change a `call_id` changes every one
in step, across sessions redacted alongside, and the subsession IDs
derived from them.

**Deterministic.** A redactor's output depends on its input and its
rules alone: no clock, no randomness, no map order, and a placeholder's
text depends only on what it replaces. A fork and its origin then give
their shared prefix the same bytes, and a rerun writes what it wrote
before, so a store pass converges instead of forking its own output.

**Leaving out, and resuming.** What a redaction writes at a position
depends on the original's entries up to it alone: a structural
decision reads the entry and its path, a group is led by its earliest
entry (a call takes its records, a run's start its end, a queued
input the items drained from it, and a response's items, all left out,
take the response), and a block
placeholder is written as the step that writes the kept entry closing
its run, a run at the end of a path being withheld. So no progress
record is needed: a resume replays every position up to the highest
any marked entry names, ranges included, rebuilding what a fresh
redaction writes there and requiring the redaction to hold an entry of
the same ID, which restores the runs still withheld and refuses a
profile reused for changed rules, and writes the rest. A session
redactor that reads the whole session, such as keeping the leaf's
path, can make that match fail after growth; the resume is then
refused rather than written. The placeholder is a custom entry under
`agentredact`, not an item: it adds nothing to the requests, so a
redacted session's requests are the original's less what was left out.

**Profiles.** A profile names a redactor set and its version, such as
`default@1`. It is written to `redacted_from.profile` and goes into the
derived ID, so two profiles of one original are two sessions, and one
profile resumes its own. Rules changed under the same profile write
into the same session, mixing two redactions in one; the profile must
change whenever the rules do.

Not found: a secret encoded in base64, in URL encoding, or in an
image's bytes. String redactors match text as written, and inline
media reaches them as an undecoded data URL. The README and the
command's help say so, and the scan and the review are the backstop,
not a guarantee.

Once these cover what agentsession's `export.Secrets`, `HomePaths` and
`Environment` do, agentsession deprecates them.

## Redacting a store (#3)

Keep one redacted session per profile for every session in a store, in
the same store, and append to it as its original grows.

- **Resume** each one from its markers. Open
  `RedactedSessionID(original, profile)`; if the store holds it, the
  highest original position its own entries name is the work done.
  Redact the original's entries after that position, in file order
  (`FileOrder`), feeding the `Rewriter` every entry from the first, so
  it knows what earlier parts hash to now.
- **Per entry**, for each entry the redactors keep or add:
  1. `Rewriter.Rewrite`, then the entry redactors;
  2. `RemapRefs` through the old→new map: `parent` and every
     entry-naming member to the IDs this session wrote, entries of
     sessions redacted alongside to theirs, and every session ID to
     the redaction the profile derives for it, held or not;
  3. `SetRedacted(e, spans)` with the positions it was made from;
  4. on a response, `Session.SetRequestHash(resp)`, after clearing
     `RequestHash` when the original's did not verify;
  5. commit it in memory; the pass then writes the session whole
     through the store's `Importer` the first time (as its record, so a
     cas store does not hold it as a mirror), and after that `Append`s
     the new entries with their IDs set, which every store checks
     against the hash it computes, and sets the head, where the store
     can (cas), to where an import of the same file puts it. A store's
     `Append` fills an empty parent from its leaf, so a new root cannot
     be appended; the pass refuses it before writing (`ErrRootAppend`)
     until agentsession can.

  The header goes through `RemapHeaderRefs` (`parent_session`, `base`)
  and the redactors, and gains `redacted`, `redacted_from` and the
  derived ID.
- **Order.** A session goes after every session its entries hash over:
  a fork's origin, and any session its `parents` reach into. Session
  IDs need no order, since every redaction's ID is derived and known up
  front. Ready sessions are taken by ID, so the order is the same on
  every run. A selection of originals takes its dependencies with it.
  Planning reads one session at a time for its dependencies; each
  original is read in full again at its turn, and kept only while a
  fork of it is still to be redacted.
- **Arrival order changes nothing written.** A session that names an
  entry of a session the store does not hold, or whose redaction this
  run could not read, waits: nothing is written for it, its dependents
  wait too, and every run reports it until the session arrives. So does
  a fork whose origin the store does not hold, or whose base the
  origin's snapshot lacks (a fork made while the pass ran).
- **Forks.** A fork's redaction is a fork of its origin's redaction,
  sharing its prefix, whose positions count in the origin, as RFC 0001
  says. What the origin's redaction made of each prefix entry is found
  by replaying the origin's redaction up to the base: so it depends on
  the origin up to the base alone and stays as both grow. The base is
  the entry standing for the original's base there. A prefix run
  folded into a block that none of the origin's own entries up to the
  base closed gets a placeholder of the fork's own, marked with the
  run's positions in the fork's file order, which is where the fork's
  own entries count. A base on a branch the origin's session redactors
  dropped has nothing standing for it, and that fork is redacted
  without a base: the one case, a decision of the origin's redaction. A
  redaction resumes in the mode it was written in.
- **References** to sessions always name the redaction the profile
  derives for them, whether or not the store holds them, so no original
  session ID is kept and neither a selection nor arrival order changes
  what is written. A `parents` element's entry in another session goes through that
  session's counterparts (each original entry to the redacted entry
  standing for it, or none when it was left out, a fate that never
  changes); one naming an entry left out there is removed and reported,
  as one naming an entry left out here is, and one naming nothing that
  session holds fails the session. An extension entry comes back
  `Opaque`, its own members unread; its strings still go through the
  `Rewriter`.
- **Blobs.** A replaced sidecar blob is written to the store under the
  replacement's hash, through its `PutBlob`, before the entries naming
  it; a kept blob is shared with the original. The cas store has
  `PutBlob`, beside its `Import`, which takes no blobs
  (agentsession#245); the memory and jsonl stores have no blob write
  path, and there a redaction that made blobs is not written.
- **Failures.** A session that fails is reported, and the sessions that
  depend on it, through any chain, are not redacted; every other
  session is. An append that fails part way leaves a redaction that the
  next run resumes, a block placeholder written without the entry that
  closes its run included.
- **A rerun** with the same profile finds every redacted session up to
  date and writes nothing.
- **A resumed redacted session** holds native entries, which a
  redacted-only store refuses. The pass reports such a session, and it
  stays private until those entries are redacted too.
- **Findings** are reported for the whole redaction on every run, each
  with a stable kind, and a session holding one is not publishable
  unless the caller accepts its kind. Errors name entries by position,
  never by an original hash.

Tests, all over synthetic stores: a parent and its fork share their
redacted prefix; a second run writes nothing; a string planted in every
place an entry can hold one is absent from the redacted session's
bytes; every redacted session verifies, its request hashes included.

## Pipeline (#4–#6)

1. **Redact** the private store as above, and convert the result to
   ATIF with `export.NoPassthrough`; each ATIF step carries its
   `redacted` marker.
2. **Scan** (#4) the redacted sessions and the ATIF documents with
   TruffleHog, the binary, over the bytes that would leave. Any finding
   blocks publishing that session.
3. **Review** (#5) with an LLM given the project's context, to catch
   what the deterministic pass missed: a name, a host, a customer. A
   flag blocks publishing until a person clears it or adds a redactor,
   which means a new profile.
4. **Manifest** (#6): for each published session, its redacted hashes
   and `redacted_from`. The original's hashes stay local, since an
   original hash lets anyone confirm a guessed value.
5. **Publish** (#6): push the redacted sessions to a store set to hold
   only redacted entries, so an original sent by mistake is refused, or
   export them, with their blobs and ATIF, into a dataset repository,
   as pi-share-hf does. Until agentsession#244 lands, a push a remote
   refuses leaves its objects there until a sweep.

Scan and review verdicts go in a separate session that links to the one
it judges, naming the entry it judged up to. They are records, not
redacted entries: appended to the redacted session they would be native
entries, and the publish target would refuse it.

The first draft moved a ref, `redacted/<profile>/<original>`, to each
newest twin, and published what those refs named. With one redacted
session per original per profile there is nothing for such a ref to
move between, so the publish selects by `redacted_from.profile` instead.

## Command

`agentredact` over a store (jsonl, cas, remote): `redact`, `scan`,
`review` and `publish`, each reading the store and the previous stage's
verdicts, and each safe to run again.

## Work, in order

1. **Scaffold and plan** (#1): this repository, this plan.
2. **Redactors** (#2): the three levels, the built-ins, the rules file,
   profiles.
3. **Store pass** (#3): resume, the per-entry steps, order, references,
   blobs; the command's `redact`.
4. **Scan gate** (#4).
5. **Review** (#5).
6. **Manifest and publish** (#6).

## Open questions

- Where the review's context comes from: the session's AGENTS.md chain,
  or a file the publisher supplies? Which model, and how its cost is
  bounded?
- First dataset host: Hugging Face? Does a dataset repository count as
  a store, and does its upload client clear the dependency rule?
- Catching a profile reused for changed rules: a digest of the rules
  would confirm guessed secret values if published, so it can only be
  kept beside the private store, never in `redacted_from`.
- Publishing a session that grew after it was judged: push it only up
  to the judged entry, or hold it until the new entries are judged?
- A header's strings: no agentsession helper rewrites them as
  `RewriteStrings` does an entry's (`cwd`, `harness`, extension
  members). Ask for one, or redact the members agentredact knows and
  refuse a header with unknown ones?
- Should `RewriteStrings` report what it changed (member paths, not
  values), so a reviewer can see a redaction without the old values?
  This is agentsession's open question too.
