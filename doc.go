// Package agentredact writes redacted sessions and decides which of
// them leave a store. A redacted session, in the Agent Session Format
// (agentsession, format 0.13), is a session of its own made from an
// original: every entry the redaction writes carries redacted, the
// positions of the original's entries it was made from, its header
// carries redacted_from and an ID derived from the original and a
// profile, and its hashes, request hashes included, are computed over
// what it holds, so it verifies, grows and resumes like any other.
//
// A [Profile] names a set of redactors: [StringRedactor]s, joined into
// the one function an agentsession Rewriter applies to every string,
// such as [Secrets], [HomePaths], [Patterns] and the rules [ParseRules]
// reads; [EntryRedactor]s, applied to each entry after, such as
// [Environment] and [Images], which replaces inline and sidecar images
// alike; [StructureRedactor]s among them, which leave an entry out
// ([LeaveOut]), fold runs of entries left out into block placeholders
// ([BlockOut]) or write several entries in one's place; and
// [SessionRedactor]s, which leave out whole branches before any entry is
// redacted ([KeepLeafPath], [DropBranches]). All are deterministic. A
// redactor matches text as written: a secret encoded in base64, in URL
// encoding or in an image's bytes is not found, so the joined function
// keeps a base64 data URL's payload as it is, giving the redactors its
// media type and parameters alone; the scan and the review are the
// backstop.
//
// [Redact] applies a profile to one session and returns the redacted
// session in memory, with the blobs its sidecar images need, or grows an
// earlier redaction by what the original appended, equal to a fresh
// redaction of the grown original. It keeps what it leaves out from
// breaking the format: a call leaves with its records, a response with
// its items, a run's end with its start; what cannot be left out alone
// is refused by name. It renames the member names in the header's
// unknown members, refuses an entry holding a member name the redactors
// would change ([ErrKeyNotRedacted]), and reports what it kept
// unredacted as local [Finding]s. It writes a fork without a base, or,
// given its origin's redaction ([WithOrigin]), as a fork of that,
// sharing its prefix. It writes every reference to another session as
// the redaction the profile derives for it, and re-points the entries a
// parents element names in sessions redacted alongside
// ([WithAlongside]).
//
// [RedactStore] keeps one redacted session per original per profile in
// a store: it redacts each original after the sessions it hashes over,
// forks as forks of their origin's redaction, imports a new redaction
// whole and appends to an existing one what its original added, writes
// the blobs through the store's [BlobWriter], and reports per session
// what it wrote, what the whole redaction holds unredacted, whether it
// waits for a session the store does not hold yet, and whether it holds
// native entries. What it writes never depends on the order sessions
// arrived in, and a rerun with nothing new writes nothing. The scan, review and
// publish stages are packages of their own.
//
// What a valid redacted session is, and what a store does with one, is
// agentsession's: this module reaches strings through its Rewriter,
// references through RemapRefs, positions through SetRedacted and
// request hashes through Session.SetRequestHash, and never re-derives
// the format. docs/plans/agentredact.md is the design.
package agentredact
