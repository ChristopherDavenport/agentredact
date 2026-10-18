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
// reads; and [EntryRedactor]s, applied to each entry after, such as
// [Environment] and [Images]. All are deterministic. [Redact] applies a
// profile to one session and returns the redacted session in memory,
// or grows an earlier redaction by what the original appended. The
// pass that keeps one redacted session per original per profile in a
// store is to come; the scan, review and publish stages are packages
// of their own. What a valid redacted
// session is, and what a store does with one, is agentsession's: this
// module reaches strings through its Rewriter, references through
// RemapRefs, positions through SetRedacted and request hashes through
// Session.SetRequestHash, and never re-derives the format.
// docs/plans/agentredact.md is the design.
package agentredact
