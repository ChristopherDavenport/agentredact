// Package agentredact writes redacted sessions and decides which of
// them leave a store. A redacted session, in the Agent Session Format
// (agentsession, format 0.13), is a session of its own made from an
// original: every entry the redaction writes carries redacted, the
// positions of the original's entries it was made from, its header
// carries redacted_from and an ID derived from the original and a
// profile, and its hashes, request hashes included, are computed over
// what it holds, so it verifies, grows and resumes like any other.
//
// The package will hold the redactors, at three levels (strings,
// entries, sessions), deterministic and named by a profile, and the
// pass that keeps one redacted session per original per profile in the
// same store, appending as the original grows; the scan, review and
// publish stages are packages of their own. What a valid redacted
// session is, and what a store does with one, is agentsession's: this
// module reaches strings through its Rewriter, references through
// RemapRefs, positions through SetRedacted and request hashes through
// Session.SetRequestHash, and never re-derives the format.
// docs/plans/agentredact.md is the design.
package agentredact
