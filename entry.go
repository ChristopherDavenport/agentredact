package agentredact

import (
	"github.com/ChristopherDavenport/agentsession"
)

// EntryRedactor redacts one entry of an original, after the profile's
// string redactors have rewritten it, and returns the entry to write in
// its place. [Redact] calls it once for each entry it writes, in the
// original's file order, and then re-points the result's references,
// marks it redacted and commits it, so an entry redactor changes the
// body alone: it leaves the envelope (ID, parent, parents, timestamp)
// and the redacted member to Redact.
//
// The entry it is given is a fresh copy, which it may change in place
// and return, or replace with a new entry of the same type. It must be
// deterministic, its output depending on the context and the entry
// alone, and must keep no state between calls: Redact skips the
// entries it already wrote when it resumes, and a profile may redact
// many sessions at once, so what a redactor needs of earlier entries it
// reads from [EntryContext.Path], or [EntryContext.Order] where file
// order is what it needs; a placeholder numbered along the path gives a
// fork and its origin the same prefix. What it cannot redact it reports
// with [EntryContext.Report], and leaves as it is or refuses with an
// error; it never passes it silently.
//
// One entry in, one entry out. A redactor that leaves an entry out,
// folds a run of them into a block placeholder or writes several
// entries in one's place changes the session's structure: it is a
// [StructureRedactor], which [Redact] checks for on each redactor of a
// profile, so redactors written to this interface keep working
// unchanged. One that drops a branch is a [SessionRedactor].
type EntryRedactor interface {
	RedactEntry(c *EntryContext, e agentsession.Entry) (agentsession.Entry, error)
}

// EntryRedactorFunc adapts a function to [EntryRedactor].
type EntryRedactorFunc func(c *EntryContext, e agentsession.Entry) (agentsession.Entry, error)

// RedactEntry calls f.
func (f EntryRedactorFunc) RedactEntry(c *EntryContext, e agentsession.Entry) (agentsession.Entry, error) {
	return f(c, e)
}

// HeaderRedactor is an [EntryRedactor] that also redacts the redacted
// session's header, after the profile's string redactors: what it
// changes there it changes in place. [Redact] calls it only when it
// writes a new header, not when it resumes a session that has one.
type HeaderRedactor interface {
	RedactHeader(h *agentsession.Header) error
}

// EntryContext is what an [EntryRedactor] knows of the entry it is
// given beyond the entry itself.
type EntryContext struct {
	// Original is the session being redacted.
	Original *agentsession.Session
	// Order is the original's entries in file order
	// ([agentsession.FileOrder]), prefix included: what the entry's
	// position counts in. A redactor must not modify it.
	Order []agentsession.Entry
	// Position is the entry's position in Order, counting from 1.
	Position int

	redactor string
	findings *[]Finding
	blobs    map[string][]byte
}

// Path returns the original's path to the entry, root first, the entry
// last, as [agentsession.Session.Path] gives it: a fork's prefix
// included. What a redactor numbers or compares along it, a fork and
// its origin number alike in their shared prefix.
func (c *EntryContext) Path() []agentsession.Entry {
	return c.Original.Path(c.Entry().Base().ID)
}

// Entry returns the original entry, unredacted, that the one given to
// the redactor was made from.
func (c *EntryContext) Entry() agentsession.Entry {
	return c.Order[c.Position-1]
}

// Report records something the redactor found in this entry and did
// not redact: at is an RFC 6901 pointer into the entry as the redactor
// was given it, so built from rewritten member names, and message says
// what and why, and must quote neither the value nor an original hash.
func (c *EntryContext) Report(at, message string) {
	if c.findings == nil {
		return
	}
	*c.findings = append(*c.findings, Finding{Position: c.Position, At: at, Redactor: c.redactor, Message: message})
}

// AddBlob records data as a blob the redacted session needs, such as
// the replacement for a sidecar image, and returns its hash,
// sha256:<hex>, which a sidecar: URL names. [Redact] returns the blobs
// of the entries it commits in [Result.Blobs] for the caller to store
// beside the redacted session; it writes none itself. A blob the
// original holds and the redaction keeps is not added: it is the
// original's, shared.
func (c *EntryContext) AddBlob(data []byte) string {
	hash := agentsession.HashBytes(data)
	if c.blobs != nil {
		c.blobs[hash] = append([]byte(nil), data...)
	}
	return hash
}

// Finding is something [Redact] wrote without redacting it, which a
// person or a later stage must look at before the redacted session
// leaves: sidecar or inline media that is not an image, an image
// inside a longer string,
// an instruction part that keeps the original's hash, a reference into
// another session, an extension entry whose own members name entries as
// written.
//
// A Finding is local, for whoever holds the original: it names the
// entry by its position in the original, which maps back only with the
// original in hand, and it holds neither the value it is about nor any
// hash of the original. It is not part of the redacted session and is
// never published with it.
type Finding struct {
	// Position is the entry's position in the original's file order,
	// counting from 1.
	Position int
	// At is an RFC 6901 pointer into the redacted entry, built from its
	// rewritten member names, "" for the whole entry.
	At string
	// Redactor names what reported it: an entry redactor's name, or
	// "redact" for Redact itself.
	Redactor string
	// Message says what was found and why it was left.
	Message string
}

// redactorName is the name a finding gives an entry redactor: its own
// when it has one.
func redactorName(r EntryRedactor) string {
	if n, ok := r.(interface{ Name() string }); ok {
		return n.Name()
	}
	return "entry"
}
