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
// reads from [EntryContext.Order]. What it cannot redact it reports
// with [EntryContext.Report], and leaves as it is or refuses with an
// error; it never passes it silently.
//
// One entry in, one entry out. A redactor that leaves an entry out,
// writes a placeholder for a run of them, merges or splits entries, or
// drops a branch, changes the session's structure and is not an
// EntryRedactor: it will be an interface of its own beside this one,
// which Redact checks for on each redactor of a profile, so redactors
// written to this one keep working unchanged.
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
}

// Entry returns the original entry, unredacted, that the one given to
// the redactor was made from.
func (c *EntryContext) Entry() agentsession.Entry {
	return c.Order[c.Position-1]
}

// Report records something the redactor found in this entry and did
// not redact: at is an RFC 6901 pointer into the entry, and message
// says what and why, and must not quote the value.
func (c *EntryContext) Report(at, message string) {
	if c.findings == nil {
		return
	}
	*c.findings = append(*c.findings, Finding{
		Position: c.Position,
		Entry:    c.Entry().Base().ID,
		At:       at,
		Redactor: c.redactor,
		Message:  message,
	})
}

// Finding is something [Redact] wrote without redacting it, which a
// person or a later stage must look at before the redacted session
// leaves: a sidecar image an inline-only redactor could not replace, an
// extension entry whose own members name entries as written. It never
// holds the value it is about.
type Finding struct {
	// Position is the entry's position in the original's file order,
	// counting from 1.
	Position int
	// Entry is the original entry's ID.
	Entry string
	// At is an RFC 6901 pointer into the entry, "" for the whole entry.
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
