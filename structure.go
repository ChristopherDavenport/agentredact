package agentredact

import (
	"errors"
	"fmt"

	"github.com/ChristopherDavenport/agentsession"
)

// StructureRedactor is an [EntryRedactor] that changes a session's
// structure: given one entry of the original, it returns the entries to
// write in its place, none to leave it out, or [Block] to leave it out
// folded into a block placeholder. [Redact] checks each redactor of
// Profile.Entries for this interface and, where it finds it, calls
// RedactStructure and never RedactEntry, so a structural redactor sits
// in the same list as the entry redactors, at the place in their order
// it is to run, and entry redactors written before it keep working
// unchanged.
//
// The entry it is given is what the redactors before it made of the
// original entry at c.Position: a fresh copy, which it may change in
// place and return. Each entry it returns must be a distinct value. The
// first entry it returns takes the original's place under its parent,
// each later one hangs from the one before, and the original's children
// hang from the last, which must be made from the original entry: the
// redaction marks it [n], and Redact finds it by that mark when it
// resumes. An entry marked [Made.Added] is one the redaction added,
// marked [].
//
// What it may leave out, and what follows from leaving it out, is
// [Redact]'s to check: a call left out takes its output, dispatches,
// decisions and links with it, and leaving out part of such a group,
// a config entry, or a run's end alone is refused. See [Redact].
//
// Like an entry redactor it must be deterministic and keep no state
// between calls, and its decision should depend on the entry and its
// path ([EntryContext.Path]) alone: what came after the entry in the
// original is not known when a redaction that later resumes is made,
// so a decision that reads it may differ on resume, which [Redact]
// refuses with [ErrResumeDiverged], and a fork and its origin give
// their shared prefix the same bytes only when the decision rests on
// the path.
type StructureRedactor interface {
	EntryRedactor
	RedactStructure(c *EntryContext, e agentsession.Entry) ([]Made, error)
}

// Made is one entry a [StructureRedactor] writes in place of the entry
// it was given.
type Made struct {
	// Entry is the entry to write. Redact sets its envelope: its parent,
	// its ID, and, when the timestamp is zero, the original entry's
	// timestamp, so that the output depends on the input alone.
	Entry agentsession.Entry
	// Added marks an entry the redaction added rather than made from
	// the original entry, which is marked [] instead of [n]. An entry
	// made from an added one is added too.
	Added bool

	block bool
}

// Block is what a [StructureRedactor] returns to leave its entry out
// folded into a block placeholder: one entry standing for a run of
// entries left out along a path, marked with their positions. [Redact]
// writes it, a custom entry under [PlaceholderNS] whose data says a
// block was redacted, once a kept entry follows the run on its path.
func Block() []Made { return []Made{{block: true}} }

// isBlock reports whether out is Block's result.
func isBlock(out []Made) bool { return len(out) == 1 && out[0].block }

// PlaceholderNS is the namespace of the custom entry a block placeholder
// is: {"type":"custom","ns":"agentredact","data":{"redacted":"block",
// "entries":<n>}}, n being the number of entries it stands for, its
// redacted member their positions. A custom entry is a record entry, so
// a placeholder adds nothing to the model's context: a redacted
// session's requests are the original's with the entries left out
// removed, and nothing the model was never sent is added to them.
const PlaceholderNS = "agentredact"

// StructureRedactorFunc adapts a function to [StructureRedactor]. Its
// RedactEntry refuses every entry, since leaving one out is not a thing
// one entry in and one entry out can do.
type StructureRedactorFunc func(c *EntryContext, e agentsession.Entry) ([]Made, error)

// RedactStructure calls f.
func (f StructureRedactorFunc) RedactStructure(c *EntryContext, e agentsession.Entry) ([]Made, error) {
	return f(c, e)
}

// RedactEntry refuses: see [StructureRedactorFunc].
func (f StructureRedactorFunc) RedactEntry(*EntryContext, agentsession.Entry) (agentsession.Entry, error) {
	return nil, errStructural
}

// errStructural is what a structural redactor's RedactEntry returns.
var errStructural = errors.New("agentredact: a structural redactor changes a session's structure; only Redact applies it")

// LeaveOut leaves out every entry match selects, writing nothing in its
// place: the entries under it hang from the nearest entry kept above
// it. match is given the entry as the redactors before it left it, and
// the context, whose Entry is the original; it must be deterministic and
// should read the entry and its path alone (see [StructureRedactor]).
func LeaveOut(match func(c *EntryContext, e agentsession.Entry) bool) StructureRedactor {
	return leaveOut{match: match}
}

// BlockOut leaves out every entry match selects folded into block
// placeholders, as [Block] says: a run of such entries along a path
// becomes one placeholder. match is as [LeaveOut]'s.
func BlockOut(match func(c *EntryContext, e agentsession.Entry) bool) StructureRedactor {
	return leaveOut{match: match, block: true}
}

type leaveOut struct {
	match func(c *EntryContext, e agentsession.Entry) bool
	block bool
}

func (r leaveOut) Name() string {
	if r.block {
		return "block-out"
	}
	return "leave-out"
}

func (r leaveOut) RedactStructure(c *EntryContext, e agentsession.Entry) ([]Made, error) {
	if r.match == nil {
		return nil, fmt.Errorf("agentredact: %s: no match function", r.Name())
	}
	switch {
	case !r.match(c, e):
		return []Made{{Entry: e}}, nil
	case r.block:
		return Block(), nil
	}
	return nil, nil
}

func (leaveOut) RedactEntry(*EntryContext, agentsession.Entry) (agentsession.Entry, error) {
	return nil, errStructural
}

// Errors [Redact] returns for leaving out what the format does not let a
// redaction leave out, wrapped with the position and ID of the entry
// that would break the rule.
var (
	// ErrSplitsCall: a call's output, dispatch, decision or link left
	// out while the call is kept. Leaving out the call leaves out the
	// whole group with it.
	ErrSplitsCall = errors.New("agentredact: leaving the entry out splits a call from its records")
	// ErrSplitsResponse: a response left out while an item it envelopes
	// is kept. Leaving out every item a response envelopes leaves out
	// the response with them.
	ErrSplitsResponse = errors.New("agentredact: leaving the response out leaves the items it envelopes without it")
	// ErrSplitsRun: a run's end left out while its start is kept, which
	// would read as a run cut off. Leaving out the start leaves out the
	// end with it.
	ErrSplitsRun = errors.New("agentredact: leaving the run's end out leaves its start without it")
	// ErrLeavesOutConfig: a config entry left out. Later entries resolve
	// against the settings it put in force (instruction parts named by
	// hash, keeps, omitted lists), which a redaction cannot know when it
	// leaves the entry out.
	ErrLeavesOutConfig = errors.New("agentredact: a config entry cannot be left out")
	// ErrFirstKept: a compaction kept whose first_kept was left out with
	// no entry that can stand in for it: none kept between it and the
	// compaction, and the nearest kept above it in context.
	ErrFirstKept = errors.New("agentredact: the compaction's first_kept was left out and nothing kept can stand in for it")
	// ErrNoPlace: a member of a kept entry names an entry left out, and
	// nothing was kept in that entry's place for it to name instead.
	ErrNoPlace = errors.New("agentredact: a member names an entry left out with nothing kept in its place")
	// ErrBreaksRecords: what was left out breaks a rule on the record
	// entries ([agentsession.Session.VerifyRecords]) on a path whose
	// original kept it, such as a run that resumed a call left out.
	ErrBreaksRecords = errors.New("agentredact: what was left out breaks a rule on the session's records")
	// ErrSessionRedactor: a session redactor kept an entry under one it
	// left out. A session redactor leaves out whole branches.
	ErrSessionRedactor = errors.New("agentredact: a session redactor kept an entry under one it left out")
	// ErrResumeDiverged: the existing redaction holds what a fresh
	// redaction of the original under the profile would not write, so
	// resuming it cannot give what a fresh one gives. A session
	// redactor that reads the whole session, such as [KeepLeafPath]
	// after the leaf moved to another branch, or a decision that reads
	// what came after its entry, gives it; redact afresh.
	ErrResumeDiverged = errors.New("agentredact: the existing redaction is not what a fresh one would write")
)
