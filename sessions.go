package agentredact

import (
	"fmt"

	"github.com/ChristopherDavenport/agentsession"
)

// SessionRedactor chooses whole branches of an original to leave out.
// [Redact] asks each of a profile's session redactors once, before it
// redacts any entry, and leaves out every entry any of them selects:
// such an entry reaches no entry redactor, needs no placeholder, and
// its position appears in no redacted entry. Entries kept elsewhere
// that named one name what was kept in its place, as [Redact] says.
//
// LeaveOut returns, for each entry of order (the original's file order,
// prefix included), whether to leave it out. It leaves out whole
// branches: an entry under one it leaves out is left out too, and
// Redact refuses one that is kept with [ErrSessionRedactor]. What it
// leaves out is held to the group rules before anything is written: a
// call's output, dispatch, decision or link, an item drained from a
// queued input, a run's end, or a response left out while what it
// belongs with is kept is refused ([ErrSplitsCall] and the others), as
// it is of a structural redactor. It must be
// deterministic. A choice that rests on each entry's path alone, as
// [DropBranches] given a predicate over the path makes, is the same
// however the original grows, so a resumed redaction stays equal to a
// fresh one; one that reads the whole session, as [KeepLeafPath] does,
// may change as the original grows, and Redact then refuses to resume
// with [ErrResumeDiverged] rather than write a redaction no fresh one
// would.
type SessionRedactor interface {
	LeaveOut(original *agentsession.Session, order []agentsession.Entry) ([]bool, error)
}

// KeepLeafPath keeps the entries on the path to the original's leaf
// ([agentsession.Session.Leaf]: in a store its head, in a file what the
// file's rules give), prefix included, and leaves out every other
// branch, except the records of the path's own groups that sit off it:
// a dispatch, output, decision, subsession or peer link or cancel notice
// of a call on the path, the end of a run started on it, the response
// enveloping items on it, and an item drained from a queued input on
// it. Such an entry is kept where it sits, under its parent, when that
// parent is kept, as after a retry that rewound to before a call's
// dispatch; nothing else of the abandoned branch is. One whose parent
// is part of the abandoned conversation, such as a run's end after a
// rewind inside the run, cannot be kept in place, and the redaction is
// refused with the group's sentinel ([ErrSplitsCall], [ErrSplitsRun] and
// the others) before anything is written. The redaction then grows with the original as long as the
// leaf moves along its branch; once the leaf moves to another branch,
// entries already redacted are off the new path, and resuming is
// refused with [ErrResumeDiverged].
//
// What the path holds about the branches it leaves out stays, and is
// reported as a [Finding]: a branch summary of an abandoned branch, a
// compaction folding what came before, an entry converging a worker
// branch's result. A label or an outcome naming an entry off the path
// is left out with it.
func KeepLeafPath() SessionRedactor { return keepLeafPath{} }

type keepLeafPath struct{}

func (keepLeafPath) Name() string { return "keep-leaf-path" }

func (keepLeafPath) LeaveOut(original *agentsession.Session, order []agentsession.Entry) ([]bool, error) {
	keep := map[string]bool{}
	if leaf := original.Leaf(); leaf != "" {
		for _, e := range original.Path(leaf) {
			keep[e.Base().ID] = true
		}
	}
	// An entry off the path is kept when it is a member of a group whose
	// head is kept and its parent is kept: the path's own call's
	// records, where they sit. File order puts the parent and the head
	// first. A member whose parent is not kept is left out, and Redact
	// refuses that with the group's sentinel before writing.
	groups := &redaction{original: original, order: order}
	kept := func(id string) bool { return keep[id] }
	out := make([]bool, len(order))
	for i, e := range order {
		b := e.Base()
		if !keep[b.ID] && b.Parent != "" && keep[b.Parent] && groups.splits(e, kept) != nil {
			keep[b.ID] = true
		}
		out[i] = !keep[b.ID]
	}
	return out, nil
}

// DropBranches leaves out every entry drop selects, with everything
// under it: a branch, here, is an entry and the entries below it. drop
// is asked about each entry in file order that is not already under one
// it selected; c.Entry() is the original entry, and c.Path() its path.
// It must be deterministic. A drop that reads the entry and its path
// alone keeps resuming equal to a fresh redaction, and a fork's prefix
// equal to its origin's; one that reads what came after, such as the
// entry's siblings, may not (see [SessionRedactor]). As with
// [KeepLeafPath], summaries and converged results on the kept branches
// that restate a dropped one stay, and are reported.
func DropBranches(drop func(c *EntryContext) bool) SessionRedactor {
	return dropBranches{drop: drop}
}

type dropBranches struct {
	drop func(c *EntryContext) bool
}

func (dropBranches) Name() string { return "drop-branches" }

func (r dropBranches) LeaveOut(original *agentsession.Session, order []agentsession.Entry) ([]bool, error) {
	if r.drop == nil {
		return nil, fmt.Errorf("agentredact: drop-branches: no drop function")
	}
	out := make([]bool, len(order))
	dropped := map[string]bool{}
	for i, e := range order {
		b := e.Base()
		if dropped[b.Parent] || r.drop(&EntryContext{Original: original, Order: order, Position: i + 1}) {
			out[i] = true
			dropped[b.ID] = true
		}
	}
	return out, nil
}

// sessionName is the name an error gives a session redactor.
func sessionName(r SessionRedactor) string {
	if n, ok := r.(interface{ Name() string }); ok {
		return n.Name()
	}
	return "session"
}
