package agentredact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// fate is what a redaction made of one entry of the original.
type fate uint8

const (
	// kept: one or more entries were written in its place.
	kept fate = iota + 1
	// folded: left out, folded into a block placeholder, which is
	// written once a kept entry follows its run on a path.
	folded
	// omitted: left out with nothing in its place.
	omitted
	// dropped: left out by a session redactor, with everything under it.
	dropped
)

// placed is what a redaction made of one entry of the original.
type placed struct {
	fate fate
	pos  int
	// first and last are the redacted entries that stand for it: for a
	// kept entry the first and the last written in its place, for a
	// folded one its block placeholder once that is written. Both are ""
	// while there is none.
	first, last string
}

// redaction is one call of [Redact].
//
// It walks the original in file order and decides each entry's fate
// from the entry and what came before it in that order, never from what
// came after: an entry's parent precedes it, a call precedes its
// records, a response's items precede it, and a block placeholder is
// written only when a kept entry closes its run, as the step that
// writes that entry. So what a redaction writes at each position
// depends on the positions up to it alone, and a redaction resumed
// after the original grew writes what a fresh one writes. A resume
// replays the positions up to the highest one the existing redaction
// names, matching what a fresh one would write there against what it
// holds, rather than writing it, and then writes the rest.
type redaction struct {
	p        Profile
	f        StringRedactor
	original *agentsession.Session
	order    []agentsession.Entry
	origID   string
	redID    string
	red      *agentsession.Session
	res      *Result
	rw       *agentsession.Rewriter
	placed   map[string]*placed
	// leftOut is set once an entry has been left out, by any redactor.
	leftOut bool

	// done is the highest position the existing redaction's entries
	// name; the positions up to it are replayed, not written.
	done int
	// held are the existing redaction's marked entries in file order,
	// and byMark the same by their redacted member.
	held    []agentsession.Entry
	byMark  map[string][]agentsession.Entry
	matched map[string]bool
}

// resume checks that existing is the redaction of the original under
// the profile, and indexes what it holds.
func (r *redaction) resume(existing *agentsession.Session) error {
	h := existing.Header()
	switch {
	case !h.Redacted || h.RedactedFrom == nil:
		return fmt.Errorf("%w: %s is not a redacted session", ErrNotThisRedaction, h.ID)
	case h.RedactedFrom.Session != r.origID:
		return fmt.Errorf("%w: %s was redacted from %s, not %s", ErrNotThisRedaction, h.ID, h.RedactedFrom.Session, r.origID)
	case h.RedactedFrom.Profile != r.p.Name:
		return fmt.Errorf("%w: %s was redacted under profile %q, not %q", ErrNotThisRedaction, h.ID, h.RedactedFrom.Profile, r.p.Name)
	case h.ID != r.redID:
		return fmt.Errorf("%w: %s is not the ID the original and profile derive, %s", ErrNotThisRedaction, h.ID, r.redID)
	case h.Base != "":
		return fmt.Errorf("%w: %s has a base; resuming a fork of a redaction is the store pass's", ErrNotThisRedaction, h.ID)
	}
	r.byMark = map[string][]agentsession.Entry{}
	r.matched = map[string]bool{}
	for _, e := range agentsession.FileOrder(existing) {
		spans, ok := agentsession.RedactedOf(e) // none on an entry appended natively
		if !ok {
			continue
		}
		for _, sp := range spans {
			if sp.To > len(r.order) {
				return fmt.Errorf("agentredact: %s: entry %s names position %d of %s, which holds %d entries: %w", h.ID, e.Base().ID, sp.To, r.origID, len(r.order), agentsession.ErrStaleOriginal)
			}
			r.done = max(r.done, sp.To)
		}
		k := markKey(spans)
		r.held = append(r.held, e)
		r.byMark[k] = append(r.byMark[k], e)
	}
	return nil
}

// sessions asks the profile's session redactors which entries to leave
// out, and holds each to leaving out whole branches.
func (r *redaction) sessions() ([]bool, error) {
	out := make([]bool, len(r.order))
	at := make(map[string]int, len(r.order))
	for i, e := range r.order {
		at[e.Base().ID] = i
	}
	for _, s := range r.p.Sessions {
		name := sessionName(s)
		drop, err := s.LeaveOut(r.original, r.order)
		if err != nil {
			return nil, fmt.Errorf("agentredact: session redactor %s: %w", name, err)
		}
		if len(drop) != len(r.order) {
			return nil, fmt.Errorf("agentredact: session redactor %s: chose for %d entries, the original has %d", name, len(drop), len(r.order))
		}
		for i, e := range r.order {
			if drop[i] {
				out[i] = true
				continue
			}
			if j, ok := at[e.Base().Parent]; ok && drop[j] {
				return nil, fmt.Errorf("%w: %s leaves out position %d and keeps position %d under it", ErrSessionRedactor, name, j+1, i+1)
			}
		}
	}
	return out, nil
}

// entry redacts the original's entry e at pos, body being its rewritten
// copy: it decides what becomes of it and, when anything is kept, writes
// or, replaying, matches the entries made from it.
func (r *redaction) entry(pos int, e, body agentsession.Entry) error {
	replay := pos <= r.done
	id := e.Base().ID
	how := r.forced(e)
	var made []Made
	if how == 0 {
		var (
			block bool
			err   error
		)
		// What the redactors report or add for an entry then left out
		// is dropped with it: a finding names an entry written, and a
		// blob is one a written entry names.
		found, blobs := len(r.res.Findings), map[string][]byte{}
		if made, block, err = r.chain(pos, body, replay, blobs); err != nil {
			return err
		}
		if len(made) == 0 {
			r.res.Findings = r.res.Findings[:found]
		} else {
			for h, b := range blobs {
				r.res.Blobs[h] = b
			}
		}
		if len(made) == 0 {
			how = omitted
			if block {
				how = folded
			}
			if err := r.mayLeaveOut(e); err != nil {
				return err
			}
		}
	}
	if how != 0 {
		r.placed[id] = &placed{fate: how, pos: pos}
		r.leftOut = true
		return nil
	}
	parent, err := r.standIn(e.Base().Parent, replay)
	if err != nil {
		return err
	}
	pl := &placed{fate: kept, pos: pos}
	for i, m := range made {
		var nid string
		if replay {
			nid, err = r.match(markOf(pos, m.Added), m.Entry.EntryType(), parent, pos)
		} else {
			nid, err = r.write(pos, e, m, parent)
		}
		if err != nil {
			return err
		}
		if i == 0 {
			pl.first = nid
		}
		parent = nid
	}
	pl.last = parent
	r.placed[id] = pl
	return nil
}

// leftFate is the fate of the entry id when it was left out by an entry
// redactor, folded or omitted, and 0 otherwise.
func (r *redaction) leftFate(id string) fate {
	if pl := r.placed[id]; pl != nil && (pl.fate == folded || pl.fate == omitted) {
		return pl.fate
	}
	return 0
}

// isKept reports whether the entry id was kept.
func (r *redaction) isKept(id string) bool {
	pl := r.placed[id]
	return pl != nil && pl.fate == kept
}

// forced returns the fate an entry takes from the group it belongs to,
// when the group's head was left out: a call's records with the call, a
// run's end with its start, a cancel notice with the link it names, and
// a response with the items it envelopes, when every one of them was
// left out. It returns 0 for an entry whose fate is its own to decide.
func (r *redaction) forced(e agentsession.Entry) fate {
	switch v := e.(type) {
	case *agentsession.ItemEntry:
		if out, ok := v.Item.(*openresponses.FunctionCallOutput); ok {
			return r.leftFate(r.callOf(e, out.CallID, ""))
		}
	case *agentsession.DispatchEntry:
		return r.leftFate(r.callOf(e, v.CallID, v.Target))
	case *agentsession.DecisionEntry:
		return r.leftFate(r.callOf(e, v.CallID, v.Target))
	case *agentsession.LinkEntry:
		if v.Rel != agentsession.RelSubsession && v.Rel != agentsession.RelPeer {
			return 0
		}
		if v.Cancel != "" && v.Target != "" {
			if f := r.leftFate(v.Target); f != 0 {
				return f
			}
		}
		return r.leftFate(r.callOf(e, v.CallID, ""))
	case *agentsession.CustomEntry:
		return r.leftFate(r.callOf(e, v.CallID, ""))
	case *agentsession.RunEntry:
		if v.IsEnd() {
			return r.leftFate(r.runStart(e))
		}
	case *agentsession.ResponseEntry:
		outs := agentsession.OutputEntries(r.original.Path(v.ID), v)
		if len(outs) == 0 {
			return 0
		}
		how := omitted
		for _, o := range outs {
			f := r.leftFate(o.ID)
			if f == 0 {
				return 0
			}
			if f == folded {
				how = folded
			}
		}
		return how
	}
	return 0
}

// mayLeaveOut refuses to leave out, on its own, an entry the format
// does not let a redaction leave out while it keeps what it belongs
// with.
func (r *redaction) mayLeaveOut(e agentsession.Entry) error {
	switch v := e.(type) {
	case *agentsession.ConfigEntry:
		return ErrLeavesOutConfig
	case *agentsession.ItemEntry:
		if out, ok := v.Item.(*openresponses.FunctionCallOutput); ok && r.isKept(r.callOf(e, out.CallID, "")) {
			return fmt.Errorf("%w: an output of a call that is kept", ErrSplitsCall)
		}
	case *agentsession.DispatchEntry:
		if r.isKept(r.callOf(e, v.CallID, v.Target)) {
			return fmt.Errorf("%w: a dispatch of a call that is kept", ErrSplitsCall)
		}
	case *agentsession.DecisionEntry:
		if r.isKept(r.callOf(e, v.CallID, v.Target)) {
			return fmt.Errorf("%w: a decision on a call that is kept", ErrSplitsCall)
		}
	case *agentsession.LinkEntry:
		if (v.Rel == agentsession.RelSubsession || v.Rel == agentsession.RelPeer) && r.isKept(r.callOf(e, v.CallID, "")) {
			return fmt.Errorf("%w: a link of a call that is kept", ErrSplitsCall)
		}
	case *agentsession.ResponseEntry:
		for _, o := range agentsession.OutputEntries(r.original.Path(v.ID), v) {
			if r.isKept(o.ID) {
				return ErrSplitsResponse
			}
		}
	case *agentsession.RunEntry:
		if v.IsEnd() && r.isKept(r.runStart(e)) {
			return ErrSplitsRun
		}
	}
	return nil
}

// callOf returns the ID of the function call entry the record e belongs
// to, as a reader binds it: the entry target names, when it is a
// function call on e's path, and otherwise the latest function call
// before e on its path with callID. It returns "" for none.
func (r *redaction) callOf(e agentsession.Entry, callID, target string) string {
	if callID == "" && target == "" {
		return ""
	}
	path := r.original.Path(e.Base().ID)
	if target != "" {
		for _, p := range path {
			if p.Base().ID == target && isFunctionCall(p) {
				return target
			}
		}
	}
	if callID == "" {
		return ""
	}
	for i := len(path) - 2; i >= 0; i-- {
		if it, ok := path[i].(*agentsession.ItemEntry); ok {
			if fc, ok := it.Item.(*openresponses.FunctionCall); ok && fc.CallID == callID {
				return it.ID
			}
		}
	}
	return ""
}

func isFunctionCall(e agentsession.Entry) bool {
	it, ok := e.(*agentsession.ItemEntry)
	if !ok {
		return false
	}
	_, ok = it.Item.(*openresponses.FunctionCall)
	return ok
}

// runStart returns the ID of the start of the run the run end e closes
// on its path, or "".
func (r *redaction) runStart(e agentsession.Entry) string {
	for _, run := range agentsession.Runs(r.original.Path(e.Base().ID)) {
		if run.End != nil && run.End.ID == e.Base().ID {
			return run.Start.ID
		}
	}
	return ""
}

// chain applies the profile's entry redactors, in order, to body, the
// rewritten entry at pos, and returns the entries to write in its
// place: none when a structural redactor left it out, and block set
// when one folded it into a block placeholder. The blobs the redactors
// add go in kept. Replaying, nothing is reported and no blob is kept,
// since that was done when the entry was written.
func (r *redaction) chain(pos int, body agentsession.Entry, replay bool, kept map[string][]byte) ([]Made, bool, error) {
	cur := []Made{{Entry: body}}
	var (
		findings *[]Finding
		blobs    map[string][]byte
	)
	if !replay {
		findings, blobs = &r.res.Findings, kept
	}
	for _, red := range r.p.Entries {
		c := &EntryContext{Original: r.original, Order: r.order, Position: pos, redactor: redactorName(red), findings: findings, blobs: blobs}
		if sr, ok := red.(StructureRedactor); ok {
			var next []Made
			for _, m := range cur {
				out, err := sr.RedactStructure(c, m.Entry)
				if err != nil {
					return nil, false, fmt.Errorf("%s: %w", c.redactor, err)
				}
				if isBlock(out) {
					return nil, true, nil
				}
				for _, o := range out {
					if o.block || o.Entry == nil {
						return nil, false, fmt.Errorf("%s: returned Block beside other entries, or no entry", c.redactor)
					}
					o.Added = o.Added || m.Added
					next = append(next, o)
				}
			}
			if cur = next; len(cur) == 0 {
				return nil, false, nil
			}
			continue
		}
		for i := range cur {
			out, err := red.RedactEntry(c, cur[i].Entry)
			if err != nil {
				return nil, false, fmt.Errorf("%s: %w", c.redactor, err)
			}
			if out == nil || out.EntryType() != cur[i].Entry.EntryType() {
				return nil, false, fmt.Errorf("%s: returned no %s entry", c.redactor, cur[i].Entry.EntryType())
			}
			cur[i].Entry = out
		}
	}
	if cur[len(cur)-1].Added {
		return nil, false, fmt.Errorf("the last entry written in place of position %d is an added one: the entries under it hang from one made from it", pos)
	}
	seen := map[*agentsession.EntryBase]bool{}
	for _, m := range cur {
		if seen[m.Entry.Base()] {
			return nil, false, errors.New("the redactors returned one entry twice")
		}
		seen[m.Entry.Base()] = true
	}
	return cur, false, nil
}

// standIn returns the ID of the redacted entry an entry under the
// original's entry parent hangs from: the last entry written in parent's
// place, or, when parent was left out, in its nearest ancestor's. A run
// of folded entries between them is closed here: its block placeholder
// is written, or, replaying, matched, under that entry, and the entry
// hangs from the placeholder. "" is a root.
func (r *redaction) standIn(parent string, replay bool) (string, error) {
	var run []string // folded entries whose run this closes, nearest first
	stand := ""
	for x := parent; x != ""; {
		pl := r.placed[x]
		if pl == nil {
			return "", fmt.Errorf("its parent %s is not an entry of the original before it", x)
		}
		if pl.last != "" {
			stand = pl.last
			break
		}
		if pl.fate == folded {
			run = append(run, x)
		}
		x = r.parentOf(x)
	}
	if len(run) == 0 {
		return stand, nil
	}
	slices.Reverse(run)
	positions := make([]int, len(run))
	for i, x := range run {
		positions[i] = r.placed[x].pos
	}
	spans := spansOf(positions)
	top, _ := r.original.Entry(run[0])
	ph, err := blockPlaceholder(len(run))
	if err != nil {
		return "", err
	}
	ph.Timestamp = top.Base().Timestamp // what it replaces, never a clock
	ph.Parent = stand
	if err := agentsession.SetRedacted(ph, spans); err != nil {
		return "", err
	}
	var id string
	if replay {
		id, err = r.match(spans, agentsession.TypeCustom, stand, 0)
	} else {
		id, err = r.commit(ph, nil, 0)
	}
	if err != nil {
		return "", err
	}
	for _, x := range run {
		r.placed[x].first, r.placed[x].last = id, id
	}
	return id, nil
}

// blockPlaceholder is the entry standing for n entries left out.
func blockPlaceholder(n int) (*agentsession.CustomEntry, error) {
	data, err := json.Marshal(struct {
		Redacted string `json:"redacted"`
		Entries  int    `json:"entries"`
	}{"block", n})
	if err != nil {
		return nil, err
	}
	return &agentsession.CustomEntry{NS: PlaceholderNS, Data: data}, nil
}

// parentOf returns the parent of the original's entry id.
func (r *redaction) parentOf(id string) string {
	e, ok := r.original.Entry(id)
	if !ok {
		return ""
	}
	return e.Base().Parent
}

// place returns the redacted entry standing in the place of the
// original's entry id: the last written in its place, or, when it was
// left out with nothing written for it yet, its nearest ancestor's.
func (r *redaction) place(id string) (string, bool) {
	for id != "" {
		pl := r.placed[id]
		if pl == nil {
			return "", false
		}
		if pl.last != "" {
			return pl.last, true
		}
		id = r.parentOf(id)
	}
	return "", false
}

// match finds, replaying, the entry of the existing redaction a fresh
// one would write here: marked spans, of type typ, under parent. pos is
// the position an entry made from one is made from, 0 for a block
// placeholder.
func (r *redaction) match(spans []agentsession.Span, typ, parent string, pos int) (string, error) {
	k := markKey(spans)
	var other agentsession.Entry // an unmatched entry so marked, of another type or under another entry
	for _, h := range r.byMark[k] {
		if r.matched[h.Base().ID] {
			continue
		}
		if h.Base().Parent == parent && h.EntryType() == typ {
			r.matched[h.Base().ID] = true
			return h.Base().ID, nil
		}
		if other == nil || other.EntryType() == typ {
			other = h
		}
	}
	if other != nil && other.EntryType() != typ && pos > 0 {
		return "", fmt.Errorf("%w: %s: the entry redacted from position %d is a %s, and the original's there a %s", ErrNotThisRedaction, r.redID, pos, other.EntryType(), typ)
	}
	return "", fmt.Errorf("%w: a fresh redaction writes a %s marked [%s] here, which it does not hold", ErrResumeDiverged, typ, k)
}

// write builds the redacted entry m made from the original's entry e at
// pos, under parent, and commits it.
func (r *redaction) write(pos int, e agentsession.Entry, m Made, parent string) (string, error) {
	n := m.Entry
	if n.Base().Timestamp.IsZero() {
		n.Base().Timestamp = e.Base().Timestamp // never a clock
	}
	if err := inspect(n, r.f, pos, &r.res.Findings); err != nil {
		return "", err
	}
	override, err := r.fixRefs(e, n, parent)
	if err != nil {
		return "", err
	}
	n.Base().Parent = "" // set below; the parent is the stand-in already found
	rr, err := agentsession.RemapRefs(n, r.remap(override))
	if err != nil {
		return "", err
	}
	for _, u := range rr.Unmapped {
		if u.Entry != "" && (u.Session == "" || u.Session == r.origID) {
			return "", fmt.Errorf("%w: %s", ErrNoPlace, u.At)
		}
		r.res.Findings = append(r.res.Findings, Finding{
			Position: pos,
			At:       u.At,
			Redactor: "redact",
			Message:  "a reference into another session kept as written: it names that session's original entry or ID, which can confirm a guess, until the store pass re-points it",
		})
	}
	if rr.Opaque {
		r.res.Findings = append(r.res.Findings, Finding{
			Position: pos,
			Redactor: "redact",
			Message:  "extension entry: its parent and parents were re-pointed, but a member of its own may still name an entry of the original",
		})
	}
	n = rr.Entry
	n.Base().ID = ""
	n.Base().Parent = parent
	if err := agentsession.SetRedacted(n, markOf(pos, m.Added)); err != nil {
		return "", err
	}
	return r.commit(n, e, pos)
}

// commit commits n, made from the original's entry e at pos, or a block
// placeholder when e is nil, to the redacted session.
func (r *redaction) commit(n, e agentsession.Entry, pos int) (string, error) {
	if n.Base().Parent == "" && r.red.Len() > 0 {
		// A root: Commit puts an entry with no parent under the leaf,
		// and SetRequestHash rebuilds a response's request there.
		r.red.ResetLeaf()
	}
	if e != nil {
		switch v := n.(type) {
		case *agentsession.ResponseEntry:
			if v.RequestHash != "" && r.original.Verify(e.Base().ID) != nil {
				v.RequestHash = "" // never certify a request the original could not
			}
			if err := r.red.SetRequestHash(v); err != nil {
				return "", err
			}
		case *agentsession.RunEntry:
			r.carryRun(v, e)
		}
	}
	res, err := r.red.Commit(n)
	if err != nil {
		return "", err
	}
	if res.Outcome == agentsession.Held {
		return "", errors.New("the redacted session already holds the entry")
	}
	r.res.Entries = append(r.res.Entries, n)
	if e != nil {
		r.res.Findings = append(r.res.Findings, unmetParts(r.red, res.ID, n, pos)...)
	}
	return res.ID, nil
}

// remap re-points the references of an entry being written: a reference
// into this file to the entry standing in its place, override first.
func (r *redaction) remap(override map[string]string) agentsession.Remap {
	return agentsession.Remap{
		Entry: func(session, entry string) (string, bool) {
			if session != "" && session != r.origID {
				return "", false
			}
			if id, ok := override[entry]; ok {
				return id, true
			}
			return r.place(entry)
		},
		Session: func(id string) (string, bool) {
			if id == r.origID {
				return r.redID, true
			}
			return "", false
		},
	}
}

// fixRefs carries what was left out through the members of n, made from
// the original's entry e and to be written under parent, that name an
// entry or a call in a way [Redact]'s re-pointing does not cover: it
// removes what names an entry left out where naming the entry in its
// place would change the meaning, and returns the references whose
// stand-in is not the one in their place, by original ID.
func (r *redaction) fixRefs(e, n agentsession.Entry, parent string) (map[string]string, error) {
	b := n.Base()
	if len(b.Parents) > 0 {
		var keep []agentsession.EntryRef
		seen := map[string]bool{}
		for _, ref := range b.Parents {
			pl := r.placed[ref.Entry]
			if ref.Session != "" && ref.Session != r.origID || pl == nil {
				keep = append(keep, ref) // another session's, or none of this file: re-pointing reports it
				continue
			}
			// A converged entry left out is named by its block
			// placeholder, or removed: naming an ancestor would claim
			// work came from where it did not.
			if pl.last == "" || pl.last == parent || seen[pl.last] {
				continue
			}
			seen[pl.last] = true
			keep = append(keep, ref)
		}
		b.Parents = keep
	}
	override := map[string]string{}
	switch v := n.(type) {
	case *agentsession.ItemEntry:
		if v.QueuedFrom != "" && r.placed[v.QueuedFrom] != nil && !r.isKept(v.QueuedFrom) {
			v.QueuedFrom = "" // optional; the queued entry it names was left out
		}
	case *agentsession.ConfigEntry:
		if v.Omit != nil && r.keepItems(&v.Omit.Items) && v.Omit.Reasoning == "" && len(v.Omit.Items) == 0 {
			v.Omit = nil // it only added items, all left out; an empty omit would clear the rule in force
		}
		for _, o := range v.InstructionsOmitted {
			if o.Keep > 0 && o.ID == "" && o.Of != "" && r.placed[o.Of] != nil && !r.isKept(o.Of) {
				return nil, fmt.Errorf("%w: an omitted instructions keep counts over a config entry left out", ErrNoPlace)
			}
		}
	case *agentsession.CompactionEntry:
		oc, _ := e.(*agentsession.CompactionEntry)
		if oc == nil {
			break
		}
		target, err := r.firstKept(oc)
		if err != nil {
			return nil, err
		}
		if target != "" {
			override[oc.FirstKept] = target
		}
		if r.keepItems(&v.Config.Omit.Items) && v.Config.Omit.Reasoning == "" && len(v.Config.Omit.Items) == 0 {
			v.Config.Omit = agentsession.Omit{}
		}
		v.Pinned = r.pinned(oc, v.Pinned)
	}
	return override, nil
}

// keepItems removes from an omit list every ID that names no kept
// entry, and reports whether it removed any. An item entry left out is
// in no request, so there is nothing for the list to omit, and naming
// the entry in its place instead would omit another.
func (r *redaction) keepItems(items *[]string) bool {
	var keep []string
	for _, id := range *items {
		if r.isKept(id) {
			keep = append(keep, id)
		}
	}
	if len(keep) == len(*items) {
		return false
	}
	*items = keep
	return true
}

// firstKept returns what the compaction oc's first_kept is to name when
// that is not the entry written in its place: the first entry standing
// for one on the compaction's path from first_kept on, so the kept
// window holds what it held less what was left out; or, when every
// entry from first_kept to the compaction was left out with nothing in
// its place, the entry in first_kept's place, when it adds nothing to
// the context. Otherwise it refuses with ErrFirstKept. "" means the
// default re-pointing.
func (r *redaction) firstKept(oc *agentsession.CompactionEntry) (string, error) {
	fk := oc.FirstKept
	pl := r.placed[fk]
	if pl == nil {
		return "", nil
	}
	if pl.fate == kept {
		if pl.first != pl.last {
			return pl.first, nil
		}
		return "", nil
	}
	path := r.original.Path(oc.ID)
	i := slices.IndexFunc(path, func(e agentsession.Entry) bool { return e.Base().ID == fk })
	if i < 0 {
		return "", nil
	}
	for _, p := range path[i : len(path)-1] {
		if q := r.placed[p.Base().ID]; q != nil && q.first != "" {
			return q.first, nil
		}
	}
	if a, ok := r.place(fk); ok {
		if ent, ok := r.red.Entry(a); ok && !agentsession.InContext(ent) {
			return a, nil
		}
	}
	return "", ErrFirstKept
}

// pinned returns pins, the rewritten pinned items of the compaction oc,
// less each whose item entries before first_kept on the path were all
// left out: a pinned item is a copy of one such entry's item, so it
// leaves with them, or the redaction would keep what it left out.
func (r *redaction) pinned(oc *agentsession.CompactionEntry, pins openresponses.Items) openresponses.Items {
	if !r.leftOut || len(oc.Pinned) == 0 || len(pins) != len(oc.Pinned) {
		return pins
	}
	path := r.original.Path(oc.ID)
	i := slices.IndexFunc(path, func(e agentsession.Entry) bool { return e.Base().ID == oc.FirstKept })
	if i < 0 {
		return pins
	}
	var out openresponses.Items
	for k, pin := range oc.Pinned {
		want, err := json.Marshal(pin)
		found, keptOne := false, false
		for _, p := range path[:i] {
			it, ok := p.(*agentsession.ItemEntry)
			if !ok || err != nil {
				continue
			}
			if got, err := json.Marshal(it.Item); err == nil && bytes.Equal(got, want) {
				found = true
				keptOne = keptOne || r.isKept(it.ID)
			}
		}
		if !found || keptOne {
			out = append(out, pins[k])
		}
	}
	return out
}

// carryRun carries what was left out through the run end n, made from
// the original's e: when the original's run verified, n's pending list
// becomes the calls pending on the redacted segment, and a reason the
// segment decides becomes the one the redacted segment reads, so the
// redacted run verifies as the original's did.
func (r *redaction) carryRun(n *agentsession.RunEntry, e agentsession.Entry) {
	if !n.IsEnd() || !r.leftOut {
		return
	}
	var orig *agentsession.Run
	for _, run := range agentsession.Runs(r.original.Path(e.Base().ID)) {
		if run.End != nil && run.End.ID == e.Base().ID {
			orig = run
		}
	}
	if orig == nil || orig.Verify() != nil {
		return
	}
	path := append(slices.Clone(r.red.Path(n.Parent)), agentsession.Entry(n))
	var run *agentsession.Run
	for _, x := range agentsession.Runs(path) {
		if x.End == n {
			run = x
		}
	}
	if run == nil {
		return
	}
	want := map[string]bool{}
	for _, id := range run.Pending() {
		want[id] = true
	}
	pending := []string{}
	for _, id := range n.Pending {
		if want[id] {
			pending = append(pending, id)
		}
	}
	n.Pending = pending
	if n.Reason != agentsession.ReasonError && n.Reason != agentsession.ReasonInterrupted {
		n.Reason = agentsession.ComputeReason(run.Path, run.Segment)
	}
}

// unmatched refuses an existing redaction holding an entry the replay
// did not match: one a fresh redaction does not write.
func (r *redaction) unmatched() error {
	for _, h := range r.held {
		if !r.matched[h.Base().ID] {
			spans, _ := agentsession.RedactedOf(h)
			return fmt.Errorf("%w: it holds entry %s, marked %s, which a fresh redaction does not write", ErrResumeDiverged, h.Base().ID, markKey(spans))
		}
	}
	return nil
}

// checkRecords holds a redaction that left something out to the rules
// on records wherever the original kept them: for each leaf of the
// redacted session made from an entry of the original, the records on
// its path verify when the original's path to that entry does.
func (r *redaction) checkRecords() error {
	if !r.leftOut {
		return nil
	}
	for _, leaf := range r.red.Leaves() {
		le, _ := r.red.Entry(leaf)
		spans, ok := agentsession.RedactedOf(le)
		if !ok || len(spans) == 0 {
			continue
		}
		pos := spans[len(spans)-1].To
		oe := r.order[pos-1]
		if r.original.VerifyRecords(oe.Base().ID) != nil {
			continue
		}
		if err := r.red.VerifyRecords(leaf); err != nil {
			return entryErr(r.origID, pos, oe, fmt.Errorf("%w: %w", ErrBreaksRecords, err))
		}
	}
	return nil
}

// markOf is the redacted member of an entry made from pos, or of one
// added.
func markOf(pos int, added bool) []agentsession.Span {
	if added {
		return []agentsession.Span{}
	}
	return []agentsession.Span{{From: pos, To: pos}}
}

// spansOf writes ascending positions as a redacted member: a range for
// each run of consecutive positions, a position for one alone.
func spansOf(positions []int) []agentsession.Span {
	var out []agentsession.Span
	for _, p := range positions {
		if n := len(out); n > 0 && out[n-1].To == p-1 {
			out[n-1].To = p
			continue
		}
		out = append(out, agentsession.Span{From: p, To: p})
	}
	return out
}

// markKey writes a redacted member as a key: "3", "3,5-7", "" for [].
func markKey(spans []agentsession.Span) string {
	var b strings.Builder
	for i, sp := range spans {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(sp.From))
		if sp.To != sp.From {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(sp.To))
		}
	}
	return b.String()
}
