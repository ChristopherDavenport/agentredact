package agentredact

import (
	"errors"
	"fmt"

	"github.com/ChristopherDavenport/agentsession"
)

// Origin is the redaction a fork is redacted as a fork of: see
// [WithOrigin].
type Origin struct {
	// Original is the fork's origin, the session its parent_session
	// names, as it was redacted.
	Original *agentsession.Session
	// Redaction is Original's redaction under the same profile, as
	// [Redact] returned it or a store holds it, up to date with
	// Original at least as far as the fork's base. Redact reads it and
	// writes nothing to it.
	Redaction *agentsession.Session
	// Origin is Original's own origin when Redaction is itself a fork
	// of a redaction, and nil when Redaction has no base.
	Origin *Origin
}

// WithOrigin has [Redact] redact the original, a fork, as a fork of its
// origin's redaction, o.Redaction, rather than without a base. The
// redaction's header has as its base the entry standing for the
// original's base in o.Redaction, and as its parent_session
// o.Redaction's ID. Its prefix is o.Redaction's path to that entry,
// shared and never redacted again, whose positions count in the
// origin's original, as RFC 0001 has a fork's prefix count. Its own
// entries are made from the original's own entries, and their positions
// count in the original's file order, prefix included, so the first own
// entry of a fork whose prefix holds k entries is made from position
// k+1 or later.
//
// What o.Redaction made of each prefix entry is what the fork's own
// entries build on: an own entry under a prefix entry it kept hangs
// from the entry written in its place; one under a run of prefix
// entries it folded into a block placeholder, where the run is closed
// by none of the origin's own entries up to the base, hangs from a
// placeholder of the fork's own, marked with the run's positions in the
// fork's file order. Redact decides those fates by replaying
// o.Original's redaction up to the base, in file order, so they depend
// on what the origin holds up to the base alone and stay as both grow.
// The replay finds in o.Redaction every entry a fresh redaction writes
// up to the base, and refuses one that lacks any with
// [ErrOriginBehind]. Where o.Redaction is itself a fork, o.Origin is
// its origin, and so on up the line.
//
// The profile's session redactors are asked about the whole original,
// as without an origin, but their choices for the prefix are not read:
// the origin's redaction made those. A base the origin's redaction left
// out on a branch a session redactor dropped, or with nothing kept above
// it, has no entry standing for it, and Redact refuses with
// [ErrBaseLeftOut]; such a fork is redacted without an origin instead.
//
// An existing redaction given to Redact with an origin must be a fork
// of o.Redaction at the same base, and one given without must have no
// base, or Redact refuses with [ErrNotThisRedaction]. So a redaction
// keeps the mode it was first written in, and resumes in it.
//
// The origin counts as redacted alongside: a reference to it names
// o.Redaction, and a parents element naming one of its entries is
// re-pointed through the [Alongside] entries given for it, and refused
// with [ErrUnmappedRef] when none are. The Alongside given with the
// origin must tell what it told when o.Redaction was written, since the
// replay rebuilds its entries.
func WithOrigin(o *Origin) Option {
	return func(opts *options) { opts.origin = o }
}

// ErrBaseLeftOut is returned by [Redact] with [WithOrigin] for a fork
// whose base nothing stands for in the origin's redaction: the base, or
// an entry above it, is on a branch the origin's session redactors left
// out, or every entry from the base up was left out with nothing in its
// place. Redact the fork without an origin instead.
var ErrBaseLeftOut = errors.New("agentredact: the origin's redaction has nothing standing for the fork's base")

// ErrOriginBehind is returned by [Redact] with [WithOrigin] when the
// origin's redaction does not hold everything a fresh redaction of the
// origin writes up to the fork's base: bring it up to date first.
var ErrOriginBehind = errors.New("agentredact: the origin's redaction does not reach the fork's base")

// forkFrom makes r a redaction of its original, a fork, as a fork of
// o.Redaction: it decides the prefix's fates by replaying the origin's
// redaction up to the base, and the base the redaction forks at.
func (r *redaction) forkFrom(o *Origin) error {
	h := r.original.Header()
	switch {
	case h.Base == "":
		return fmt.Errorf("agentredact: %s has no base: only a fork is redacted as a fork of its origin's redaction", r.origID)
	case o.Original == nil || o.Redaction == nil:
		return errors.New("agentredact: an origin needs its original and its redaction")
	case h.ParentSession != o.Original.ID():
		return fmt.Errorf("agentredact: %s is a fork of %q, not of %s", r.origID, h.ParentSession, o.Original.ID())
	}
	state, err := originState(r.p, o, h.Base, r.along)
	if err != nil {
		return fmt.Errorf("agentredact: %s as a fork of %s: %w", r.origID, o.Redaction.ID(), err)
	}
	for i, e := range r.order {
		id := e.Base().ID
		if !r.original.Prefix(id) {
			break
		}
		pl := state[id]
		if pl == nil {
			return fmt.Errorf("agentredact: %s: prefix entry %s is not one the origin's redaction decided", r.origID, id)
		}
		if pl.fate == dropped {
			return fmt.Errorf("%w: prefix entry %s is on a branch the origin's session redactors left out", ErrBaseLeftOut, id)
		}
		// The fate is the origin's; the position is this file's, which a
		// placeholder of this redaction's own names.
		r.placed[id] = &placed{fate: pl.fate, pos: i + 1, first: pl.first, last: pl.last}
		if pl.fate != kept {
			r.leftOut = true
		}
		r.prefixLen = i + 1
	}
	if r.prefixLen == 0 || r.order[r.prefixLen-1].Base().ID != h.Base {
		return fmt.Errorf("agentredact: %s: its prefix does not end at its base %s", r.origID, h.Base)
	}
	base, ok := r.place(h.Base)
	if !ok || base == "" {
		return fmt.Errorf("%w: every entry from the base up was left out with nothing in its place", ErrBaseLeftOut)
	}
	r.fork, r.base = true, base
	r.originID, r.originRedID = o.Original.ID(), o.Redaction.ID()
	return nil
}

// originState replays the redaction of o.Original into o.Redaction up
// to the entry base, and returns what it made of each entry up to
// there. Nothing is written to o.Redaction.
func originState(p Profile, o *Origin, base string, along Alongside) (map[string]*placed, error) {
	r := newRedaction(p, o.Original, along)
	if o.Origin != nil {
		if err := r.forkFrom(o.Origin); err != nil {
			return nil, err
		}
	}
	pos := 0
	for i, e := range r.order {
		if e.Base().ID == base {
			pos = i + 1
			break
		}
	}
	if pos == 0 {
		return nil, fmt.Errorf("%w: the origin %s does not hold the base %s", agentsession.ErrNoEntry, r.origID, base)
	}
	if err := r.resume(o.Redaction); err != nil {
		return nil, err
	}
	r.red = o.Redaction
	r.res = &Result{Session: r.red, Blobs: map[string][]byte{}}
	var err error
	if r.out, err = r.sessions(); err != nil {
		return nil, err
	}
	if err := r.checkSessions(r.out); err != nil {
		return nil, err
	}
	r.lastTS = o.Original.Header().CreatedAt
	behind := r.done < pos
	r.done = max(r.done, pos) // replay it all: never write to the origin's redaction
	if err := r.walk(pos, false); err != nil {
		if behind && errors.Is(err, ErrResumeDiverged) {
			return nil, fmt.Errorf("%w: %w", ErrOriginBehind, err)
		}
		return nil, err
	}
	return r.placed, nil
}
