package agentredact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/ChristopherDavenport/agentsession"
)

// BlobWriter is implemented by a store that takes media blobs, as the
// cas store does: PutBlob stores data under its hash, sha256:<hex>, and
// returns the hash. [RedactStore] writes through it the blobs a
// redaction made ([Result.Blobs]) before the entries that name them.
type BlobWriter interface {
	PutBlob(ctx context.Context, data []byte) (string, error)
}

// ErrNoBlobWriter is reported by [RedactStore] for a session whose
// redaction made blobs, such as the replacement for a sidecar image,
// in a store that takes none ([BlobWriter]): the redaction is not
// written, since its entries would name blobs the store does not hold.
var ErrNoBlobWriter = errors.New("agentredact: the store takes no blobs, and the redaction names blobs it made")

// ErrNoImporter is reported by [RedactStore] for a session whose
// redaction is new, in a store that cannot import a session whole
// ([agentsession.Importer]).
var ErrNoImporter = errors.New("agentredact: the store cannot import a session")

// ErrDependency is reported by [RedactStore] for a session it did not
// redact because a session it depends on was not redacted: its fork's
// origin, or a session one of its parents elements names.
var ErrDependency = errors.New("agentredact: a session this one depends on was not redacted")

// ErrCycle is reported by [RedactStore] for sessions that depend on
// each other, or on such sessions. Content addressing makes that
// impossible for references that name entries their writer held, so a
// cycle means a reference names an entry it could not have seen.
var ErrCycle = errors.New("agentredact: sessions depend on each other")

// StoreOptions are the options of [RedactStore].
type StoreOptions struct {
	// Select chooses, by its header, each original to redact; nil
	// chooses every one. The sessions a chosen one depends on are
	// redacted too, chosen or not: its fork's origin, and each session
	// one of its parents elements names.
	Select func(agentsession.Header) bool
}

// StoreReport is what [RedactStore] did.
type StoreReport struct {
	// Profile is the profile's name.
	Profile string
	// Sessions are the originals it redacted or tried to, in the order
	// it took them.
	Sessions []SessionReport
	// Skipped counts the sessions the store holds that are redactions
	// themselves, under any profile, which are never redacted again.
	Skipped int
}

// SessionReport is what [RedactStore] did with one original.
type SessionReport struct {
	// Original is the original's ID.
	Original string
	// Redaction is its redaction's ID,
	// [agentsession.RedactedSessionID] of the original and the profile.
	Redaction string
	// Fork says the redaction is a fork of its origin's redaction (see
	// [WithOrigin]); a fork redacted otherwise has no base.
	Fork bool
	// Created says the redaction was new, and imported whole.
	Created bool
	// Written counts the redaction's own entries written: all of them
	// when Created, and those appended otherwise.
	Written int
	// Blobs counts the blobs written ([Result.Blobs]).
	Blobs int
	// UpToDate says nothing was written: the redaction held everything
	// the original did.
	UpToDate bool
	// Native counts the redaction's own entries that carry no redacted:
	// appended natively, by a writer who resumed the redaction. A store
	// set to hold only redacted entries refuses such a session, so it
	// is not to be published until those entries are redacted too.
	Native int
	// Findings are what the redaction wrote without redacting, from
	// this run's entries and, when Created, its header: see [Finding].
	// They hold no values.
	Findings []Finding
	// Err is why the session was not redacted, or not wholly written.
	// It wraps [ErrDependency] for one stopped because a session it
	// depends on failed, and errors.Is finds every sentinel below it.
	Err error
}

// Publishable reports whether the redaction is written and holds no
// native entries, so a store set to hold only redacted entries takes
// it. It says nothing of what the scan and the review will find.
func (r SessionReport) Publishable() bool { return r.Err == nil && r.Native == 0 }

// RedactStore keeps a redaction under the profile p of each original
// the store st holds, in st: it creates the redactions that are missing
// and appends to the others what their originals have appended since,
// with [Redact]. A rerun when no original has grown writes nothing.
//
// It lists every session in st. A session that is itself redacted is
// skipped, whatever its profile: a redaction is never redacted. Every
// other is an original. It reads the originals opts.Select chooses,
// and those they depend on, through [agentsession.Reader] where st
// implements it, as a snapshot, and redacts each after every session
// its entries hash over: a fork's origin, and each session a parents
// element names. No other order is needed, since every redaction's ID
// is derived and known up front.
//
// References into another original the store holds point at its
// redaction under p ([Alongside]): parent_session, a link's session,
// and a parents element's session and entry, which is why a session
// comes after those its parents elements name. A reference to a
// session the store does not hold stays as written and is reported as
// a [Finding]. A reference to an original outside the selection is
// re-pointed too, to the redaction that session has once it is
// redacted; so a selection changes what is written for no session.
//
// A fork whose origin is redacted alongside is redacted as a fork of
// the origin's redaction ([WithOrigin]), sharing its prefix, unless
// nothing in the origin's redaction stands for its base
// ([ErrBaseLeftOut]), when it is redacted without a base. An existing
// redaction resumes in the mode it was written in.
//
// For each original, RedactStore reads its redaction, when st holds
// one, as a snapshot, and runs Redact on the two. It writes what Redact
// made: the blobs first, through st's [BlobWriter], and then a new
// redaction whole, through st's [agentsession.Importer], with asRecord
// set, as the store is its record; or the entries Redact appended to an
// existing one ([Result.Entries]), each with [agentsession.Store.Append]
// in order, their IDs set, which the store checks. A redaction that
// made blobs in a store that takes none is not written
// ([ErrNoBlobWriter]). Then it lets the redaction go where st has a
// Release(id) method, as the jsonl and cas stores do, so a store over
// many sessions does not keep each one open; a caller that holds one of
// them open through the same store opens it again.
//
// A session that fails is reported with the error in
// [SessionReport.Err], and the sessions that depend on it, directly or
// through others, are not redacted and report [ErrDependency]; every
// other session is redacted as if it had not failed. An append that
// fails part way leaves the redaction holding the entries before it,
// which the next run resumes from. The error returned joins every
// session's error, and is nil when each was redacted; the report is
// returned either way, with what was done. A listing that fails, or a
// context that ends, stops the pass, and the report holds what was done
// before.
func RedactStore(ctx context.Context, st agentsession.Store, p Profile, opts StoreOptions) (*StoreReport, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("agentredact: no store")
	}
	ps := &pass{
		st:     st,
		p:      p,
		report: &StoreReport{Profile: p.Name},
		heads:  map[string]agentsession.Header{},
		snaps:  map[string]*agentsession.Session{},
		reds:   map[string]*agentsession.Session{},
		chains: map[string]*Origin{},
		failed: map[string]error{},
		along:  Alongside{Sessions: map[string]string{}, Entries: map[string]map[string]string{}},
	}
	if err := ps.list(ctx); err != nil {
		return ps.report, err
	}
	order, err := ps.plan(ctx, opts.Select)
	if err != nil {
		return ps.report, err
	}
	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return ps.report, err
		}
		rp := ps.one(ctx, id)
		ps.report.Sessions = append(ps.report.Sessions, rp)
		if rp.Err != nil {
			ps.failed[id] = rp.Err
		}
		ps.done(id)
	}
	var errs []error
	for _, rp := range ps.report.Sessions {
		if rp.Err != nil {
			errs = append(errs, fmt.Errorf("agentredact: session %s: %w", rp.Original, rp.Err))
		}
	}
	return ps.report, errors.Join(errs...)
}

// pass is one run of [RedactStore].
type pass struct {
	st     agentsession.Store
	p      Profile
	report *StoreReport
	// heads are the originals the store holds, by ID.
	heads map[string]agentsession.Header
	// snaps are the snapshots of the originals still needed: to be
	// redacted, or the origin of a fork still to be redacted.
	snaps map[string]*agentsession.Session
	// reds are the redactions written, while a fork of theirs is still
	// to be redacted; chains, the origin each was redacted as a fork of.
	reds   map[string]*agentsession.Session
	chains map[string]*Origin
	// deps are each session's dependencies, and forks counts the forks
	// still to be redacted of each.
	deps  map[string][]string
	forks map[string]int
	// failed are the sessions not redacted, with why.
	failed map[string]error
	along  Alongside
}

// list reads every header the store lists: the originals, and the
// redactions, which are counted and skipped.
func (ps *pass) list(ctx context.Context) error {
	for sum, err := range ps.st.List(ctx, agentsession.ListFilter{}) {
		if err != nil {
			return fmt.Errorf("agentredact: listing the store: %w", err)
		}
		h := sum.Header
		if h.Redacted {
			ps.report.Skipped++
			continue
		}
		ps.heads[h.ID] = h
		ps.along.Sessions[h.ID] = agentsession.RedactedSessionID(h.ID, ps.p.Name)
	}
	return nil
}

// plan reads the chosen originals and those they depend on, and orders
// them so each comes after its dependencies. A session it cannot read,
// or one in a cycle or depending on one, is reported and left out of
// the order.
func (ps *pass) plan(ctx context.Context, sel func(agentsession.Header) bool) ([]string, error) {
	ids := make([]string, 0, len(ps.heads))
	for id, h := range ps.heads {
		if sel == nil || sel(h) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	ps.deps = map[string][]string{}
	ps.forks = map[string]int{}
	work := map[string]bool{}
	for len(ids) > 0 {
		id := ids[0]
		ids = ids[1:]
		if work[id] {
			continue
		}
		work[id] = true
		s, err := readHeld(ctx, ps.st, id)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			ps.fail(id, fmt.Errorf("agentredact: reading the original: %w", err))
			continue
		}
		ps.snaps[id] = s
		deps := ps.dependencies(s)
		ps.deps[id] = deps
		ids = append(ids, deps...)
	}
	// Kahn's algorithm, taking the ready sessions by ID so the order is
	// the same on every run.
	waiting := map[string]int{}
	users := map[string][]string{}
	for id := range work {
		for _, d := range ps.deps[id] {
			waiting[id]++
			users[d] = append(users[d], id)
		}
	}
	var ready, order []string
	for id := range work {
		if waiting[id] == 0 {
			ready = append(ready, id)
		}
	}
	for len(ready) > 0 {
		sort.Strings(ready)
		id := ready[0]
		ready = ready[1:]
		if _, unread := ps.failed[id]; !unread {
			order = append(order, id)
		}
		for _, u := range users[id] {
			if waiting[u]--; waiting[u] == 0 {
				ready = append(ready, u)
			}
		}
	}
	var cyclic []string
	for id := range work {
		if waiting[id] > 0 {
			cyclic = append(cyclic, id)
		}
	}
	sort.Strings(cyclic)
	for _, id := range cyclic {
		ps.fail(id, fmt.Errorf("%w: it is in a cycle of dependencies, or depends on one", ErrCycle))
	}
	// A session that could not be read is reported where it would have
	// been taken; those that depend on it report it when their turn comes.
	for _, id := range order {
		if h := ps.heads[id]; h.Base != "" && ps.isOrigin(id, h.ParentSession) {
			ps.forks[h.ParentSession]++
		}
	}
	return order, nil
}

// fail reports the original id as not redacted, for err.
func (ps *pass) fail(id string, err error) {
	ps.failed[id] = err
	ps.report.Sessions = append(ps.report.Sessions, SessionReport{Original: id, Redaction: ps.along.Sessions[id], Err: err})
}

// dependencies are the originals s's entries hash over: its origin,
// when it is a fork of an original the store holds, and every original
// a parents element names, other than s.
func (ps *pass) dependencies(s *agentsession.Session) []string {
	own := s.ID()
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || id == own || seen[id] {
			return
		}
		if _, held := ps.heads[id]; !held {
			return // not the store's: its references stay as written
		}
		seen[id] = true
		out = append(out, id)
	}
	if h := s.Header(); h.Base != "" {
		add(h.ParentSession)
	}
	for _, e := range s.Entries() {
		for _, ref := range e.Base().Parents {
			add(ref.Session)
		}
	}
	sort.Strings(out)
	return out
}

// isOrigin reports whether parent, which id depends on, is the origin
// id is a fork of.
func (ps *pass) isOrigin(id, parent string) bool {
	for _, d := range ps.deps[id] {
		if d == parent {
			return true
		}
	}
	return false
}

// done lets go of what no session still to be redacted needs: the
// snapshot of id, and those of its origin once its last fork is done.
func (ps *pass) done(id string) {
	if h := ps.heads[id]; h.Base != "" && ps.isOrigin(id, h.ParentSession) {
		if ps.forks[h.ParentSession]--; ps.forks[h.ParentSession] <= 0 {
			ps.drop(h.ParentSession)
		}
	}
	if ps.forks[id] <= 0 {
		ps.drop(id)
	}
}

func (ps *pass) drop(id string) {
	delete(ps.snaps, id)
	delete(ps.reds, id)
	delete(ps.chains, id)
}

// one redacts the original id and writes the result.
func (ps *pass) one(ctx context.Context, id string) SessionReport {
	rp := SessionReport{Original: id, Redaction: ps.along.Sessions[id]}
	for _, d := range ps.deps[id] {
		if _, bad := ps.failed[d]; bad {
			rp.Err = fmt.Errorf("%w: %s was not redacted", ErrDependency, d)
			return rp
		}
	}
	orig := ps.snaps[id]
	existing, err := readHeld(ctx, ps.st, rp.Redaction)
	switch {
	case errors.Is(err, agentsession.ErrNoSession):
		existing = nil
	case err != nil:
		rp.Err = fmt.Errorf("agentredact: reading the redaction %s: %w", rp.Redaction, err)
		return rp
	}
	h := orig.Header()
	var origin *Origin
	switch {
	case existing != nil && existing.Header().Base != "":
		if origin = ps.origin(h); origin == nil {
			rp.Err = fmt.Errorf("%w: %s is a fork of a redaction, and the fork's origin %q is not an original the store holds", ErrNotThisRedaction, rp.Redaction, h.ParentSession)
			return rp
		}
	case existing == nil && h.Base != "":
		origin = ps.origin(h) // nil: redacted without a base
	}
	opts := []Option{WithAlongside(ps.along)}
	if origin != nil {
		opts = append(opts, WithOrigin(origin))
	}
	res, err := Redact(ps.p, orig, existing, opts...)
	if err != nil && existing == nil && origin != nil && errors.Is(err, ErrBaseLeftOut) {
		origin = nil
		res, err = Redact(ps.p, orig, nil, WithAlongside(ps.along))
	}
	if err != nil {
		rp.Err = err
		return rp
	}
	red := res.Session
	rp.Fork = red.Header().Base != ""
	rp.Findings = res.Findings
	for _, e := range red.Entries() {
		if _, marked := agentsession.RedactedOf(e); !marked && !red.Prefix(e.Base().ID) {
			rp.Native++
		}
	}
	if err := ps.write(ctx, &rp, existing == nil, res); err != nil {
		rp.Err = err
		return rp
	}
	rp.UpToDate = !rp.Created && rp.Written == 0 && rp.Blobs == 0
	ps.along.Entries[id] = res.Counterparts
	if ps.forks[id] > 0 {
		ps.reds[id], ps.chains[id] = red, origin
	}
	return rp
}

// origin is the origin a fork of an original redacted alongside is
// redacted as a fork of, or nil when its origin was not redacted in
// this pass or does not hold its base.
func (ps *pass) origin(h agentsession.Header) *Origin {
	o, red := ps.snaps[h.ParentSession], ps.reds[h.ParentSession]
	if o == nil || red == nil {
		return nil
	}
	if _, ok := o.Entry(h.Base); !ok {
		return nil
	}
	return &Origin{Original: o, Redaction: red, Origin: ps.chains[h.ParentSession]}
}

// write stores what Redact made of one original: its blobs, then the
// redaction whole when it is new, or the entries appended to it.
func (ps *pass) write(ctx context.Context, rp *SessionReport, created bool, res *Result) error {
	if len(res.Blobs) > 0 {
		bw, ok := ps.st.(BlobWriter)
		if !ok {
			return fmt.Errorf("%w: %d blobs", ErrNoBlobWriter, len(res.Blobs))
		}
		hashes := make([]string, 0, len(res.Blobs))
		for h := range res.Blobs {
			hashes = append(hashes, h)
		}
		sort.Strings(hashes)
		for _, want := range hashes {
			got, err := bw.PutBlob(ctx, res.Blobs[want])
			if err != nil {
				return fmt.Errorf("agentredact: writing blob %s: %w", want, err)
			}
			if got != want {
				return fmt.Errorf("agentredact: the store holds blob %s as %s", want, got)
			}
			rp.Blobs++
		}
	}
	if created {
		im, ok := ps.st.(agentsession.Importer)
		if !ok {
			return ErrNoImporter
		}
		var buf bytes.Buffer
		if err := agentsession.Write(&buf, res.Session); err != nil {
			return err
		}
		if _, err := im.Import(ctx, &buf, true); err != nil {
			return fmt.Errorf("agentredact: importing the redaction %s: %w", rp.Redaction, err)
		}
		rp.Created, rp.Written = true, len(res.Entries)
	} else {
		for _, e := range res.Entries {
			own, err := clone(e)
			if err != nil {
				return err
			}
			got, err := ps.st.Append(ctx, rp.Redaction, own)
			if err != nil {
				return fmt.Errorf("agentredact: appending to the redaction %s: %w", rp.Redaction, err)
			}
			if got != e.Base().ID {
				return fmt.Errorf("agentredact: the store appended %s as %s", e.Base().ID, got)
			}
			rp.Written++
		}
	}
	if rl, ok := ps.st.(interface{ Release(id string) error }); ok && (rp.Created || rp.Written > 0) {
		if err := rl.Release(rp.Redaction); err != nil {
			return fmt.Errorf("agentredact: releasing the redaction %s: %w", rp.Redaction, err)
		}
	}
	return nil
}

// readHeld reads the session id from st without a hold where st can,
// and opens it otherwise.
func readHeld(ctx context.Context, st agentsession.Store, id string) (*agentsession.Session, error) {
	if r, ok := st.(agentsession.Reader); ok {
		return r.Read(ctx, id)
	}
	return st.Open(ctx, id)
}
