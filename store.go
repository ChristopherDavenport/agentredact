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

// ErrRootAppend is reported by [RedactStore] for a redaction that grew
// a new root: an entry whose ancestors in the original were all left
// out with nothing in their place, appended after the redaction was
// first written. A store's Append fills an empty parent from the
// store's leaf, so no store appends a root to a session it holds;
// nothing is written for the session, and every run reports it until
// agentsession appends one.
var ErrRootAppend = errors.New("agentredact: the redaction grew a new root, which a store cannot append")

// ErrDependency is reported by [RedactStore] for a session it did not
// redact because a session it depends on failed: its fork's origin, or
// a session one of its parents elements names.
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
	// AcceptFindings are the kinds of finding a redaction may hold and
	// still be publishable ([SessionReport.Publishable]). None are by
	// default: whoever accepts a kind has decided that what it names may
	// leave.
	AcceptFindings []FindingKind
}

// StoreReport is what [RedactStore] did.
type StoreReport struct {
	// Profile is the profile's name.
	Profile string
	// Sessions are the originals it redacted, or tried to or waited on,
	// in the order it took them.
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
	// [WithOrigin]); a fork whose base that redaction left out has no
	// base.
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
	// WaitingOn names the session this one waits on, when it was not
	// redacted this run and nothing was written for it: a session the
	// store does not hold, or not in a form this run can use, that a
	// parents element of it names or that is its fork's origin; or a
	// session it depends on that waits itself. Waiting is not a failure:
	// once that session arrives a later run redacts this one, and until
	// then every run reports it.
	WaitingOn string
	// Native counts the redaction's own entries that carry no redacted:
	// appended natively, by a writer who resumed the redaction. A store
	// set to hold only redacted entries refuses such a session, so it
	// is not to be published until those entries are redacted too. It
	// counts what the redaction held when this run read it, at this
	// session's turn: a native append after that is not counted.
	Native int
	// Findings are what the whole redaction holds unredacted, recounted
	// on every run, so the latest report says it all: see [Finding].
	// They hold no values.
	Findings []Finding
	// Warnings are what went wrong after the redaction was written,
	// which does not undo the write: a Release that failed, or a head
	// that could not be set.
	Warnings []string
	// Err is why the session was not redacted, or not wholly written.
	// It wraps [ErrDependency] for one stopped because a session it
	// depends on failed, and errors.Is finds every sentinel below it.
	// Its message names no entry by a hash.
	Err error

	accept map[FindingKind]bool
}

// Publishable reports whether the redaction is written and up to date
// with the original as this run read it, holds no native entries, and
// holds no finding but of a kind [StoreOptions.AcceptFindings] accepts.
// A store set to hold only redacted entries then takes it. It holds for
// the redaction as this run read it, and says nothing of what the scan
// and the review will find.
func (r SessionReport) Publishable() bool {
	if r.Err != nil || r.WaitingOn != "" || r.Native > 0 {
		return false
	}
	for _, f := range r.Findings {
		if !r.accept[f.Kind] {
			return false
		}
	}
	return true
}

// RedactStore keeps a redaction under the profile p of each original
// the store st holds, in st: it creates the redactions that are missing
// and appends to the others what their originals have appended since,
// with [Redact]. A rerun when no original has grown writes nothing.
//
// It lists every session in st. A session that is itself redacted is
// skipped, whatever its profile: a redaction is never redacted. Every
// other is an original. It plans with the originals opts.Select chooses
// and those they depend on, reading each once, through
// [agentsession.Reader] where st implements it, for its parents
// elements alone; then it redacts each after every session its entries
// hash over: a fork's origin, and each session a parents element names.
// It reads each original in full again at its turn, as a snapshot.
//
// What is written never depends on which sessions the store held when.
// A reference to a session, parent_session, a link's session and a
// parents element's session, always names the redaction the profile
// derives for it, held or not. The entry a parents element names in
// another session is re-pointed through that session's redaction
// ([Alongside]), so a session naming an entry of a session the store
// does not hold, or one not redacted this run, waits
// ([SessionReport.WaitingOn]): nothing is written for it until that
// session's redaction can be read, and then it is written as a fresh
// pass would write it. The sessions that depend on a waiting one wait
// too.
//
// A fork is redacted as a fork of its origin's redaction
// ([WithOrigin]), sharing its prefix. One whose origin the store does
// not hold, or whose base the origin's snapshot this run does not hold
// yet (a fork made while the pass ran), waits. Only a base the origin's
// redaction left out ([ErrBaseLeftOut]), a decision that redaction
// made, has the fork redacted without a base. An existing redaction
// resumes in the mode it was written in.
//
// For each original, RedactStore reads its redaction, when st holds
// one, as a snapshot, and runs Redact on the two. It writes what Redact
// made: the blobs first, through st's [BlobWriter], and then a new
// redaction whole, through st's [agentsession.Importer], with asRecord
// set, as the store is its record; or the entries Redact appended to an
// existing one ([Result.Entries]), each with [agentsession.Store.Append]
// in order, their IDs set, which the store checks. A redaction that
// made blobs in a store that takes none is not written
// ([ErrNoBlobWriter]), nor one that grew a root ([ErrRootAppend]), a
// known limit until agentsession appends one. After appends, where st
// has SetHead, as the cas store does, the head is moved to where an
// import of the same file would put it, so a grown redaction and a fresh
// one have the same head. Once it has started writing a session it lets
// the redaction go where st has a Release(id) method, as the jsonl and
// cas stores do, however the write ends, so a store over many sessions
// does not keep each one open; a caller that holds one of them open
// through the same store opens it again.
//
// A session that fails is reported with the error in
// [SessionReport.Err], and the sessions that depend on it, directly or
// through others, are not redacted and report [ErrDependency]; every
// other session is redacted as if it had not failed. An append that
// fails part way leaves the redaction holding the entries before it,
// which the next run resumes from. The error returned joins every
// session's error, and is nil when each was redacted or waits; the
// report is returned either way, with what was done. A listing that
// fails stops the pass; a context that ends stops it too, and the error
// returned then joins the context's error to the sessions'.
//
// It holds in memory at once: the original being redacted and its
// redaction; for each origin with a fork still to be redacted, its
// snapshot and its redaction; and for each session a parents element of
// a session still to be redacted names, its redaction's counterparts,
// an entry ID to an entry ID. Planning holds one session at a time.
func RedactStore(ctx context.Context, st agentsession.Store, p Profile, opts StoreOptions) (*StoreReport, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("agentredact: no store")
	}
	ps := &pass{
		st:      st,
		p:       p,
		report:  &StoreReport{Profile: p.Name},
		accept:  map[FindingKind]bool{},
		heads:   map[string]agentsession.Header{},
		deps:    map[string]deps{},
		failed:  map[string]bool{},
		waiting: map[string]bool{},
		snaps:   map[string]*agentsession.Session{},
		reds:    map[string]*agentsession.Session{},
		chains:  map[string]*Origin{},
		forks:   map[string]int{},
		users:   map[string]int{},
		along:   Alongside{Entries: map[string]map[string]string{}},
	}
	for _, k := range opts.AcceptFindings {
		ps.accept[k] = true
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
			return ps.report, errors.Join(append(ps.errs(), err)...)
		}
		rp := ps.one(ctx, id)
		rp.Err = scrubErr(rp.Err, nil)
		ps.report.Sessions = append(ps.report.Sessions, rp)
		switch {
		case rp.Err != nil:
			ps.failed[id] = true
		case rp.WaitingOn != "":
			ps.waiting[id] = true
		}
		ps.finish(id)
	}
	return ps.report, errors.Join(ps.errs()...)
}

// pass is one run of [RedactStore].
type pass struct {
	st     agentsession.Store
	p      Profile
	report *StoreReport
	accept map[FindingKind]bool
	// heads are the originals the store holds, by ID.
	heads map[string]agentsession.Header
	// deps are what each session depends on, as the plan read it.
	deps map[string]deps
	// failed and waiting are the sessions not redacted this run.
	failed, waiting map[string]bool
	// snaps and reds are the snapshots and redactions of the origins
	// with a fork still to be redacted, and chains the origin each was
	// redacted as a fork of; forks counts those forks.
	snaps, reds map[string]*agentsession.Session
	chains      map[string]*Origin
	forks       map[string]int
	// users counts, for each session, the sessions still to be redacted
	// whose parents elements name it, while along holds its
	// counterparts.
	users map[string]int
	along Alongside
}

// deps are the originals the store holds that one session hashes over.
type deps struct {
	// origin is the origin of a fork, when the store holds it.
	origin string
	// parents are the sessions its parents elements name.
	parents []string
}

func (d deps) all() []string {
	if d.origin == "" {
		return d.parents
	}
	return append([]string{d.origin}, d.parents...)
}

// errs are the errors of the sessions reported, each naming its session.
func (ps *pass) errs() []error {
	var errs []error
	for _, rp := range ps.report.Sessions {
		if rp.Err != nil {
			errs = append(errs, fmt.Errorf("agentredact: session %s: %w", rp.Original, rp.Err))
		}
	}
	return errs
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
	}
	return nil
}

// plan reads the chosen originals and those they depend on, one at a
// time and keeping only what each depends on, and orders them so each
// comes after its dependencies. A session it cannot read, or one in a
// cycle or depending on one, is reported and left out of the order.
func (ps *pass) plan(ctx context.Context, sel func(agentsession.Header) bool) ([]string, error) {
	queue := make([]string, 0, len(ps.heads))
	for id, h := range ps.heads {
		if sel == nil || sel(h) {
			queue = append(queue, id)
		}
	}
	sort.Strings(queue)
	work := map[string]bool{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if work[id] {
			continue
		}
		work[id] = true
		s, err := ps.read(ctx, id)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			ps.fail(id, fmt.Errorf("agentredact: reading the original: %w", err))
			continue
		}
		d := ps.dependencies(s)
		ps.deps[id] = d
		queue = append(queue, d.all()...)
	}
	// Kahn's algorithm, taking the ready sessions by ID so the order is
	// the same on every run.
	waiting := map[string]int{}
	users := map[string][]string{}
	for id := range work {
		for _, d := range ps.deps[id].all() {
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
		if !ps.failed[id] {
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
	for _, id := range order {
		d := ps.deps[id]
		if d.origin != "" {
			ps.forks[d.origin]++
		}
		for _, t := range d.parents {
			ps.users[t]++
		}
	}
	return order, nil
}

// fail reports the original id as not redacted, for err.
func (ps *pass) fail(id string, err error) {
	ps.failed[id] = true
	ps.report.Sessions = append(ps.report.Sessions, SessionReport{Original: id, Redaction: ps.redID(id), Err: scrubErr(err, nil), accept: ps.accept})
}

func (ps *pass) redID(id string) string { return agentsession.RedactedSessionID(id, ps.p.Name) }

// dependencies are the originals the store holds that s's entries hash
// over: its origin, when it is a fork, and every session a parents
// element names, other than s.
func (ps *pass) dependencies(s *agentsession.Session) deps {
	own := s.ID()
	var d deps
	held := func(id string) bool {
		_, ok := ps.heads[id]
		return ok && id != own
	}
	if h := s.Header(); h.Base != "" && held(h.ParentSession) {
		d.origin = h.ParentSession
	}
	seen := map[string]bool{}
	for _, e := range s.Entries() {
		for _, ref := range e.Base().Parents {
			if held(ref.Session) && !seen[ref.Session] {
				seen[ref.Session] = true
				d.parents = append(d.parents, ref.Session)
			}
		}
	}
	sort.Strings(d.parents)
	return d
}

// finish lets go of what no session still to be redacted needs, once
// id's turn is over: the counterparts and the origin snapshots id
// needed, and its own when nothing will.
func (ps *pass) finish(id string) {
	d := ps.deps[id]
	if d.origin != "" {
		if ps.forks[d.origin]--; ps.forks[d.origin] <= 0 {
			ps.dropOrigin(d.origin)
		}
	}
	for _, t := range d.parents {
		if ps.users[t]--; ps.users[t] <= 0 {
			delete(ps.along.Entries, t)
		}
	}
	if ps.forks[id] <= 0 {
		ps.dropOrigin(id)
	}
	if ps.users[id] <= 0 {
		delete(ps.along.Entries, id)
	}
}

func (ps *pass) dropOrigin(id string) {
	delete(ps.snaps, id)
	delete(ps.reds, id)
	delete(ps.chains, id)
}

// one redacts the original id and writes the result.
func (ps *pass) one(ctx context.Context, id string) SessionReport {
	rp := SessionReport{Original: id, Redaction: ps.redID(id), accept: ps.accept}
	planned := ps.deps[id].all()
	for _, d := range planned {
		if ps.failed[d] {
			rp.Err = fmt.Errorf("%w: %s was not redacted", ErrDependency, d)
			return rp
		}
	}
	for _, d := range planned {
		if ps.waiting[d] {
			rp.WaitingOn = d
			return rp
		}
	}
	orig, err := ps.read(ctx, id)
	if err != nil {
		rp.Err = fmt.Errorf("agentredact: reading the original: %w", err)
		return rp
	}
	existing, err := ps.read(ctx, rp.Redaction)
	switch {
	case errors.Is(err, agentsession.ErrNoSession):
		existing = nil
	case err != nil:
		rp.Err = fmt.Errorf("agentredact: reading the redaction %s: %w", rp.Redaction, err)
		return rp
	}
	// The snapshot is newer than the plan's read: what it depends on is
	// read again from it.
	h := orig.Header()
	var origin *Origin
	if h.Base != "" && (existing == nil || existing.Header().Base != "") {
		if ps.failed[h.ParentSession] {
			rp.Err = fmt.Errorf("%w: %s was not redacted", ErrDependency, h.ParentSession)
			return rp
		}
		if origin = ps.origin(h); origin == nil {
			rp.WaitingOn = h.ParentSession
			return rp
		}
	}
	seen := map[string]bool{}
	for _, e := range orig.Entries() {
		for _, ref := range e.Base().Parents {
			t := ref.Session
			if t == "" || t == id || seen[t] {
				continue
			}
			seen[t] = true
			if ps.failed[t] {
				rp.Err = fmt.Errorf("%w: %s was not redacted", ErrDependency, t)
				return rp
			}
			if _, ok := ps.along.Entries[t]; !ok {
				rp.WaitingOn = t
				return rp
			}
		}
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
	if ps.users[id] > 0 {
		ps.along.Entries[id] = res.Counterparts
	}
	if ps.forks[id] > 0 {
		ps.snaps[id], ps.reds[id], ps.chains[id] = orig, red, origin
	}
	return rp
}

// origin is the origin a fork is redacted as a fork of: its origin's
// snapshot and redaction this run, when the origin was redacted this
// run and its snapshot holds the fork's base; nil otherwise.
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
// redaction whole when it is new, or the entries appended to it. What
// it refuses, it refuses before writing anything.
func (ps *pass) write(ctx context.Context, rp *SessionReport, created bool, res *Result) error {
	if !created {
		for _, e := range res.Entries {
			if e.Base().Parent == "" {
				return ErrRootAppend
			}
		}
	}
	var im agentsession.Importer
	if created {
		var ok bool
		if im, ok = ps.st.(agentsession.Importer); !ok {
			return ErrNoImporter
		}
	}
	var bw BlobWriter
	if len(res.Blobs) > 0 {
		var ok bool
		if bw, ok = ps.st.(BlobWriter); !ok {
			return fmt.Errorf("%w: %d blobs", ErrNoBlobWriter, len(res.Blobs))
		}
	}
	if !created && len(res.Entries) == 0 && len(res.Blobs) == 0 {
		return nil
	}
	// From here the store may take a hold on the redaction, which is
	// let go however the write ends.
	defer ps.release(rp)
	hashes := make([]string, 0, len(res.Blobs))
	for h := range res.Blobs {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	for _, want := range hashes {
		got, err := bw.PutBlob(ctx, res.Blobs[want])
		if err != nil {
			return fmt.Errorf("agentredact: writing a blob: %w", err)
		}
		if got != want {
			return errors.New("agentredact: the store holds a blob under another hash")
		}
		rp.Blobs++
	}
	if created {
		var buf bytes.Buffer
		if err := agentsession.Write(&buf, res.Session); err != nil {
			return err
		}
		if _, err := im.Import(ctx, &buf, true); err != nil {
			return fmt.Errorf("agentredact: importing the redaction %s: %w", rp.Redaction, err)
		}
		rp.Created, rp.Written = true, len(res.Entries)
		return nil
	}
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
			return fmt.Errorf("agentredact: the store appended entry %d of the redaction under another ID", rp.Written+1)
		}
		rp.Written++
	}
	ps.setHead(ctx, rp, res.Session)
	return nil
}

// headSetter is a store that moves a session's head, given the head it
// expects, as the cas store does.
type headSetter interface {
	SetHead(ctx context.Context, sessionID, expected, to string) error
}

// setHead moves the head of the redaction a store appended to, where
// the store can, to where an import of the same file puts it: by the
// resume rule, as RFC 0002 imports a projection, where an append moved
// it by the live rule, which a branch does not move. A store that keeps
// a session's head only in its lines reads it by the resume rule
// already.
func (ps *pass) setHead(ctx context.Context, rp *SessionReport, red *agentsession.Session) {
	hs, ok := ps.st.(headSetter)
	if !ok {
		return
	}
	var buf bytes.Buffer
	if err := agentsession.Write(&buf, red); err != nil {
		rp.Warnings = append(rp.Warnings, scrubErr(err, nil).Error())
		return
	}
	file, err := agentsession.Read(&buf)
	if err != nil {
		rp.Warnings = append(rp.Warnings, scrubErr(err, nil).Error())
		return
	}
	held, err := ps.read(ctx, rp.Redaction)
	if err != nil {
		rp.Warnings = append(rp.Warnings, scrubErr(fmt.Errorf("agentredact: reading the head: %w", err), nil).Error())
		return
	}
	want, got := file.Leaf(), held.Leaf()
	if want == "" || want == got {
		return
	}
	if err := hs.SetHead(ctx, rp.Redaction, got, want); err != nil {
		rp.Warnings = append(rp.Warnings, scrubErr(fmt.Errorf("agentredact: setting the head: %w", err), nil).Error())
	}
}

// releaser is a store that lets a session it holds go.
type releaser interface {
	Release(id string) error
}

// release lets the redaction go where the store can; a failure is a
// warning, since what was written stays written.
func (ps *pass) release(rp *SessionReport) {
	if rl, ok := ps.st.(releaser); ok {
		if err := rl.Release(rp.Redaction); err != nil {
			rp.Warnings = append(rp.Warnings, scrubErr(fmt.Errorf("agentredact: releasing the redaction: %w", err), nil).Error())
		}
	}
}

// read reads the session id from the store as a snapshot of its own.
func (ps *pass) read(ctx context.Context, id string) (*agentsession.Session, error) {
	return readHeld(ctx, ps.st, id)
}

// readHeld reads the session id from st without a hold where st can.
// Otherwise it opens it, copies it, so nothing done to the copy reaches
// the store's own session, and lets it go where st has Release.
func readHeld(ctx context.Context, st agentsession.Store, id string) (*agentsession.Session, error) {
	if r, ok := st.(agentsession.Reader); ok {
		return r.Read(ctx, id)
	}
	s, err := st.Open(ctx, id)
	if err != nil {
		return nil, err
	}
	if rl, ok := st.(releaser); ok {
		defer func() { _ = rl.Release(id) }()
	}
	var buf bytes.Buffer
	if err := agentsession.Write(&buf, s); err != nil {
		return nil, err
	}
	return agentsession.Read(&buf)
}
