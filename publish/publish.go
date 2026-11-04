// Package publish pushes the redacted sessions that may leave a private
// store to a store that holds only redacted entries (#6): the target
// is opened set to refuse anything else (agentsession's
// WithRedactedOnly on jsonl, cas and the remote client,
// MemoryRedactedOnly in memory), so an original sent there by mistake
// is refused, before any upload over RFC 0003. A session is published
// when the store pass says it is publishable and every judge required
// cleared it at its current judged entry; the rest are held, each with
// its reason.
package publish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
)

// Options say what to publish.
type Options struct {
	// Profile selects the redacted sessions whose redacted_from names it.
	Profile string
	// Report is the store pass's latest report over the private store
	// under Profile ([agentredact.RedactStore]): a session it does not
	// say is publishable, or whose state it read is not the session's
	// state now ([agentredact.SessionReport.State]), is held.
	Report *agentredact.StoreReport
	// Judges are the judges whose verdicts must clear a session in its
	// current state ([agentredact.Cleared]); [DefaultJudges], the scan,
	// when none are named.
	Judges []string
	// Unjudged publishes with no verdict required at all, the store
	// pass's report alone deciding. It must be set by name: nothing
	// publishes unscanned by default (#4).
	Unjudged bool
}

// DefaultJudges are the judges a session must be cleared by when
// Options names none: the TruffleHog scan (package scan's Judge).
var DefaultJudges = []string{"scan"}

// Published names one session pushed, as a manifest names it: its own
// ID and the hash of its head entry, never its original's ID or hashes
// (RFC 0002, Redacted sessions).
type Published struct {
	Session string
	Head    string
	// Appended counts the entries pushed this run, all of them when the
	// target did not hold the session.
	Appended int
}

// Held is a session not published, and why.
type Held struct {
	Session string
	Reason  string
}

// Result is what Publish did.
type Result struct {
	Published []Published
	Held      []Held
}

// ErrNotRedacted is reported for a session holding an entry the
// redaction did not make.
var ErrNotRedacted = errors.New("publish: the session holds an entry that is not redacted")

// Publish copies to the target every redacted session of the private
// store from under opts.Profile that may leave: the blobs it references
// first ([agentredact.SidecarRefs]), each with its type, then the
// session, imported whole when the
// target does not hold it and otherwise grown by the entries it lacks.
// It reads each session afresh and holds it, unpublished, when it holds
// a native entry, when opts.Report does not say it is publishable, or
// when a judge has not cleared it at its judged entry, or when it
// references a blob the report does not let it carry
// ([agentredact.SessionReport.CarriesBlob]): one the redaction could
// not redact, or one the report does not name; the reason names the
// blob. A hash written in text is not a reference and is never
// followed or carried (agentredact#23). A session the
// target refuses is held with the refusal; the error returned joins the
// failures that stopped a session part way.
func Publish(ctx context.Context, from, to agentsession.Store, opts Options) (*Result, error) {
	g, err := newGate(opts)
	if err != nil {
		return nil, err
	}
	var ids []string
	for sum, err := range from.List(ctx, agentsession.ListFilter{}) {
		if err != nil {
			return nil, fmt.Errorf("publish: listing the private store: %w", err)
		}
		h := sum.Header
		if h.Redacted && h.RedactedFrom != nil && h.RedactedFrom.Profile == opts.Profile && agentsession.VerifiesAsRedacted(h) {
			ids = append(ids, h.ID)
		}
	}
	sort.Strings(ids)
	res := &Result{}
	var errs []error
	for _, id := range ids {
		hold := func(reason string) { res.Held = append(res.Held, Held{Session: id, Reason: reason}) }
		red, blobs, reason, err := g.check(ctx, from, id)
		if err != nil {
			errs = append(errs, err)
		}
		if red == nil {
			hold(reason)
			continue
		}
		n, err := push(ctx, from, to, red, blobs)
		if err != nil {
			hold("the target refused it")
			errs = append(errs, fmt.Errorf("publish: %s: %w", id, err))
			continue
		}
		res.Published = append(res.Published, Published{Session: id, Head: red.Leaf(), Appended: n})
	}
	return res, errors.Join(errs...)
}

// gate is what a session must pass to leave the private store, by
// publish or by export.
type gate struct {
	judges  []string
	reports map[string]agentredact.SessionReport
}

func newGate(opts Options) (*gate, error) {
	if opts.Profile == "" || opts.Report == nil {
		return nil, errors.New("publish: a profile and the store pass's report are needed")
	}
	if opts.Report.Profile != opts.Profile {
		return nil, fmt.Errorf("publish: the report is of profile %q, not %q", opts.Report.Profile, opts.Profile)
	}
	g := &gate{judges: opts.Judges, reports: map[string]agentredact.SessionReport{}}
	switch {
	case opts.Unjudged && len(g.judges) > 0:
		return nil, errors.New("publish: Unjudged and Judges both set")
	case opts.Unjudged:
	case len(g.judges) == 0:
		g.judges = DefaultJudges
	}
	for _, r := range opts.Report.Sessions {
		g.reports[r.Redaction] = r
	}
	return g, nil
}

// check reads the redacted session id from the private store from and
// returns it, with the blobs it references, when it may leave: the
// report holds it publishable in the state it is in now, it holds no
// native entry, the report lets it carry every blob it references, and
// every judge cleared that exact state. Otherwise it returns nil and
// why, and an error for a failure to read.
func (g *gate) check(ctx context.Context, from agentsession.Store, id string) (*agentsession.Session, []string, string, error) {
	rp, ok := g.reports[id]
	if !ok {
		return nil, nil, "the store pass did not report it", nil
	}
	for _, h := range slices.Sorted(maps.Keys(rp.Sidecar)) {
		if rp.Sidecar[h] == agentredact.BlobUnredacted {
			return nil, nil, unredacted(h), nil
		}
	}
	if !rp.Publishable() {
		return nil, nil, "the store pass does not hold it publishable", nil
	}
	red, err := read(ctx, from, id)
	if err != nil {
		return nil, nil, "it could not be read", err
	}
	if rp.State != agentredact.StateOf(red) {
		return nil, nil, "the report is of another state of the session: run the store pass again", nil
	}
	if err := ownRedacted(red); err != nil {
		return nil, nil, err.Error(), nil
	}
	blobs, err := agentredact.SidecarRefs(red)
	if err != nil {
		return nil, nil, "its blob references could not be read", err
	}
	for _, h := range blobs {
		if !rp.CarriesBlob(h) {
			return nil, nil, unredacted(h), nil
		}
	}
	if len(g.judges) > 0 {
		verdicts, err := agentredact.Verdicts(ctx, from, id)
		if err != nil {
			return nil, nil, "its verdicts could not be read", err
		}
		if !agentredact.Cleared(verdicts, red, g.judges...) {
			return nil, nil, "not cleared by every judge in its current state", nil
		}
	}
	return red, blobs, "", nil
}

// unredacted is the reason a session referencing the blob hash, which
// the redaction did not redact, is held. The hash may be an original
// blob's: a held reason is for whoever holds the private store, and is
// not to be published.
func unredacted(hash string) string {
	return "it references blob " + hash + ", which the redaction did not redact: it may not leave"
}

// ownRedacted refuses a session one of whose own entries carries no
// redacted: appended natively, which a redacted-only store refuses too.
func ownRedacted(s *agentsession.Session) error {
	for _, e := range s.Entries() {
		if s.Prefix(e.Base().ID) {
			continue
		}
		if _, ok := agentsession.RedactedOf(e); !ok {
			if l, ok := e.(*agentsession.LabelEntry); ok && l.Label != nil && *l.Label == agentsession.LeafLabel {
				continue // a head move, which carries no content
			}
			return ErrNotRedacted
		}
	}
	return nil
}

// push copies hashes, the blobs red references, then red, to the
// target, and returns how many entries it wrote.
func push(ctx context.Context, from, to agentsession.Store, red *agentsession.Session, hashes []string) (int, error) {
	if len(hashes) > 0 {
		br, ok := from.(agentsession.BlobReader)
		tw, ok2 := to.(agentsession.TypedBlobWriter)
		if !ok || !ok2 {
			return 0, errors.New("a store holds no blobs, and the session names some")
		}
		for _, h := range hashes {
			data, typ, err := agentsession.ReadSessionBlob(ctx, br, red.ID(), h)
			if err != nil {
				return 0, err
			}
			if _, err := tw.PutTypedBlob(ctx, data, typ); err != nil {
				return 0, err
			}
		}
	}
	held, err := read(ctx, to, red.ID())
	if errors.Is(err, agentsession.ErrNoSession) {
		im, ok := to.(agentsession.Importer)
		if !ok {
			return 0, errors.New("the target cannot import a session")
		}
		var buf bytes.Buffer
		if err := agentsession.Write(&buf, red); err != nil {
			return 0, err
		}
		if _, err := im.Import(ctx, &buf, true); err != nil {
			return 0, err
		}
		return len(red.Entries()), nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range agentsession.FileOrder(red) {
		if red.Prefix(e.Base().ID) {
			continue
		}
		if _, ok := held.Entry(e.Base().ID); ok {
			continue
		}
		data, err := agentsession.MarshalEntry(e)
		if err != nil {
			return n, err
		}
		own, err := agentsession.UnmarshalEntry(data)
		if err != nil {
			return n, err
		}
		if _, err := to.Append(ctx, red.ID(), own); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// read reads the session id from st without a hold where st can.
func read(ctx context.Context, st agentsession.Store, id string) (*agentsession.Session, error) {
	if r, ok := st.(agentsession.Reader); ok {
		return r.Read(ctx, id)
	}
	s, err := st.Open(ctx, id)
	if err != nil {
		return nil, err
	}
	if rl, ok := st.(agentsession.Releaser); ok {
		defer func() { _ = rl.Release(id) }()
	}
	var buf bytes.Buffer
	if err := agentsession.Write(&buf, s); err != nil {
		return nil, err
	}
	return agentsession.Read(&buf)
}
