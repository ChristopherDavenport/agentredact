package agentredact

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ChristopherDavenport/agentsession"
)

// ErrNotThisRedaction is returned by [Redact] for an existing session
// that is not the redaction of the original under the profile: one not
// marked redacted, one whose redacted_from names another original or
// another profile, or one whose ID is not the one the two derive.
var ErrNotThisRedaction = errors.New("agentredact: not the redaction of this original under this profile")

// Result is what [Redact] made.
type Result struct {
	// Session is the redacted session: the existing one, grown, when
	// Redact was given one, and a new one otherwise. It is in memory;
	// nothing is written to a store.
	Session *agentsession.Session
	// Entries are the entries this call committed to Session, in
	// order, their IDs set, block placeholders included: all of them for
	// a new session, and only the new ones for a resumed one, which is
	// what a store appends.
	Entries []agentsession.Entry
	// Findings are what the redaction wrote without redacting, which
	// must be looked at before the session leaves: see [Finding].
	Findings []Finding
	// Blobs are the blobs the entries this call committed name that the
	// redaction made, such as the replacement for a sidecar image
	// ([Images]), keyed by their hash, sha256:<hex>, which their
	// sidecar: URLs name. Redact writes none: the caller stores them
	// beside the redacted session. A blob the redaction keeps is the
	// original's and is not here. Nil when there are none.
	Blobs map[string]Blob
	// Counterparts maps every entry of the original, by ID, a fork's
	// prefix included, to the redacted entry that stands for it in
	// Session: the last entry written in its place when it was kept,
	// and "" when it was left out, however (folded into a block,
	// omitted, or on a branch a session redactor left out). Its fate
	// never changes as the original grows, so neither does its value.
	// It is what another session redacted alongside re-points a
	// reference into this one through: see [Alongside].
	Counterparts map[string]string
}

// Option changes what [Redact] does.
type Option func(*options)

type options struct {
	origin    *Origin
	alongside Alongside
	resolve   func(id string) (*agentsession.Session, error)
}

// WithResolve lets [Redact] read the sessions the original names, so
// that a reference to one that verifies as a redacted session's derived
// ID ([agentsession.VerifiesAsRedacted]) keeps that ID, as a fork of a
// redacted session names it in parent_session (RFC 0001, The redacted
// session, since 0.19): it is a redaction already. resolve returns nil
// and no error for a session it does not hold. Without it every session
// a reference names but the original itself is named by its keyed
// pseudonym's redaction ([agentsession.RedactionNames]).
func WithResolve(resolve func(id string) (*agentsession.Session, error)) Option {
	return func(o *options) { o.resolve = resolve }
}

// Alongside is what [Redact] is told of the other sessions redacted
// with this one under the same profile, so that it re-points the
// entries a parents element names in them, as RFC 0001 has a redaction
// that holds another session's redaction do. A reference to a session,
// parent_session, a link's session or a parents element's, needs
// nothing here: Redact always re-points it to the redaction the key and
// the profile derive for it.
type Alongside struct {
	// Entries maps another session's original ID to its redaction's
	// [Result.Counterparts]. A parents element naming an entry of such
	// a session is re-pointed to the entry standing for it there, or
	// removed, with a Finding, when that one was left out, as a parents
	// element naming an entry of this session left out is; one naming
	// an entry its Counterparts does not hold is refused with
	// [ErrUnmappedRef]. A parents element naming an entry of a session
	// not here keeps that entry as written, and is reported as a
	// [FindingForeignReference].
	Entries map[string]map[string]string
}

// WithAlongside tells [Redact] of the sessions redacted alongside.
func WithAlongside(a Alongside) Option {
	return func(o *options) { o.alongside = a }
}

// ErrUnmappedRef is returned by [Redact] for a parents element naming
// an entry of a session redacted alongside ([Alongside]) whose
// counterparts do not hold that entry.
var ErrUnmappedRef = errors.New("agentredact: a reference into a session redacted alongside names nothing its redaction holds")

// Redact applies the profile p to the session original and returns the
// redacted session, in memory.
//
// First p's session redactors choose the branches to leave out
// ([SessionRedactor]); the entries they leave out reach no other
// redactor and their positions appear nowhere. Then each other entry of
// the original, in its file order ([agentsession.FileOrder]), has its
// strings rewritten by p's string redactors through one
// [agentsession.Rewriter], and p's entry redactors applied in order. An
// [EntryRedactor] changes the entry; a [StructureRedactor] may leave it
// out, fold it into a block placeholder, or write several entries in
// its place. Each entry written has its references re-pointed with
// [agentsession.RemapRefs] to the entries already written, and is
// marked redacted with the position it was made from, [n], counting
// from 1, or [] when a structural redactor added it
// ([agentsession.SetRedacted]). A response is then given the
// request_hash its request rebuilds to in the redacted session
// ([agentsession.Session.SetRequestHash]), unless its request_hash did
// not verify in the original, or it had none, when it gets none, so the
// redaction never certifies a request the original could not. Then it
// is committed.
//
// # Leaving entries out
//
// An entry left out with nothing in its place has the entries under it
// hang from the nearest entry kept above it. An entry folded into a
// block placeholder joins the run of folded entries above it on its
// path; when a kept entry follows the run, Redact writes the run's
// placeholder under the entry kept above the run, and the kept entry
// under it. The placeholder is a custom entry under [PlaceholderNS],
// marked with the run's positions, [[from, to]] where they are
// consecutive in file order and several elements where they are not,
// its timestamp the first entry's, its data the number of entries; it
// adds nothing to any request. A run no kept entry follows yet, at the
// end of a path, is withheld: nothing is written for it until the
// original grows a kept entry under it, so a block is written once, as
// one placeholder, however the run grew. A folded entry two paths share
// goes into the first placeholder written, as the first kept entry
// under it closes its run; the other path's later run hangs from that
// placeholder, which then names a position off that path. A run that
// would be all a resumed run's segment holds, closed by its end, gets
// no placeholder, since one would turn an empty resume into an input:
// its entries are left out with nothing in their place.
//
// A member of a kept entry that named an entry left out names its block
// placeholder when one stands in its place. Otherwise: a label or an
// outcome naming it is left out too, as RFC 0001's "names that or is
// removed" has it, a leaf label included; a judged_by link loses its
// target; a parents element, a queued_from and an omit item are removed;
// a branch summary's from and the parent of an entry name the nearest
// entry kept above it; and a member that must name an entry with
// nothing there is refused with [ErrNoPlace]. An omit naming an item
// split into several entries names the last.
//
// Some entries belong to a group, headed by its earliest entry, and
// leaving out the head leaves out the group, in the same way (folded or
// with nothing in its place):
//
//   - a call: its function_call item, and after it every
//     function_call_output, dispatch and decision bound to it, every
//     subsession or peer link with its call_id, cancel notices among
//     them, and every custom entry with its call_id;
//   - a run: its start and the end that closes it on the path;
//   - a queued input: the queued entry and the items drained from it
//     (queued_from), since the queued entry holds the input verbatim;
//   - a response and the items it envelopes ([agentsession.OutputEntries]),
//     where the items come first: leaving out every one of them leaves
//     out the response, and leaving out some keeps it, enveloping the
//     rest.
//
// Leaving out a group's member while its head is kept is refused, since
// the head was already written when the member is met: an output,
// dispatch, decision or link of a kept call ([ErrSplitsCall]), an item
// drained from a kept queued input ([ErrSplitsQueued]), a response whose
// items are kept ([ErrSplitsResponse]), a run end whose start is kept
// ([ErrSplitsRun]). The same rules hold what the session redactors leave
// out, checked before anything is written, but for a run end whose
// parent they leave out too, which goes with it and leaves the run open
// on the kept path; [KeepLeafPath] keeps the path's own records that
// sit off it rather than dropping them. A group
// head written as an entry of another type is refused ([ErrGroupHead]).
// So is leaving out a config entry or a compaction ([ErrLeavesOutConfig],
// [ErrLeavesOutCompaction]): later entries resolve against what they put
// in force, and a compaction left out would put what it folded back
// into later requests.
//
// Where leaving out changes a kept entry's meaning, Redact carries it
// through: a run end loses the calls left out from its pending list,
// and, when the original's run verified, gets the pending list and,
// unless it was error or interrupted, the reason its redacted segment
// reads; a compaction's pinned item whose item entries were all left out
// leaves with them; an omit list loses the IDs left out, and an omit
// that only added them is dropped; a compaction's first_kept left out
// names the first entry standing for one from it to the compaction, or,
// when every one was left out with nothing in its place, the entry in
// its place when that adds nothing to the context, and is otherwise
// refused ([ErrFirstKept]). Each leaf's path whose original verified its
// records is held to [agentsession.Session.VerifyRecords]; a failure,
// such as a run that resumes a call left out, is refused with
// [ErrBreaksRecords]. Without an origin Redact writes no base, so the
// base rule holds of any root it leaves: an entry whose ancestors were
// all left out is a root. With one ([WithOrigin]), every own entry
// hangs from the base or another own entry, since the base is what
// stands for the original's base, and an entry kept above it.
//
// What restates entries left out without naming them cannot be removed
// without changing requests, and is reported as a [Finding], with no
// value: a kept branch summary whose branch was left out, a kept
// compaction whose summary, or server-side compaction item, covers
// entries left out before first_kept, a kept entry converging one left
// out (its parents), a pinned item matching no entry while entries
// before first_kept were left out, and an item's source or a run
// start's trigger copying the trigger of a queued input left out.
// Leaving out an env entry can make a later one read as a substitution,
// or stop one reading so.
//
// Sessions are named under key (RFC 0001, The redacted session, since
// format 0.19), which [Redact] refuses when it holds no key
// ([agentsession.ErrRedactionKey]): redacted_from names the original by
// its keyed pseudonym, and the redacted session's ID, and every
// reference into another session, derive from the pseudonym
// ([RedactedID], [agentsession.RedactionNames]), so a holder of the
// original's ID cannot find its redaction. One key belongs to a store
// of originals: see [Key].
//
// The header is new: it carries redacted, redacted_from naming the
// original's pseudonym and p, and the ID derived from the two. Of the
// original's header members it keeps created_at, payload, records,
// media and spawned_by as written; re-points parent_session as a
// reference into another session (below); gives cwd, harness's name and
// version, and every name and string inside each member the format does
// not define, at any depth, to p's string redactors
// ([agentsession.RewriteHeaderStrings]), whose own names the format
// keeps as written, each that p's string redactors would change
// reported as a [FindingHeaderName]; and writes no base unless it is a
// fork of its origin's redaction ([WithOrigin]). Two names of one
// object made one is refused with [agentsession.ErrKeyCollision], whose
// message names neither. format is the one agentsession writes. Then
// each of p's entry redactors that is a [HeaderRedactor] redacts it, as
// [Environment] blanks cwd.
//
// A member name that is data, in a custom entry's data, an outcome's
// details, a decision's args, a member the format does not define or an
// extension entry, reaches p's string redactors through the Rewriter
// and is renamed, as RFC 0001 0.14 has it.
//
// An original that is a fork, one with a base, is redacted without a
// base unless an origin is given: its prefix is redacted into entries of
// the redaction's own, whose positions count in the fork's file order,
// as RFC 0001 allows, and the redaction promises no records, since the
// original's promise covered its own entries and not its prefix, which
// may answer a call the origin never dispatched. Given its origin's
// redaction ([WithOrigin]), it is redacted as a fork of that, sharing
// its prefix, and keeps the original's promise.
//
// A reference to another session, parent_session, a link's session, a
// parents element's or a copied item's, always names the redaction key
// and p derive for it, whether or not that redaction exists yet: the ID
// is known without the session, so what Redact writes never depends on
// which sessions are at hand, and no original session ID is kept, but
// for one that verifies as a redacted session's ID through
// [WithResolve], which is a redaction already. The entry a parents
// element names in another session is re-pointed to the one standing
// for it in that session's redaction when its counterparts are given
// ([WithAlongside]); one that redaction left out is removed and
// reported, and one it does not hold is refused with [ErrUnmappedRef].
// Without the counterparts the entry standing for it is not known, so
// the reference is removed, as RFC 0001 0.19 has a redactor that holds
// neither that session nor its redaction leave it out, and reported as a
// [FindingForeignReference]. Inline media that is not an image and an
// image data URL inside a longer string are kept and reported.
//
// Findings are reported for the whole redaction on every call: a resume
// reports those of the entries it replays as well as those it writes,
// so the latest call says everything the redaction holds unredacted.
//
// existing, when not nil, is the redaction of original under p that an
// earlier call made, as a store holds it: Redact appends to it, and
// returns it, so a redacted session grows with its original and equals,
// byte for byte, a fresh redaction of the grown original. What Redact
// writes at a position depends on the original's entries up to it
// alone, provided the redactors' decisions do, so the work done is
// every position up to the highest any marked entry of existing names,
// ranges included. Redact replays those positions, building each entry
// a fresh redaction would write there and requiring existing to hold an
// entry of the same ID, so the same bytes, which restores the runs still
// withheld, and then writes the rest; a position past it that was left
// out is decided again, the same way, and still writes nothing. Its
// header is kept. Redact refuses, with [ErrNotThisRedaction], an
// existing session whose redacted_from names another original, the
// original under another key, or another profile, whose ID is not the derived one, that has a base
// when no origin is given, or none or another when one is, or none of
// whose entries made from a position is of the type a fresh
// redaction writes there; wrapping [agentsession.ErrStaleOriginal], one
// naming a position past the original's end; and, with
// [ErrResumeDiverged], one that differs from a fresh redaction in any
// entry up to that position, holds an entry it would not write or lacks
// one it would: a profile reused for changed rules, a redactor whose
// output reads what came after its entry, or a [KeepLeafPath] leaf moved
// to another branch. Entries appended to it natively stay where they
// are. A block placeholder existing holds with nothing under it, as an
// append interrupted between the placeholder and the kept entry that
// closes its run leaves one, is matched when that entry is written.
// These refusals, and those of what the session redactors leave out,
// come before anything is written to existing; on any later error
// existing may hold some of the new entries, so discard it and read it
// again.
//
// An instruction part named by the hash of a text the redaction cannot
// resolve on its path, one no entry it wrote before it holds
// ([agentsession.Rewriter.Unmet]), is written as [UnmetPartText] under
// its id rather than under the original's hash, which would neither
// verify nor hide the text; the responses after it carry the
// request_hash the redacted session rebuilds. A part that keeps parts
// the redaction does not hold is refused with [ErrUnmetKeep].
//
// An error from agentsession, such as [agentsession.ErrInstructionsJoin]
// or [agentsession.ErrKeyCollision], is wrapped with the position and
// type of the entry that failed, and errors.Is finds it. No error names
// an entry by an original hash: an entry of the original is named by
// its position, and any other hash in the message is elided, since an
// original hash can confirm a guess and an error travels to logs.
func Redact(p Profile, key Key, original, existing *agentsession.Session, opts ...Option) (*Result, error) {
	res, err := redactSession(p, key, original, existing, opts)
	if err != nil {
		return nil, scrubErr(err, original)
	}
	return res, nil
}

func redactSession(p Profile, key Key, original, existing *agentsession.Session, opts []Option) (*Result, error) {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if original == nil {
		return nil, errors.New("agentredact: no original session")
	}
	r, err := newRedaction(p, key, original, o.alongside, o.resolve)
	if err != nil {
		return nil, err
	}
	if o.origin != nil {
		if err := r.forkFrom(o.origin); err != nil {
			return nil, err
		}
	}
	// The header goes through the string redactors on a resume too, so
	// the placeholders are numbered as a fresh redaction numbers them.
	h, headerFindings, err := r.header()
	if err != nil {
		return nil, err
	}
	if existing == nil {
		if r.red, err = r.newSession(h, o.origin); err != nil {
			return nil, err
		}
	} else {
		if err := r.resume(existing); err != nil {
			return nil, err
		}
		r.red = existing
	}
	r.res = &Result{Session: r.red, Blobs: map[string]Blob{}}
	if r.out, err = r.sessions(); err != nil {
		return nil, err
	}
	if err := r.checkSessions(r.out); err != nil {
		return nil, err
	}
	r.res.Findings = append(r.res.Findings, headerFindings...)
	r.lastTS = original.Header().CreatedAt
	if err := r.walk(len(r.order), true); err != nil {
		return nil, err
	}
	// Every entry the existing redaction holds was matched, the block
	// placeholder an interrupted append left as a leaf included.
	if err := r.unmatched(false); err != nil {
		return nil, err
	}
	if err := r.checkRecords(); err != nil {
		return nil, err
	}
	if len(r.res.Blobs) == 0 {
		r.res.Blobs = nil
	}
	r.res.Counterparts = make(map[string]string, len(r.placed))
	for id, pl := range r.placed {
		if pl.fate == kept {
			r.res.Counterparts[id] = pl.last
		} else {
			r.res.Counterparts[id] = ""
		}
	}
	return r.res, nil
}

// newRedaction starts a redaction of original under p, which has been
// validated, and key.
func newRedaction(p Profile, key Key, original *agentsession.Session, along Alongside, resolve func(id string) (*agentsession.Session, error)) (*redaction, error) {
	names, err := key.names(original, p.Name)
	if err != nil {
		return nil, err
	}
	if resolve != nil {
		names.WithResolve(resolve)
	}
	r := &redaction{
		p:        p,
		key:      key,
		resolve:  resolve,
		names:    names,
		original: original,
		order:    agentsession.FileOrder(original),
		origID:   original.ID(),
		placed:   map[string]*placed{},
		along:    along,
	}
	r.redID = names.ID()
	r.ph = NewPlaceholders()
	chain := p.StringFunc()
	r.f = func(s string) string { return chain(s, r.ph) }
	r.rw = agentsession.NewRewriter(r.f).Alongside(r.alongside)
	return r, nil
}

// newSession is the new redacted session whose header is h: a fork of
// the origin's redaction at r.base when r is a fork of it, and a
// session of its own otherwise.
func (r *redaction) newSession(h agentsession.Header, o *Origin) (*agentsession.Session, error) {
	if !r.fork {
		return agentsession.New(h), nil
	}
	h.Base, h.ParentSession = r.base, r.originRedID
	h.Records = append([]string(nil), r.original.Header().Records...) // its own entries are the original's own
	if err := agentsession.CheckCreate(h, false); err != nil {
		return nil, err
	}
	s, err := agentsession.Fork(o.Redaction, r.base, h)
	if err != nil {
		return nil, fmt.Errorf("agentredact: forking %s at %s: %w", r.originRedID, r.base, err)
	}
	return s, nil
}

// walk redacts the original's entries at positions 1 to upto, in file
// order: replaying those up to r.done, writing the rest. check says
// whether an existing redaction holding what a fresh one does not
// write is refused as the replay ends, before anything is written.
func (r *redaction) walk(upto int, check bool) error {
	for i, e := range r.order[:upto] {
		pos := i + 1
		if check && pos == r.done+1 {
			// Replayed: refuse an existing redaction a fresh one does not
			// write before anything is written to it.
			if err := r.unmatched(true); err != nil {
				return err
			}
		}
		// The Rewriter meets every entry from the first, those left out
		// and those already redacted among them, so a part named by hash
		// names the rewritten text an earlier entry holds.
		met := len(r.rw.Unmet())
		body, err := r.rw.Rewrite(e)
		if err != nil {
			return entryErr(r.origID, pos, e, quietRewriteErr(err))
		}
		unmet := r.rw.Unmet()[met:]
		if pos <= r.prefixLen {
			// A fork's prefix: the origin's redaction decided it.
			if !r.isKept(e.Base().ID) {
				r.rw.LeftOut(e)
			}
			continue
		}
		if r.out[i] {
			r.placed[e.Base().ID] = &placed{fate: dropped, pos: pos}
			r.leftOut = true
			r.rw.LeftOut(e)
			continue
		}
		if err := writeUnmet(body, unmet); err != nil {
			return entryErr(r.origID, pos, e, err)
		}
		if err := r.entry(pos, e, body); err != nil {
			return entryErr(r.origID, pos, e, err)
		}
		if !r.isKept(e.Base().ID) {
			r.rw.LeftOut(e)
		}
	}
	return nil
}

// UnmetPartText is the text an instruction part is written with when
// the redaction cannot resolve the hash the original names it by: a
// hash of text that no entry the redaction wrote before it on its path
// holds, which would be the original's hash, neither verifying in the
// redacted session nor hiding the text (RFC 0001, Every redacted entry).
// The part keeps its id; the responses after it carry the request_hash
// the redacted session rebuilds with this text.
const UnmetPartText = "[REDACTED instruction part not in this redaction]"

// ErrUnmetKeep is returned by [Redact] for an instruction part that
// keeps parts no entry the redaction wrote on its path put in force: it
// cannot be written as text, since the redaction does not hold the parts
// it counts.
var ErrUnmetKeep = errors.New("agentredact: an instruction part keeps parts the redaction does not hold")

// writeUnmet writes each part of body, the Rewriter's output, that the
// Rewriter reports as unmet ([agentsession.Rewriter.Unmet]) as
// [UnmetPartText] in place of its hash, and refuses a keep it cannot.
// The parts are named by pointer, never by hash or text.
func writeUnmet(body agentsession.Entry, unmet []agentsession.UnmetPart) error {
	for _, u := range unmet {
		var parts []agentsession.InstructionPart
		switch v := body.(type) {
		case *agentsession.ConfigEntry:
			parts = v.InstructionsParts
		case *agentsession.CompactionEntry:
			parts = v.Config.InstructionsParts
		}
		rest, ok := strings.CutSuffix(u.At, "/hash")
		if !ok {
			return fmt.Errorf("%w: at %s", ErrUnmetKeep, u.At)
		}
		i := strings.LastIndexByte(rest, '/')
		n, err := strconv.Atoi(rest[i+1:])
		if err != nil || n < 0 || n >= len(parts) {
			return fmt.Errorf("agentredact: an unmet instruction part at %s the entry does not hold", u.At)
		}
		parts[n].Hash, parts[n].Text = "", UnmetPartText
	}
	return nil
}

// header is the header a new redaction writes, and what the header
// keeps that must be reported. It is computed on every call, resumed or
// not, before any entry, so the placeholders are numbered alike.
func (r *redaction) header() (agentsession.Header, []Finding, error) {
	h, err := redactedHeader(r.p, r.original.Header(), r.names, r.f, r.remap(nil))
	if err != nil {
		return agentsession.Header{}, nil, err
	}
	return h, headerNames(r.original.Header(), r.f), nil
}

// redactedHeader is the header of a new redaction of the original whose
// header is h, its text rewritten by f through
// [agentsession.RewriteHeaderStrings], its session references
// re-pointed through remap, and its ID and redacted_from those names
// derives.
func redactedHeader(p Profile, h agentsession.Header, names *agentsession.RedactionNames, f func(string) string, remap agentsession.Remap) (agentsession.Header, error) {
	src := h
	if _, ok := src.Extra["redacted_from"]; ok {
		// A member in another form, from before 0.13: this header writes
		// its own.
		src.Extra = maps.Clone(src.Extra)
		delete(src.Extra, "redacted_from")
	}
	n, err := agentsession.RewriteHeaderStrings(src, f)
	if err != nil {
		return agentsession.Header{}, quietRewriteErr(err)
	}
	n.Format, n.Base = "", ""
	n.Records = append([]string(nil), h.Records...)
	if h.Base != "" {
		// Redacted without a base, its prefix becomes entries of its own,
		// which the original's promise of records never covered: a call
		// in the prefix may be answered with no dispatch, as the origin's
		// own promise allowed. The promise is the redaction's to write,
		// and a fork redacted as a fork of its origin's redaction sets it
		// again below.
		n.Records = nil
	}
	n.Redacted, n.RedactedFrom = true, names.RedactedFrom()
	n, _ = agentsession.RemapHeaderRefs(n, agentsession.Remap{Session: remap.Session}) // always mapped
	for _, r := range p.Entries {
		if hr, ok := r.(HeaderRedactor); ok {
			if err := hr.RedactHeader(&n); err != nil {
				return agentsession.Header{}, fmt.Errorf("agentredact: header: %s: %w", redactorName(r), err)
			}
		}
	}
	n.ID, n.Redacted, n.Base = names.ID(), true, ""
	n.RedactedFrom = names.RedactedFrom()
	if err := agentsession.CheckCreate(n, false); err != nil {
		return agentsession.Header{}, err
	}
	return n, nil
}

// headerNames reports each member of the header h the format does not
// define whose name f would change. RFC 0001 has a redactor keep the
// names of the header's members as written, since the header is an
// object the format defines, and rewrite their values alone
// ([agentsession.RewriteHeaderStrings]), so such a name is kept: a
// finding of the whole session, at position 0, naming neither the
// member nor what f matched.
func headerNames(h agentsession.Header, f func(string) string) []Finding {
	var out []Finding
	for _, k := range slices.Sorted(maps.Keys(h.Extra)) {
		if k != "redacted_from" && f(k) != k {
			out = append(out, Finding{Kind: FindingHeaderName, Redactor: "redact",
				Message: "a header member's name holds what the string redactors replace, and the format keeps a header member's name as written"})
		}
	}
	return out
}

// entryErr wraps err with the entry of the original it came from, by
// position, never by its hash.
func entryErr(origID string, pos int, e agentsession.Entry, err error) error {
	return fmt.Errorf("agentredact: redacting %s, entry %d (%s): %w", origID, pos, e.EntryType(), err)
}

// quietRewriteErr is err, from a rewrite, with a message that quotes no
// original text: agentsession's ErrKeyCollision names the two member
// names a rewrite made one, as written in the original, and an error
// travels to logs. errors.Is still finds the sentinel.
func quietRewriteErr(err error) error {
	if errors.Is(err, agentsession.ErrKeyCollision) {
		return &scrubbed{msg: agentsession.ErrKeyCollision.Error() + " (the names are not shown)", err: err}
	}
	return err
}

// hashRef matches a hash as the format writes one.
var hashRef = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// scrubbed is an error whose message names no original hash; errors.Is
// and errors.As reach the error it was made from.
type scrubbed struct {
	msg string
	err error
}

func (e *scrubbed) Error() string { return e.msg }
func (e *scrubbed) Unwrap() error { return e.err }

// scrubErr is err with each entry of original its message names by ID
// named by its position in original's file order instead, and every
// other hash elided. Nil, and an error naming no hash, come back as they
// are.
func scrubErr(err error, original *agentsession.Session) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if !hashRef.MatchString(msg) {
		return err
	}
	pos := map[string]int{}
	if original != nil {
		for i, e := range agentsession.FileOrder(original) {
			pos[e.Base().ID] = i + 1
		}
	}
	msg = hashRef.ReplaceAllStringFunc(msg, func(h string) string {
		if p, ok := pos[h]; ok {
			return "[position " + strconv.Itoa(p) + "]"
		}
		return "sha256:…"
	})
	return &scrubbed{msg: msg, err: err}
}

// clone is a copy of e sharing nothing with it, as a store keeps its
// own: a store may commit the entry it is given into its session.
func clone(e agentsession.Entry) (agentsession.Entry, error) {
	data, err := agentsession.MarshalEntry(e)
	if err != nil {
		return nil, err
	}
	return agentsession.UnmarshalEntry(data)
}
