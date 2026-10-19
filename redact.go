package agentredact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

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
	Blobs map[string][]byte
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
}

// Alongside is what [Redact] is told of the other sessions redacted
// with this one under the same profile, so that it re-points the
// references into them, as RFC 0001 has a redaction that holds another
// session's redaction do: parent_session, a parents element naming an
// entry of another session, and a link's session.
type Alongside struct {
	// Sessions maps another session's original ID to its redaction's
	// ID, [agentsession.RedactedSessionID] of the two. A reference to
	// a session named here is re-pointed to its redaction; one to a
	// session not named here is kept as written and reported as a
	// [Finding].
	Sessions map[string]string
	// Entries maps a session of Sessions, by original ID, to its
	// redaction's [Result.Counterparts]. A parents element naming an
	// entry of such a session is re-pointed to the entry standing for
	// it there, or removed, with a Finding, when that one was left out,
	// as a parents element naming an entry of this session left out is.
	// A parents element naming an entry of a session in Sessions whose
	// entries are not given, or an entry its Counterparts does not hold,
	// is refused with [ErrUnmappedRef]: the session is redacted
	// alongside, so the reference cannot stay as written.
	Entries map[string]map[string]string
}

// WithAlongside tells [Redact] of the sessions redacted alongside.
func WithAlongside(a Alongside) Option {
	return func(o *options) { o.alongside = a }
}

// ErrUnmappedRef is returned by [Redact] for a reference into a session
// redacted alongside ([Alongside]) that it cannot re-point: one whose
// entry the session's counterparts do not hold, or whose counterparts
// were not given.
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
// The header is new: it carries redacted, redacted_from naming the
// original and p, and the ID [agentsession.RedactedSessionID] derives
// from the two. Of the original's header members it keeps created_at,
// payload, records, media and spawned_by as written; re-points
// parent_session as a reference into another session (below); gives
// cwd, harness's name and version, and every member the format does
// not define, its name and every name and string inside it at any
// depth, to p's string redactors; and writes no base unless it is a
// fork of its origin's redaction ([WithOrigin]). Two names of one
// object made one, or a name made one the format defines, is refused
// with [agentsession.ErrKeyCollision]. format is the one agentsession
// writes. Then each of p's entry redactors that is a [HeaderRedactor]
// redacts it, as [Environment] blanks cwd.
//
// An entry holding a member name, at any depth, that p's string
// redactors would change is refused with [ErrKeyNotRedacted]: the
// Rewriter gives a redactor no member name but an env entry's file
// paths, so the name would be written as the original had it. The check
// cannot tell a name the format defines from one a writer chose, so a
// rule that would change a format member name, such as a literal rule
// for "content", refuses every entry that holds it.
//
// An original that is a fork, one with a base, is redacted without a
// base unless an origin is given: its prefix is redacted into entries of
// the redaction's own, whose positions count in the fork's file order,
// as RFC 0001 allows. Given its origin's redaction ([WithOrigin]), it
// is redacted as a fork of that, sharing its prefix.
//
// A reference into another session, a parents element or a link naming
// one, and parent_session, is re-pointed to that session's redaction
// when the session is redacted alongside ([WithAlongside]), as RFC 0001
// has a redaction holding another session's redaction do; a parents
// element naming an entry that redaction left out is removed and
// reported, and one it cannot re-point is refused with [ErrUnmappedRef].
// A reference into a session not redacted alongside stays as written,
// and each is reported as a [Finding], parent_session's with position
// 0. So are inline media that is not an image and an image data URL
// inside a longer string, which are kept.
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
// existing session whose redacted_from names another original or
// another profile, whose ID is not the derived one, that has a base
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
// An instruction part named by the hash of a text the Rewriter never
// met, in no entry of the original before it, keeps the original's
// hash, since the Rewriter has no rewritten text to name: the redacted
// session then does not hash independently there, and the hash can
// confirm a guessed text. Redact reports each such part as a [Finding]
// with its entry's position, its pointer and the part's id, never its
// hash or text.
//
// An error from agentsession, such as [agentsession.ErrInstructionsJoin]
// or [agentsession.ErrKeyCollision], is wrapped with the position and
// ID of the entry that failed, and errors.Is finds it.
func Redact(p Profile, original, existing *agentsession.Session, opts ...Option) (*Result, error) {
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
	r := newRedaction(p, original, o.alongside)
	if o.origin != nil {
		if err := r.forkFrom(o.origin); err != nil {
			return nil, err
		}
	}
	var found []Finding
	if existing == nil {
		h, hf, err := redactedHeader(p, original.Header(), r.redID, r.f, r.remap(nil))
		if err != nil {
			return nil, err
		}
		found = hf
		if r.red, err = r.newSession(h, o.origin); err != nil {
			return nil, err
		}
	} else {
		if err := r.resume(existing); err != nil {
			return nil, err
		}
		r.red = existing
	}
	r.res = &Result{Session: r.red, Blobs: map[string][]byte{}, Findings: found}
	var err error
	if r.out, err = r.sessions(); err != nil {
		return nil, err
	}
	if err := r.checkSessions(r.out); err != nil {
		return nil, err
	}
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
// validated.
func newRedaction(p Profile, original *agentsession.Session, along Alongside) *redaction {
	r := &redaction{
		p:        p,
		f:        p.StringFunc(),
		original: original,
		order:    agentsession.FileOrder(original),
		origID:   original.ID(),
		placed:   map[string]*placed{},
		along:    along,
	}
	r.redID = agentsession.RedactedSessionID(r.origID, p.Name)
	r.rw = agentsession.NewRewriter(r.f)
	return r
}

// newSession is the new redacted session whose header is h: a fork of
// the origin's redaction at r.base when r is a fork of it, and a
// session of its own otherwise.
func (r *redaction) newSession(h agentsession.Header, o *Origin) (*agentsession.Session, error) {
	if !r.fork {
		return agentsession.New(h), nil
	}
	h.Base, h.ParentSession = r.base, r.originRedID
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
		body, err := r.rw.Rewrite(e)
		if err != nil {
			return entryErr(r.origID, pos, e, err)
		}
		if pos <= r.prefixLen {
			continue // a fork's prefix: the origin's redaction decided it
		}
		if r.out[i] {
			r.placed[e.Base().ID] = &placed{fate: dropped, pos: pos}
			r.leftOut = true
			continue
		}
		if err := r.entry(pos, e, body); err != nil {
			return entryErr(r.origID, pos, e, err)
		}
	}
	return nil
}

// unmetParts reports each instruction part of n, committed to red as
// id, that is named by a hash the redacted session cannot resolve on
// its path: a hash of text the Rewriter never met, which is the
// original's hash still. It names the part by its index and its id,
// never by its hash or text.
func unmetParts(red *agentsession.Session, id string, n agentsession.Entry, pos int) []Finding {
	var (
		parts []agentsession.InstructionPart
		at    string
	)
	switch v := n.(type) {
	case *agentsession.ConfigEntry:
		parts, at = v.InstructionsParts, "/instructions_parts/"
	case *agentsession.CompactionEntry:
		parts, at = v.Config.InstructionsParts, "/config/instructions_parts/"
	default:
		return nil
	}
	var byHash []int
	for i, part := range parts {
		if part.Text == "" && part.Hash != "" {
			byHash = append(byHash, i)
		}
	}
	if len(byHash) == 0 {
		return nil
	}
	finding := func(i int, message string) Finding {
		return Finding{Position: pos, At: at + strconv.Itoa(i), Redactor: "redact", Message: message}
	}
	var out []Finding
	ctx, err := red.ContextAt(id)
	if err != nil {
		for _, i := range byHash {
			out = append(out, finding(i, fmt.Sprintf("instruction part %q is named by a hash that could not be checked against the redacted session, which may be the original's", parts[i].ID)))
		}
		return out
	}
	inForce := map[string]agentsession.InstructionPart{}
	for _, part := range ctx.Settings.InstructionsParts {
		inForce[part.ID] = part
	}
	for _, i := range byHash {
		if now, ok := inForce[parts[i].ID]; ok && !now.Unresolved() {
			continue
		}
		out = append(out, finding(i, fmt.Sprintf("instruction part %q keeps the original's hash: its text is in no entry the redaction was given, so the hash was not rewritten, and it can confirm a guessed text", parts[i].ID)))
	}
	return out
}

// redactedHeader is the header of a new redaction of the original whose
// header is h, its session references re-pointed through remap, and
// the findings for those it kept as written.
func redactedHeader(p Profile, h agentsession.Header, redID string, f StringRedactor, remap agentsession.Remap) (agentsession.Header, []Finding, error) {
	n := agentsession.Header{
		ID:            redID,
		CreatedAt:     h.CreatedAt,
		Payload:       h.Payload,
		Records:       append([]string(nil), h.Records...),
		CWD:           h.CWD,
		ParentSession: h.ParentSession,
		SpawnedBy:     h.SpawnedBy,
		Media:         h.Media,
		Redacted:      true,
		RedactedFrom:  &agentsession.RedactedFrom{Session: h.ID, Profile: p.Name},
	}
	n.CWD = nonEmpty(n.CWD, f)
	if h.Harness != nil {
		n.Harness = &agentsession.Harness{Name: nonEmpty(h.Harness.Name, f), Version: nonEmpty(h.Harness.Version, f)}
	}
	keys := make([]string, 0, len(h.Extra))
	for k := range h.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "redacted_from" {
			continue // a member in another form, from before 0.13: this header writes its own
		}
		name := f(k)
		if _, taken := n.Extra[name]; taken {
			return agentsession.Header{}, nil, fmt.Errorf("%w: header members %s", agentsession.ErrKeyCollision, pointerToken(name))
		}
		v, err := rewriteJSON(h.Extra[k], f)
		if err != nil {
			return agentsession.Header{}, nil, fmt.Errorf("agentredact: header member %s: %w", pointerToken(name), err)
		}
		if n.Extra == nil {
			n.Extra = map[string]json.RawMessage{}
		}
		n.Extra[name] = v
	}
	if err := extraStaysExtra(n); err != nil {
		return agentsession.Header{}, nil, err
	}
	n, unmapped := agentsession.RemapHeaderRefs(n, agentsession.Remap{Session: remap.Session})
	var found []Finding
	for _, u := range unmapped {
		found = append(found, Finding{At: u.At, Redactor: "redact", Message: "a reference into another session kept as written: it names that session's original ID, which can confirm a guess, as no redaction of it is held alongside"})
	}
	for _, r := range p.Entries {
		if hr, ok := r.(HeaderRedactor); ok {
			if err := hr.RedactHeader(&n); err != nil {
				return agentsession.Header{}, nil, fmt.Errorf("agentredact: header: %s: %w", redactorName(r), err)
			}
		}
	}
	n.ID, n.Redacted, n.Base = redID, true, ""
	n.RedactedFrom = &agentsession.RedactedFrom{Session: h.ID, Profile: p.Name}
	if err := agentsession.CheckCreate(n, false); err != nil {
		return agentsession.Header{}, nil, err
	}
	return n, found, nil
}

// entryErr wraps err with the entry of the original it came from.
func entryErr(origID string, pos int, e agentsession.Entry, err error) error {
	return fmt.Errorf("agentredact: redacting %s, entry %d (%s %s): %w", origID, pos, e.EntryType(), e.Base().ID, err)
}

// rewriteJSON applies f to every string value and every member name in
// raw, JSON, at any depth; numbers and literals are kept as written. Two
// names of one object made one are [agentsession.ErrKeyCollision], named
// by a pointer built from rewritten names.
func rewriteJSON(raw json.RawMessage, f StringRedactor) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var walk func(v any, at string) (any, error)
	walk = func(v any, at string) (any, error) {
		switch x := v.(type) {
		case string:
			return f(x), nil
		case []any:
			for i := range x {
				w, err := walk(x[i], fmt.Sprintf("%s/%d", at, i))
				if err != nil {
					return nil, err
				}
				x[i] = w
			}
		case map[string]any:
			out := make(map[string]any, len(x))
			for _, k := range sortedMembers(x) {
				name := f(k)
				if _, taken := out[name]; taken {
					return nil, fmt.Errorf("%w: at %s", agentsession.ErrKeyCollision, at+"/"+pointerToken(name))
				}
				w, err := walk(x[k], at+"/"+pointerToken(name))
				if err != nil {
					return nil, err
				}
				out[name] = w
			}
			return out, nil
		}
		return v, nil
	}
	v, err := walk(v, "")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// extraStaysExtra refuses a header one of whose members the format does
// not define was renamed to a member it does, which agentsession would
// read as that member: the header is written and read again, and Extra
// must come back whole.
func extraStaysExtra(h agentsession.Header) error {
	if h.Format == "" {
		h.Format = agentsession.Format // what New fills, under which redacted_from is typed
	}
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	var back agentsession.Header
	if err := json.Unmarshal(data, &back); err != nil {
		return err
	}
	if len(back.Extra) != len(h.Extra) {
		return fmt.Errorf("%w: a header member was renamed to one the format defines", agentsession.ErrKeyCollision)
	}
	return nil
}

// nonEmpty is f(s) for a string that is not empty, and "" for one that
// is, so an absent header member stays absent.
func nonEmpty(s string, f StringRedactor) string {
	if s == "" {
		return ""
	}
	return f(s)
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
