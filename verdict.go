package agentredact

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ChristopherDavenport/agentsession"
)

// Verdict is a judgement of a redacted session its redaction did not
// make, such as a scan's or a review's (#4, #5): whether the session may
// leave, and what was found, by kind and count, never by value. It is
// written as an outcome in a fork of the redacted session at the last
// entry judged ([WriteVerdict]), as RFC 0001 0.19 has a judge write one
// (The redacted session): not into the redacted session, where it would
// be a native entry that a redacted-only store refuses, so the verdict
// cannot be published with the session it judged.
type Verdict struct {
	// Judge names what judged, such as "scan" or "review": one verdict
	// per judge per judged entry.
	Judge string
	// Kind is the outcome's kind: "test" for a verifier such as a scan,
	// "eval" for an evaluation such as a review.
	Kind string
	// Pass is the verdict: the session, up to the judged entry, may leave.
	Pass bool
	// Findings counts what was found, by kind, such as a TruffleHog
	// detector's name.
	Findings map[string]int
	// Entries names the redacted session's own entries something was
	// found in, by their IDs in the redacted session, which name no
	// original.
	Entries []string
	// Covered is the state of the redacted session the verdict judged
	// ([StateOf]), which [WriteVerdict] records: a verdict clears that
	// state and no other.
	Covered State
}

// State is what a redacted session holds, as a verdict covers it and a
// report reads it: its head ([JudgedEntry]), and every entry it holds,
// on every branch, but leaf labels, which move the head and carry
// nothing, counted and digested. Two states are one only when the
// session holds exactly the same entries under the same head, so an
// entry appended on a branch, which leaves the head where it was, is a
// new state, and a leaf label moving the head back is no way round it.
type State struct {
	Head    string `json:"head"`
	Entries int    `json:"entries"`
	// Digest is sha256:<hex> over the entries' IDs, sorted, each ended
	// by a newline.
	Digest string `json:"digest"`
}

// StateOf is the state of the session s.
func StateOf(s *agentsession.Session) State {
	var ids []string
	for _, e := range agentsession.FileOrder(s) {
		if l, ok := e.(*agentsession.LabelEntry); ok && l.Label != nil && *l.Label == agentsession.LeafLabel {
			continue
		}
		ids = append(ids, e.Base().ID)
	}
	slices.Sort(ids)
	h := sha256.New()
	for _, id := range ids {
		h.Write([]byte(id + "\n"))
	}
	return State{Head: JudgedEntry(s), Entries: len(ids), Digest: "sha256:" + hex.EncodeToString(h.Sum(nil))}
}

// VerdictHarness is the harness a verdict session's header names, by
// which [Verdicts] lists them and [RedactStore] skips them.
const VerdictHarness = "agentredact"

// verdictMember is the header member that marks a verdict session and
// names its judge.
const verdictMember = "agentredact:verdict"

// details is the outcome's details: what was found, never a value or a
// hash of one.
type verdictDetails struct {
	Findings map[string]int `json:"agentredact:findings"`
	Entries  []string       `json:"agentredact:entries,omitempty"`
	Covered  *State         `json:"agentredact:covered,omitempty"`
}

// ErrNotRedacted is returned by [WriteVerdict] for a session that is
// not a redacted one.
var ErrNotRedacted = errors.New("agentredact: not a redacted session")

// JudgedEntry is the entry a verdict on red's path to its leaf names:
// the leaf, or, when that is a leaf label, its nearest ancestor that is
// not one (RFC 0001 0.19). "" for a session with no entry.
func JudgedEntry(red *agentsession.Session) string {
	path := red.Path(red.Leaf())
	for i := len(path) - 1; i >= 0; i-- {
		if l, ok := path[i].(*agentsession.LabelEntry); ok && l.Label != nil && *l.Label == agentsession.LeafLabel {
			continue
		}
		return path[i].Base().ID
	}
	return ""
}

// VerdictID is the ID of the verdict judge writes on the redacted
// session red at its entry judged at the time at: a UUIDv5 under the nil
// namespace over ["agentredact/verdict", red, judged, judge, at], at in
// RFC 3339 with nanoseconds, so one judgement written again names one
// session, and each judgement made another.
func VerdictID(red, judged, judge string, at time.Time) string {
	name, _ := json.Marshal([]string{"agentredact/verdict", red, judged, judge, at.UTC().Format(time.RFC3339Nano)}) // strings always encode
	h := sha1.New()
	h.Write(make([]byte, 16)) // the nil namespace
	h.Write(name)
	var b [16]byte
	copy(b[:], h.Sum(nil))
	b[6] = 0x50 | b[6]&0x0f
	b[8] = 0x80 | b[8]&0x3f
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// WriteVerdict returns the session recording v on the redacted session
// red, judged up to the entry judged ([JudgedEntry] for its leaf): a
// fork of red whose base is that entry, whose parent_session is red's
// ID, whose header carries no redacted and names [VerdictHarness], and
// whose one own entry is an outcome of v's kind targeting the base, its
// pass v's, its details the findings by kind and count and the entries
// they were found in. at is the outcome's time. The caller stores it in
// the private store beside red; a store that holds only redacted
// entries refuses it, so a verdict never leaves with the session.
func WriteVerdict(red *agentsession.Session, judged string, v Verdict, at time.Time) (*agentsession.Session, error) {
	h := red.Header()
	if !h.Redacted {
		return nil, fmt.Errorf("%w: %s", ErrNotRedacted, red.ID())
	}
	if v.Judge == "" || v.Kind == "" {
		return nil, errors.New("agentredact: a verdict names its judge and its kind")
	}
	if _, ok := red.Entry(judged); !ok {
		return nil, fmt.Errorf("%w: %s holds no entry %s", agentsession.ErrNoEntry, red.ID(), judged)
	}
	judge, err := json.Marshal(struct {
		Judge string `json:"judge"`
	}{v.Judge})
	if err != nil {
		return nil, err
	}
	f, err := agentsession.Fork(red, judged, agentsession.Header{
		ID:            VerdictID(red.ID(), judged, v.Judge, at),
		CreatedAt:     at.UTC(),
		ParentSession: red.ID(),
		Harness:       &agentsession.Harness{Name: VerdictHarness},
		Extra:         map[string]json.RawMessage{verdictMember: judge},
	})
	if err != nil {
		return nil, fmt.Errorf("agentredact: forking %s for a verdict: %w", red.ID(), err)
	}
	entries := slices.Clone(v.Entries)
	slices.Sort(entries)
	covered := StateOf(red)
	if covered.Head != judged {
		return nil, fmt.Errorf("agentredact: a verdict judges a session up to its head, %s, not %s", covered.Head, judged)
	}
	d := verdictDetails{Findings: v.Findings, Entries: slices.Compact(entries), Covered: &covered}
	if d.Findings == nil {
		d.Findings = map[string]int{}
	}
	details, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	pass := v.Pass
	o := agentsession.NewOutcomeEntry(v.Kind, judged)
	o.Pass, o.Label, o.Details = &pass, "agentredact/"+v.Judge, details
	o.Timestamp = at.UTC()
	if _, err := f.Append(o); err != nil {
		return nil, fmt.Errorf("agentredact: the verdict: %w", err)
	}
	return f, nil
}

// isVerdict reports whether h is a verdict session's header.
func isVerdict(h agentsession.Header) bool {
	_, ok := h.Extra[verdictMember]
	return ok && h.Harness != nil && h.Harness.Name == VerdictHarness
}

// RecordedVerdict is a verdict as a store holds it.
type RecordedVerdict struct {
	Verdict
	// Session is the verdict session's ID, and Judged the redacted
	// session's entry it judged up to.
	Session, Judged string
	// At is the outcome's time.
	At time.Time
}

// Verdicts lists the verdicts st holds on the redacted session red,
// oldest first, then by judge.
func Verdicts(ctx context.Context, st agentsession.Store, red string) ([]RecordedVerdict, error) {
	var out []RecordedVerdict
	for sum, err := range st.List(ctx, agentsession.ListFilter{ParentSession: red, Harness: VerdictHarness}) {
		if err != nil {
			return nil, err
		}
		if !isVerdict(sum.Header) {
			continue
		}
		s, err := readHeld(ctx, st, sum.Header.ID)
		if err != nil {
			return nil, err
		}
		for _, e := range s.Entries() {
			o, ok := e.(*agentsession.OutcomeEntry)
			if !ok || s.Prefix(o.ID) || o.Pass == nil {
				continue
			}
			var d verdictDetails
			if len(o.Details) > 0 {
				if err := json.Unmarshal(o.Details, &d); err != nil {
					return nil, fmt.Errorf("agentredact: verdict %s: %w", s.ID(), err)
				}
			}
			judge := o.Label
			if len(judge) > len("agentredact/") {
				judge = judge[len("agentredact/"):]
			}
			out = append(out, RecordedVerdict{
				Verdict: Verdict{Judge: judge, Kind: o.Kind, Pass: *o.Pass, Findings: d.Findings, Entries: d.Entries, Covered: covered(d.Covered)},
				Session: s.ID(), Judged: o.Target, At: o.Timestamp,
			})
		}
	}
	slices.SortStableFunc(out, func(a, b RecordedVerdict) int {
		if c := a.At.Compare(b.At); c != 0 {
			return c
		}
		if a.Judge < b.Judge {
			return -1
		}
		if a.Judge > b.Judge {
			return 1
		}
		return 0
	})
	return out, nil
}

// covered is the state a verdict records, the zero State for one that
// records none, which clears nothing.
func covered(s *State) State {
	if s == nil {
		return State{}
	}
	return *s
}

// Cleared reports whether every judge of judges passed red in exactly
// the state it holds now ([StateOf]: its head and every entry, on every
// branch), the latest such verdict of each counting. A session that
// changed after it was judged, by an entry on any branch, waits for a
// new verdict.
func Cleared(verdicts []RecordedVerdict, red *agentsession.Session, judges ...string) bool {
	now := StateOf(red)
	for _, j := range judges {
		ok := false
		for _, v := range verdicts {
			if v.Judge == j && v.Covered.Digest != "" && v.Covered == now && v.Judged == now.Head {
				ok = v.Pass
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
