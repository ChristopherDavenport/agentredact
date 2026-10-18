package agentredact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
	// order, their IDs set: all of them for a new session, and only the
	// new ones for a resumed one, which is what a store appends.
	Entries []agentsession.Entry
	// Findings are what the redaction wrote without redacting, which
	// must be looked at before the session leaves: see [Finding].
	Findings []Finding
}

// Redact applies the profile p to the session original and returns the
// redacted session, in memory. Each entry of the original, in its file
// order ([agentsession.FileOrder]), becomes one entry of the redaction:
// its strings rewritten by p's string redactors through one
// [agentsession.Rewriter], then p's entry redactors applied in order,
// its references re-pointed with [agentsession.RemapRefs] to the
// entries already written, and marked redacted with its position,
// [n], counting from 1 ([agentsession.SetRedacted]). A response is then
// given the request_hash its request rebuilds to in the redacted
// session ([agentsession.Session.SetRequestHash]), unless its
// request_hash did not verify in the original, or it had none, when it
// gets none, so the redaction never certifies a request the original
// could not. Then it is committed.
//
// The header is new: it carries redacted, redacted_from naming the
// original and p, and the ID [agentsession.RedactedSessionID] derives
// from the two. Of the original's header members it keeps created_at,
// payload, records, media, parent_session and spawned_by as written;
// gives cwd, harness's name and version, and every string inside the
// members the format does not define, to p's string redactors; and
// writes no base. format is the one agentsession writes. Then each of
// p's entry redactors that is a [HeaderRedactor] redacts it, as
// [Environment] blanks cwd.
//
// An original that is a fork, one with a base, is redacted without a
// base: its prefix is redacted into entries of the redaction's own,
// whose positions count in the fork's file order, as RFC 0001 allows.
// A reference into another session, a parents element or a link naming
// one, and parent_session, stays as written; re-pointing them into
// redactions held alongside is the store pass's.
//
// existing, when not nil, is the redaction of original under p that an
// earlier call made, as a store holds it: Redact appends to it, and
// returns it, only the original's entries past the highest position its
// entries name, so a redacted session grows with its original and
// equals, entry for entry, a fresh redaction of the grown original. Its
// header is kept. Redact refuses, with [ErrNotThisRedaction], an
// existing session whose redacted_from names another original or
// another profile, and, wrapping [agentsession.ErrStaleOriginal], one
// naming a position past the original's end. Entries appended to it
// natively stay where they are. On an error existing may hold some of
// the new entries; discard it and read it again.
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
func Redact(p Profile, original, existing *agentsession.Session) (*Result, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if original == nil {
		return nil, errors.New("agentredact: no original session")
	}
	origID := original.ID()
	redID := agentsession.RedactedSessionID(origID, p.Name)
	f := p.StringFunc()
	order := agentsession.FileOrder(original)
	ids := map[string]string{}
	done := 0
	red := existing
	if red == nil {
		h, err := redactedHeader(p, original.Header(), redID, f)
		if err != nil {
			return nil, err
		}
		red = agentsession.New(h)
	} else {
		var err error
		if done, err = resumePoint(p, origID, redID, existing, order, ids); err != nil {
			return nil, err
		}
	}
	remap := agentsession.Remap{
		Entry: func(session, entry string) (string, bool) {
			if session != "" && session != origID {
				return "", false
			}
			id, ok := ids[entry]
			return id, ok
		},
		Session: func(id string) (string, bool) {
			if id == origID {
				return redID, true
			}
			return "", false
		},
	}
	rw := agentsession.NewRewriter(f)
	// The Rewriter meets every entry from the first, so a part named by
	// hash in a new entry names the rewritten text an earlier one holds.
	for i := 0; i < done; i++ {
		if _, err := rw.Rewrite(order[i]); err != nil {
			return nil, entryErr(origID, i+1, order[i], err)
		}
	}
	res := &Result{Session: red}
	for i := done; i < len(order); i++ {
		e, pos := order[i], i+1
		n, err := redactEntry(p, rw, remap, original, order, pos, &res.Findings)
		if err != nil {
			return nil, entryErr(origID, pos, e, err)
		}
		if resp, ok := n.(*agentsession.ResponseEntry); ok {
			if resp.RequestHash != "" && original.Verify(e.Base().ID) != nil {
				resp.RequestHash = "" // never certify a request the original could not
			}
			if err := red.SetRequestHash(resp); err != nil {
				return nil, entryErr(origID, pos, e, err)
			}
		}
		if n.Base().Parent == "" && red.Len() > 0 {
			red.ResetLeaf() // a root: Commit puts an entry with no parent under the leaf
		}
		r, err := red.Commit(n)
		if err != nil {
			return nil, entryErr(origID, pos, e, err)
		}
		if r.Outcome == agentsession.Held {
			return nil, entryErr(origID, pos, e, errors.New("the redacted session already holds the entry"))
		}
		ids[e.Base().ID] = r.ID
		res.Entries = append(res.Entries, n)
		res.Findings = append(res.Findings, unmetParts(red, r.ID, n, pos, e.Base().ID)...)
	}
	return res, nil
}

// unmetParts reports each instruction part of n, committed to red as
// id, that is named by a hash the redacted session cannot resolve on
// its path: a hash of text the Rewriter never met, which is the
// original's hash still. It names the part by its index and its id,
// never by its hash or text.
func unmetParts(red *agentsession.Session, id string, n agentsession.Entry, pos int, origID string) []Finding {
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
		return Finding{Position: pos, Entry: origID, At: at + strconv.Itoa(i), Redactor: "redact", Message: message}
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

// redactEntry makes the redacted entry for the original's entry at pos,
// short of its request_hash and its commit: rewritten, redacted,
// re-pointed, marked and its ID cleared.
func redactEntry(p Profile, rw *agentsession.Rewriter, remap agentsession.Remap, original *agentsession.Session, order []agentsession.Entry, pos int, findings *[]Finding) (agentsession.Entry, error) {
	e := order[pos-1]
	body, err := rw.Rewrite(e)
	if err != nil {
		return nil, err
	}
	for _, r := range p.Entries {
		c := &EntryContext{Original: original, Order: order, Position: pos, redactor: redactorName(r), findings: findings}
		out, err := r.RedactEntry(c, body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.redactor, err)
		}
		if out == nil || out.EntryType() != e.EntryType() {
			return nil, fmt.Errorf("%s: returned no %s entry", c.redactor, e.EntryType())
		}
		body = out
	}
	rr, err := agentsession.RemapRefs(body, remap)
	if err != nil {
		return nil, err
	}
	for _, u := range rr.Unmapped {
		if u.Entry != "" && (u.Session == "" || u.Session == original.ID()) {
			return nil, fmt.Errorf("%s names %s, which the redaction has not written", u.At, u.Entry)
		}
	}
	if rr.Opaque {
		*findings = append(*findings, Finding{
			Position: pos,
			Entry:    e.Base().ID,
			Redactor: "redact",
			Message:  "extension entry: its parent and parents were re-pointed, but a member of its own may still name an entry of the original",
		})
	}
	n := rr.Entry
	n.Base().ID = ""
	if err := agentsession.SetRedacted(n, []agentsession.Span{{From: pos, To: pos}}); err != nil {
		return nil, err
	}
	return n, nil
}

// redactedHeader is the header of a new redaction of the original whose
// header is h.
func redactedHeader(p Profile, h agentsession.Header, redID string, f StringRedactor) (agentsession.Header, error) {
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
	for k, raw := range h.Extra {
		if k == "redacted_from" {
			continue // a member in another form, from before 0.13: this header writes its own
		}
		v, err := rewriteJSON(raw, f)
		if err != nil {
			return agentsession.Header{}, fmt.Errorf("agentredact: header member %s: %w", k, err)
		}
		if n.Extra == nil {
			n.Extra = map[string]json.RawMessage{}
		}
		n.Extra[k] = v
	}
	n, _ = agentsession.RemapHeaderRefs(n, agentsession.Remap{
		Session: func(id string) (string, bool) {
			if id == h.ID {
				return redID, true
			}
			return "", false
		},
	})
	for _, r := range p.Entries {
		if hr, ok := r.(HeaderRedactor); ok {
			if err := hr.RedactHeader(&n); err != nil {
				return agentsession.Header{}, fmt.Errorf("agentredact: header: %s: %w", redactorName(r), err)
			}
		}
	}
	n.ID, n.Redacted, n.Base = redID, true, ""
	n.RedactedFrom = &agentsession.RedactedFrom{Session: h.ID, Profile: p.Name}
	if err := agentsession.CheckCreate(n, false); err != nil {
		return agentsession.Header{}, err
	}
	return n, nil
}

// resumePoint checks that existing is the redaction of the original
// under p, fills ids with the original's entries it already holds
// redactions of, and returns the highest original position its entries
// name: the original's entries up to it are done.
func resumePoint(p Profile, origID, redID string, existing *agentsession.Session, order []agentsession.Entry, ids map[string]string) (int, error) {
	h := existing.Header()
	switch {
	case !h.Redacted || h.RedactedFrom == nil:
		return 0, fmt.Errorf("%w: %s is not a redacted session", ErrNotThisRedaction, h.ID)
	case h.RedactedFrom.Session != origID:
		return 0, fmt.Errorf("%w: %s was redacted from %s, not %s", ErrNotThisRedaction, h.ID, h.RedactedFrom.Session, origID)
	case h.RedactedFrom.Profile != p.Name:
		return 0, fmt.Errorf("%w: %s was redacted under profile %q, not %q", ErrNotThisRedaction, h.ID, h.RedactedFrom.Profile, p.Name)
	case h.ID != redID:
		return 0, fmt.Errorf("%w: %s is not the ID the original and profile derive, %s", ErrNotThisRedaction, h.ID, redID)
	case h.Base != "":
		return 0, fmt.Errorf("%w: %s has a base; resuming a fork of a redaction is the store pass's", ErrNotThisRedaction, h.ID)
	}
	done := 0
	for _, e := range agentsession.FileOrder(existing) {
		spans, ok := agentsession.RedactedOf(e)
		if !ok {
			continue // appended natively
		}
		for _, sp := range spans {
			if sp.To > len(order) {
				return 0, fmt.Errorf("agentredact: %s: entry %s names position %d of %s, which holds %d entries: %w", h.ID, e.Base().ID, sp.To, origID, len(order), agentsession.ErrStaleOriginal)
			}
			done = max(done, sp.To)
		}
		if len(spans) == 1 && spans[0].From == spans[0].To {
			orig := order[spans[0].From-1].Base().ID
			if _, seen := ids[orig]; !seen {
				ids[orig] = e.Base().ID
			}
		}
	}
	return done, nil
}

// entryErr wraps err with the entry of the original it came from.
func entryErr(origID string, pos int, e agentsession.Entry, err error) error {
	return fmt.Errorf("agentredact: redacting %s, entry %d (%s %s): %w", origID, pos, e.EntryType(), e.Base().ID, err)
}

// rewriteJSON applies f to every string value in raw, JSON, at any
// depth; member names, numbers and literals are kept as written.
func rewriteJSON(raw json.RawMessage, f StringRedactor) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var walk func(v any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			return f(x)
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case map[string]any:
			for _, k := range sortedMembers(x) {
				x[k] = walk(x[k])
			}
		}
		return v
	}
	v = walk(v)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// nonEmpty is f(s) for a string that is not empty, and "" for one that
// is, so an absent header member stays absent.
func nonEmpty(s string, f StringRedactor) string {
	if s == "" {
		return ""
	}
	return f(s)
}
