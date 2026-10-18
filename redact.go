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
	// order, their IDs set: all of them for a new session, and only the
	// new ones for a resumed one, which is what a store appends.
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
// gives cwd, harness's name and version, and every member the format
// does not define, its name and every name and string inside it at any
// depth, to p's string redactors; and writes no base. Two names of one
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
// base: its prefix is redacted into entries of the redaction's own,
// whose positions count in the fork's file order, as RFC 0001 allows.
// Redact has no mode that writes a fork of a redaction; the store pass
// (#3) adds it. A reference into another session, a parents element or
// a link naming one, and parent_session, stays as written, and each is
// reported as a [Finding]; re-pointing them into redactions held
// alongside is the store pass's. So are inline media that is not an
// image and an image data URL inside a longer string, which are kept.
//
// existing, when not nil, is the redaction of original under p that an
// earlier call made, as a store holds it: Redact appends to it, and
// returns it, only the original's entries past the highest position its
// entries name, so a redacted session grows with its original and
// equals, entry for entry, a fresh redaction of the grown original. Its
// header is kept. Redact refuses, with [ErrNotThisRedaction], an
// existing session whose redacted_from names another original or
// another profile, whose ID is not the derived one, that has a base, or
// one of whose entries made from one position is not of the type of the
// original's entry there; and, wrapping [agentsession.ErrStaleOriginal],
// one naming a position past the original's end. Entries appended to it
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
	res := &Result{Session: red, Blobs: map[string][]byte{}}
	for i := done; i < len(order); i++ {
		e, pos := order[i], i+1
		n, err := redactEntry(p, f, rw, remap, original, order, pos, &res.Findings, res.Blobs)
		if err != nil {
			return nil, entryErr(origID, pos, e, err)
		}
		if n.Base().Parent == "" && red.Len() > 0 {
			// A root: Commit puts an entry with no parent under the leaf,
			// and SetRequestHash rebuilds a response's request there.
			red.ResetLeaf()
		}
		if resp, ok := n.(*agentsession.ResponseEntry); ok {
			if resp.RequestHash != "" && original.Verify(e.Base().ID) != nil {
				resp.RequestHash = "" // never certify a request the original could not
			}
			if err := red.SetRequestHash(resp); err != nil {
				return nil, entryErr(origID, pos, e, err)
			}
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
		res.Findings = append(res.Findings, unmetParts(red, r.ID, n, pos)...)
	}
	if len(res.Blobs) == 0 {
		res.Blobs = nil
	}
	return res, nil
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

// redactEntry makes the redacted entry for the original's entry at pos,
// short of its request_hash and its commit: rewritten, redacted,
// re-pointed, marked and its ID cleared.
func redactEntry(p Profile, f StringRedactor, rw *agentsession.Rewriter, remap agentsession.Remap, original *agentsession.Session, order []agentsession.Entry, pos int, findings *[]Finding, blobs map[string][]byte) (agentsession.Entry, error) {
	e := order[pos-1]
	body, err := rw.Rewrite(e)
	if err != nil {
		return nil, err
	}
	for _, r := range p.Entries {
		c := &EntryContext{Original: original, Order: order, Position: pos, redactor: redactorName(r), findings: findings, blobs: blobs}
		out, err := r.RedactEntry(c, body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.redactor, err)
		}
		if out == nil || out.EntryType() != e.EntryType() {
			return nil, fmt.Errorf("%s: returned no %s entry", c.redactor, e.EntryType())
		}
		body = out
	}
	if err := inspect(body, f, pos, findings); err != nil {
		return nil, err
	}
	rr, err := agentsession.RemapRefs(body, remap)
	if err != nil {
		return nil, err
	}
	for _, u := range rr.Unmapped {
		if u.Entry != "" && (u.Session == "" || u.Session == original.ID()) {
			return nil, fmt.Errorf("%s names an entry the redaction has not written", u.At)
		}
		*findings = append(*findings, Finding{
			Position: pos,
			At:       u.At,
			Redactor: "redact",
			Message:  "a reference into another session kept as written: it names that session's original entry or ID, which can confirm a guess, until the store pass re-points it",
		})
	}
	if rr.Opaque {
		*findings = append(*findings, Finding{
			Position: pos,
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
			return agentsession.Header{}, fmt.Errorf("%w: header members %s", agentsession.ErrKeyCollision, pointerToken(name))
		}
		v, err := rewriteJSON(h.Extra[k], f)
		if err != nil {
			return agentsession.Header{}, fmt.Errorf("agentredact: header member %s: %w", pointerToken(name), err)
		}
		if n.Extra == nil {
			n.Extra = map[string]json.RawMessage{}
		}
		n.Extra[name] = v
	}
	if err := extraStaysExtra(n); err != nil {
		return agentsession.Header{}, err
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
	held := agentsession.FileOrder(existing)
	for _, e := range held {
		spans, _ := agentsession.RedactedOf(e) // none on an entry appended natively
		for _, sp := range spans {
			if sp.To > len(order) {
				return 0, fmt.Errorf("agentredact: %s: entry %s names position %d of %s, which holds %d entries: %w", h.ID, e.Base().ID, sp.To, origID, len(order), agentsession.ErrStaleOriginal)
			}
			done = max(done, sp.To)
		}
	}
	for _, e := range held {
		spans, _ := agentsession.RedactedOf(e)
		if len(spans) != 1 || spans[0].From != spans[0].To {
			continue
		}
		o := order[spans[0].From-1]
		if o.EntryType() != e.EntryType() {
			return 0, fmt.Errorf("%w: %s: the entry redacted from position %d is a %s, and the original's there a %s", ErrNotThisRedaction, h.ID, spans[0].From, e.EntryType(), o.EntryType())
		}
		if _, seen := ids[o.Base().ID]; !seen {
			ids[o.Base().ID] = e.Base().ID
		}
	}
	return done, nil
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
