package agentredact

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentsession"
)

// Every fixture here is synthetic, as in redact_test.go.

// userAt appends a user message under parent, or under the leaf when
// parent is "".
func userAt(t *testing.T, s *agentsession.Session, c *clock, parent, text string) string {
	t.Helper()
	e := user(text)
	e.Parent = parent
	return appendAt(t, s, c, e)
}

// fork forks origin at the entry at, as a store's Create does, with a
// header of its own.
func fork(t *testing.T, origin *agentsession.Session, at, id string) *agentsession.Session {
	t.Helper()
	f, err := agentsession.Fork(origin, at, agentsession.Header{ID: id, CreatedAt: t0, CWD: fakeHome + "/fork"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// redactFork redacts f as a fork of the origin's redaction.
func redactFork(t *testing.T, p Profile, f, existing *agentsession.Session, o *Origin) *Result {
	t.Helper()
	res, err := Redact(p, f, existing, WithOrigin(o))
	if err != nil {
		t.Fatalf("Redact as a fork: %v", err)
	}
	return res
}

func readBack(t *testing.T, s *agentsession.Session) *agentsession.Session {
	t.Helper()
	back, err := agentsession.Read(bytes.NewReader(fileOf(t, s)))
	if err != nil {
		t.Fatalf("read back: %v\n%s", err, fileOf(t, s))
	}
	return back
}

// checkFork holds res, the redaction of the fork f as a fork of
// originRed, to the rules: linked to it at the entry standing for f's
// base, its prefix that redaction's path there, its own entries marked
// past f's prefix unless a placeholder of the prefix, no planted value,
// every response verifying when read back alone, every member naming
// an entry the file holds, and a rerun writing the same bytes.
func checkFork(t *testing.T, p Profile, f *agentsession.Session, res *Result, o *Origin, wantOwn []string) {
	t.Helper()
	red := res.Session
	h := red.Header()
	if h.ID != agentsession.RedactedSessionID(f.ID(), p.Name) || !h.Redacted || h.RedactedFrom == nil || h.RedactedFrom.Session != f.ID() {
		t.Errorf("header %+v", h)
	}
	if h.ParentSession != o.Redaction.ID() || h.Base == "" {
		t.Fatalf("parent_session %q, base %q: not a fork of %s", h.ParentSession, h.Base, o.Redaction.ID())
	}
	if _, ok := o.Redaction.Entry(h.Base); !ok {
		t.Errorf("the base %s is not an entry of the origin's redaction", h.Base)
	}
	var prefix, want []string
	for _, e := range agentsession.FileOrder(red) {
		if red.Prefix(e.Base().ID) {
			prefix = append(prefix, e.Base().ID)
		}
	}
	for _, e := range o.Redaction.Path(h.Base) {
		want = append(want, e.Base().ID)
	}
	if !slices.Equal(prefix, want) {
		t.Errorf("the prefix is not the origin's redaction's path to the base:\n%v\n%v", prefix, want)
	}
	var own []string
	for _, e := range agentsession.FileOrder(red) {
		if !red.Prefix(e.Base().ID) {
			spans, ok := agentsession.RedactedOf(e)
			if !ok {
				t.Errorf("own entry %s carries no redacted", e.Base().ID)
			}
			own = append(own, markKey(spans))
		}
	}
	if strings.Join(own, " ") != strings.Join(wantOwn, " ") {
		t.Errorf("own marks %q, want %q", own, wantOwn)
	}
	if len(res.Entries) != len(own) {
		t.Errorf("Result.Entries holds %d, the session %d own entries", len(res.Entries), len(own))
	}
	file := fileOf(t, red)
	for _, v := range planted {
		if bytes.Contains(file, []byte(v)) {
			t.Errorf("the redaction kept %q", v)
		}
	}
	back := readBack(t, red)
	verified := 0
	for _, e := range back.Entries() {
		if r, ok := e.(*agentsession.ResponseEntry); ok && r.RequestHash != "" {
			verified++
			if err := back.Verify(r.ID); err != nil {
				t.Errorf("response %s does not verify: %v", r.ResponseID, err)
			}
		}
		if _, err := agentsession.RemapRefs(e, agentsession.Remap{Entry: func(session, id string) (string, bool) {
			if session == "" || session == back.ID() {
				if _, ok := back.Entry(id); !ok {
					t.Errorf("entry %s names %s, which the file does not hold", e.Base().ID, id)
				}
			}
			return id, true
		}}); err != nil {
			t.Fatal(err)
		}
	}
	if verified == 0 {
		t.Error("no response with a request_hash; the case proves nothing")
	}
	if again := redactFork(t, p, f, nil, o); !bytes.Equal(fileOf(t, again.Session), file) {
		t.Errorf("a rerun wrote other bytes")
	}
}

// checkOriginal holds the redactions to agentsession.Original over a
// store holding them and their originals: every entry made from one
// position maps to an entry of its original of its type, the prefix's
// counted in the origin's original.
func checkOriginal(t *testing.T, originals, redactions []*agentsession.Session) {
	t.Helper()
	ctx := context.Background()
	st := agentsession.NewMemoryStore()
	for _, s := range append(slices.Clone(originals), redactions...) {
		if _, err := st.Import(ctx, bytes.NewReader(fileOf(t, s)), true); err != nil {
			t.Fatalf("import %s: %v", s.ID(), err)
		}
	}
	for _, red := range redactions {
		held, err := st.Read(ctx, red.ID())
		if err != nil {
			t.Fatal(err)
		}
		orig, m, err := agentsession.Original(ctx, st, held)
		if err != nil {
			t.Fatalf("Original of %s: %v", red.ID(), err)
		}
		mapped := 0
		for _, e := range held.Entries() {
			ids := m[e.Base().ID]
			spans, _ := agentsession.RedactedOf(e)
			if isPlaceholder(e) || len(spans) != 1 || spans[0].From != spans[0].To {
				continue
			}
			if len(ids) != 1 {
				t.Errorf("%s: entry %s marked %s maps to %v", red.ID(), e.Base().ID, markKey(spans), ids)
				continue
			}
			o, ok := orig.Entry(ids[0])
			if !ok || o.EntryType() != e.EntryType() {
				t.Errorf("%s: entry %s (%s) marked %s maps to %s, not an entry of its type in %s", red.ID(), e.Base().ID, e.EntryType(), markKey(spans), ids[0], orig.ID())
			}
			mapped++
		}
		if mapped == 0 {
			t.Errorf("%s: nothing mapped", red.ID())
		}
	}
}

// TestForkOfRedaction redacts forks as forks of their origin's
// redaction: at a kept base, at a base folded into a block no own entry
// of the origin had closed, and down a line of forks, at an entry of
// the origin's own and at one of its prefix. Each is grown with its
// origin and resumed, equal to a fresh redaction.
func TestForkOfRedaction(t *testing.T) {
	p := blockProfile("test.fork-of@1")

	t.Run("kept base", func(t *testing.T) {
		c := &clock{}
		o := newOriginal("orig-o")
		userAt(t, o, c, "", "start "+fakeKey)             // 1
		userAt(t, o, c, "", "secret-block in the prefix") // 2
		userAt(t, o, c, "", "kept in the prefix")         // 3
		base := turn(t, o, c, "resp-1", "one")            // 4, 5
		userAt(t, o, c, "", "secret-block after the base")
		userAt(t, o, c, "", "origin goes on "+fakePassword)
		turn(t, o, c, "resp-2", "two")
		f := fork(t, o, base, "orig-f")
		userAt(t, f, c, "", "on the fork, "+fakeKey) // 6
		turn(t, f, c, "resp-f", "forked")            // 7, 8

		ro := redact(t, p, o, nil)
		og := &Origin{Original: o, Redaction: ro.Session}
		rf := redactFork(t, p, f, nil, og)
		checkFork(t, p, f, rf, og, []string{"6", "7", "8"})
		if base, _ := rf.Session.Entry(rf.Session.Header().Base); base.EntryType() != agentsession.TypeResponse {
			t.Errorf("the base is a %s, want resp-1's redaction", base.EntryType())
		}
		checkOriginal(t, []*agentsession.Session{o, f}, []*agentsession.Session{ro.Session, rf.Session})

		// Both grow; each resumes equal to a fresh redaction.
		userAt(t, o, c, "", "origin later")
		turn(t, o, c, "resp-3", "three")
		userAt(t, f, c, "", "secret-block on the fork")
		userAt(t, f, c, "", "fork later")
		turn(t, f, c, "resp-g", "four")
		ro2 := redact(t, p, o, readBack(t, ro.Session))
		rf2 := redactFork(t, p, f, readBack(t, rf.Session), &Origin{Original: o, Redaction: ro2.Session})
		if len(rf2.Entries) != 4 { // the placeholder, the user message, the reply, the response
			t.Errorf("the resume wrote %d entries, want 4", len(rf2.Entries))
		}
		fo := redact(t, p, o, nil)
		ff := redactFork(t, p, f, nil, &Origin{Original: o, Redaction: fo.Session})
		if !bytes.Equal(fileOf(t, rf2.Session), fileOf(t, ff.Session)) {
			t.Errorf("the resumed fork differs from a fresh one:\n%s\n---\n%s", fileOf(t, rf2.Session), fileOf(t, ff.Session))
		}
		if !bytes.Equal(fileOf(t, ro2.Session), fileOf(t, fo.Session)) {
			t.Error("the resumed origin differs from a fresh one")
		}
	})

	t.Run("base in an open block", func(t *testing.T) {
		c := &clock{}
		o := newOriginal("orig-o")
		userAt(t, o, c, "", "start "+fakeKey)                                  // 1
		turn(t, o, c, "resp-1", "one")                                         // 2, 3
		base := userAt(t, o, c, "", "secret-block at the fork, "+fakePassword) // 4
		f := fork(t, o, base, "orig-f")
		userAt(t, f, c, "", "on the fork") // 5
		turn(t, f, c, "resp-f", "forked")  // 6, 7

		ro := redact(t, p, o, nil)
		og := &Origin{Original: o, Redaction: ro.Session}
		rf := redactFork(t, p, f, nil, og)
		// The fork's own placeholder stands for the prefix's open block,
		// named by its position in the fork's file order.
		checkFork(t, p, f, rf, og, []string{"4", "5", "6", "7"})
		if base, _ := rf.Session.Entry(rf.Session.Header().Base); base.EntryType() != agentsession.TypeResponse {
			t.Errorf("the base is a %s, want the response above the block", base.EntryType())
		}
		checkOriginal(t, []*agentsession.Session{o, f}, []*agentsession.Session{ro.Session, rf.Session})

		// The origin closes the block with an entry of its own: its
		// redaction writes its own placeholder, and the fork, resumed,
		// still forks where it did.
		userAt(t, o, c, "", "origin goes on")
		turn(t, o, c, "resp-2", "two")
		userAt(t, f, c, "", "fork later")
		ro2 := redact(t, p, o, readBack(t, ro.Session))
		if got := marks(t, ro2.Session); strings.Join(got, " ") != "1 2 3 4 5 6 7" {
			t.Errorf("origin marks %q", got)
		}
		rf2 := redactFork(t, p, f, readBack(t, rf.Session), &Origin{Original: o, Redaction: ro2.Session})
		ff := redactFork(t, p, f, nil, &Origin{Original: o, Redaction: redact(t, p, o, nil).Session})
		if !bytes.Equal(fileOf(t, rf2.Session), fileOf(t, ff.Session)) {
			t.Errorf("the resumed fork differs from a fresh one:\n%s\n---\n%s", fileOf(t, rf2.Session), fileOf(t, ff.Session))
		}
		if rf2.Session.Header().Base != rf.Session.Header().Base {
			t.Error("the fork's base moved")
		}
	})

	t.Run("own placeholder counts in the fork", func(t *testing.T) {
		// The origin holds a branch before the base, so a prefix entry's
		// position in the fork (2) is not its position in the origin (3).
		c := &clock{}
		o := newOriginal("orig-o")
		root := userAt(t, o, c, "", "start "+fakeKey)                        // 1
		userAt(t, o, c, root, "a side branch")                               // 2
		base := userAt(t, o, c, root, "secret-block at the fork, "+fakeHome) // 3
		f := fork(t, o, base, "orig-f")
		userAt(t, f, c, base, "on the fork") // 3 in the fork
		turn(t, f, c, "resp-f", "forked")    // 4, 5
		ro := redact(t, p, o, nil)
		og := &Origin{Original: o, Redaction: ro.Session}
		rf := redactFork(t, p, f, nil, og)
		checkFork(t, p, f, rf, og, []string{"2", "3", "4", "5"})
		checkOriginal(t, []*agentsession.Session{o, f}, []*agentsession.Session{ro.Session, rf.Session})
	})

	t.Run("a line of forks", func(t *testing.T) {
		c := &clock{}
		o2 := newOriginal("orig-o2")
		userAt(t, o2, c, "", "first "+fakeKey)      // 1
		inPrefix := turn(t, o2, c, "resp-1", "one") // 2, 3
		userAt(t, o2, c, "", "secret-block in o2")  // 4
		userAt(t, o2, c, "", "second")              // 5
		baseO := turn(t, o2, c, "resp-2", "two")    // 6, 7
		o := fork(t, o2, baseO, "orig-o")
		userAt(t, o, c, "", "on o, "+fakePassword) // 8
		inOwn := turn(t, o, c, "resp-o", "o")      // 9, 10
		f1 := fork(t, o, inOwn, "orig-f1")
		userAt(t, f1, c, "", "on f1") // 11
		turn(t, f1, c, "resp-f1", "f1")
		f2 := fork(t, o, inPrefix, "orig-f2")
		userAt(t, f2, c, "", "on f2") // 4
		turn(t, f2, c, "resp-f2", "f2")

		ro2 := redact(t, p, o2, nil)
		og2 := &Origin{Original: o2, Redaction: ro2.Session}
		ro := redactFork(t, p, o, nil, og2)
		checkFork(t, p, o, ro, og2, []string{"8", "9", "10"})
		og := &Origin{Original: o, Redaction: ro.Session, Origin: og2}
		rf1 := redactFork(t, p, f1, nil, og)
		checkFork(t, p, f1, rf1, og, []string{"11", "12", "13"})
		rf2 := redactFork(t, p, f2, nil, og)
		checkFork(t, p, f2, rf2, og, []string{"4", "5", "6"})
		checkOriginal(t, []*agentsession.Session{o2, o, f1, f2}, []*agentsession.Session{ro2.Session, ro.Session, rf1.Session, rf2.Session})

		// Resumed down the line after o grows, each equals a fresh one.
		userAt(t, o, c, "", "o later")
		userAt(t, f2, c, "", "f2 later")
		roG := redactFork(t, p, o, readBack(t, ro.Session), og2)
		ogG := &Origin{Original: o, Redaction: roG.Session, Origin: og2}
		rf2G := redactFork(t, p, f2, readBack(t, rf2.Session), ogG)
		fresh := redactFork(t, p, f2, nil, &Origin{Original: o, Redaction: redactFork(t, p, o, nil, og2).Session, Origin: og2})
		if !bytes.Equal(fileOf(t, rf2G.Session), fileOf(t, fresh.Session)) {
			t.Error("the resumed fork of a fork differs from a fresh one")
		}
	})
}

// TestForkOfRedactionRefusals: an origin whose redaction drops the
// base, one behind the base, and a redaction written in the other mode.
func TestForkOfRedactionRefusals(t *testing.T) {
	c := &clock{}
	o := newOriginal("orig-o")
	root := userAt(t, o, c, "", "first")
	base := turn(t, o, c, "resp-1", "one")
	if err := o.Branch(userAt(t, o, c, root, "the leaf's branch")); err != nil {
		t.Fatal(err)
	}
	turn(t, o, c, "resp-2", "two")
	f := fork(t, o, base, "orig-f")
	userAt(t, f, c, "", "on the fork")

	leaf := structProfile("test.leaf@1", nil, KeepLeafPath())
	ro := redact(t, leaf, o, nil)
	if _, err := Redact(leaf, f, nil, WithOrigin(&Origin{Original: o, Redaction: ro.Session})); !errors.Is(err, ErrBaseLeftOut) {
		t.Errorf("a base on a branch the origin's redaction dropped: %v, want ErrBaseLeftOut", err)
	}

	p := testProfile()
	ro = redact(t, p, o, nil)
	userAt(t, o, c, "", "origin later")
	later := turn(t, o, c, "resp-3", "three")
	g := fork(t, o, later, "orig-g")
	if _, err := Redact(p, g, nil, WithOrigin(&Origin{Original: o, Redaction: ro.Session})); !errors.Is(err, ErrOriginBehind) {
		t.Errorf("an origin's redaction behind the base: %v, want ErrOriginBehind", err)
	}

	ro = redact(t, p, o, nil)
	alone := redact(t, p, f, nil)
	if _, err := Redact(p, f, alone.Session, WithOrigin(&Origin{Original: o, Redaction: ro.Session})); !errors.Is(err, ErrNotThisRedaction) {
		t.Errorf("a redaction written without a base, resumed as a fork: %v, want ErrNotThisRedaction", err)
	}
	asFork := redactFork(t, p, f, nil, &Origin{Original: o, Redaction: ro.Session})
	if _, err := Redact(p, f, asFork.Session); !errors.Is(err, ErrNotThisRedaction) {
		t.Errorf("a fork of a redaction resumed without its origin: %v, want ErrNotThisRedaction", err)
	}
	if _, err := Redact(p, o, nil, WithOrigin(&Origin{Original: o, Redaction: ro.Session})); err == nil {
		t.Error("an original that is not a fork redacted as one")
	}
}

// TestAlongside re-points references into a session redacted alongside:
// parent_session, a link's session and a parents element, whose entry
// names the one standing for it there, or is removed when that one was
// left out; one naming nothing that session's original holds is
// refused.
func TestAlongside(t *testing.T) {
	c := &clock{}
	p := blockProfile("test.alongside@1")
	s1 := newOriginal("orig-s1")
	userAt(t, s1, c, "", "first "+fakeKey)
	answer := turn(t, s1, c, "resp-1", "one")
	folded := userAt(t, s1, c, "", "secret-block worker note")
	r1 := redact(t, p, s1, nil)
	if len(r1.Counterparts) != len(s1.Entries()) {
		t.Errorf("counterparts for %d entries, the original holds %d", len(r1.Counterparts), len(s1.Entries()))
	}
	if r1.Counterparts[folded] != "" || r1.Counterparts[answer] == "" {
		t.Errorf("counterparts %v", r1.Counterparts)
	}
	along := Alongside{
		Sessions: map[string]string{s1.ID(): r1.Session.ID()},
		Entries:  map[string]map[string]string{s1.ID(): r1.Counterparts},
	}

	s2 := agentsession.New(agentsession.Header{ID: "orig-s2", CreatedAt: t0, ParentSession: s1.ID()})
	userAt(t, s2, c, "", "start")
	appendAt(t, s2, c, &agentsession.LinkEntry{Rel: agentsession.RelContinuedIn, Session: s1.ID()})
	conv := user("merged the answer")
	conv.Parents = []agentsession.EntryRef{{Session: s1.ID(), Entry: answer}}
	appendAt(t, s2, c, conv)
	gone := user("merged the note")
	gone.Parents = []agentsession.EntryRef{{Session: s1.ID(), Entry: folded}}
	appendAt(t, s2, c, gone)
	turn(t, s2, c, "resp-2", "two")

	r2, err := Redact(p, s2, nil, WithAlongside(along))
	if err != nil {
		t.Fatal(err)
	}
	if h := r2.Session.Header(); h.ParentSession != r1.Session.ID() {
		t.Errorf("parent_session %q, want %s", h.ParentSession, r1.Session.ID())
	}
	order := agentsession.FileOrder(r2.Session)
	if l := order[1].(*agentsession.LinkEntry); l.Session != r1.Session.ID() {
		t.Errorf("link session %q", l.Session)
	}
	if got := order[2].Base().Parents; len(got) != 1 || got[0].Session != r1.Session.ID() || got[0].Entry != r1.Counterparts[answer] {
		t.Errorf("parents %+v, want the answer's redaction", got)
	}
	if got := order[3].Base().Parents; len(got) != 0 {
		t.Errorf("parents %+v, want the element naming an entry left out removed", got)
	}
	var at []string
	for _, f := range r2.Findings {
		at = append(at, f.At)
	}
	if strings.Join(at, ",") != "/parents" {
		t.Errorf("findings at %v, want one for the removed element", at)
	}
	if file := fileOf(t, r2.Session); bytes.Contains(file, []byte(s1.ID())) || bytes.Contains(file, []byte(answer)) {
		t.Errorf("the redaction names the original:\n%s", file)
	}
	for _, e := range order {
		if r, ok := e.(*agentsession.ResponseEntry); ok {
			if err := r2.Session.Verify(r.ID); err != nil {
				t.Errorf("response does not verify: %v", err)
			}
		}
	}

	s3 := newOriginal("orig-s3")
	stray := user("merged a stranger")
	stray.Parents = []agentsession.EntryRef{{Session: s1.ID(), Entry: agentsession.HashText("fake entry")}}
	appendAt(t, s3, c, stray)
	if _, err := Redact(p, s3, nil, WithAlongside(along)); !errors.Is(err, ErrUnmappedRef) {
		t.Errorf("a parents element naming nothing the session holds: %v, want ErrUnmappedRef", err)
	}
	if _, err := Redact(p, s2, nil, WithAlongside(Alongside{Sessions: along.Sessions})); !errors.Is(err, ErrUnmappedRef) {
		t.Errorf("a session alongside whose counterparts were not given: %v, want ErrUnmappedRef", err)
	}
}

// TestResumeInterruptedPlaceholder: a redaction whose writing stopped
// between a block placeholder and the kept entry that closes its run
// resumes, equal to a fresh redaction.
func TestResumeInterruptedPlaceholder(t *testing.T) {
	c := &clock{}
	p := blockProfile("test.interrupted@1")
	o := newOriginal("orig-interrupted")
	userAt(t, o, c, "", "first")
	userAt(t, o, c, "", "secret-block one")
	userAt(t, o, c, "", "secret-block two")
	userAt(t, o, c, "", "kept")
	turn(t, o, c, "resp-1", "one")
	fresh := redact(t, p, o, nil)
	cut := slices.IndexFunc(fresh.Entries, isPlaceholder)
	if cut < 0 {
		t.Fatal("no placeholder")
	}
	part := agentsession.New(fresh.Session.Header())
	for _, e := range fresh.Entries[:cut+1] {
		own, err := clone(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Commit(own); err != nil {
			t.Fatal(err)
		}
	}
	res := redact(t, p, o, part)
	if len(res.Entries) != len(fresh.Entries)-cut-1 {
		t.Errorf("the resume wrote %d entries, want %d", len(res.Entries), len(fresh.Entries)-cut-1)
	}
	if !bytes.Equal(fileOf(t, res.Session), fileOf(t, fresh.Session)) {
		t.Errorf("the resumed redaction differs from a fresh one:\n%s\n---\n%s", fileOf(t, res.Session), fileOf(t, fresh.Session))
	}
}
