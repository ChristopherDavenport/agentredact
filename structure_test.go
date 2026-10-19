package agentredact

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// Every fixture here is synthetic: call IDs, texts and markers are made
// up, and the secrets are the fake ones redact_test.go plants.

// structProfile is testProfile with structural and session redactors
// after its own.
func structProfile(name string, entries []EntryRedactor, sessions ...SessionRedactor) Profile {
	p := testProfile()
	p.Name = name
	p.Entries = append(p.Entries, entries...)
	p.Sessions = sessions
	return p
}

// userWith selects a user message whose original holds sub.
func userWith(sub string) func(c *EntryContext, e agentsession.Entry) bool {
	return func(c *EntryContext, _ agentsession.Entry) bool {
		it, ok := c.Entry().(*agentsession.ItemEntry)
		if !ok {
			return false
		}
		m, ok := it.Item.(*openresponses.Message)
		if !ok || m.Role != openresponses.RoleUser {
			return false
		}
		data, err := json.Marshal(m)
		return err == nil && bytes.Contains(data, []byte(sub))
	}
}

// atPositions selects the entries at the positions given.
func atPositions(ps ...int) func(c *EntryContext, e agentsession.Entry) bool {
	return func(c *EntryContext, _ agentsession.Entry) bool {
		for _, p := range ps {
			if c.Position == p {
				return true
			}
		}
		return false
	}
}

// ofType selects the entries of a type, an item by its item's type.
func ofType(typ string) func(c *EntryContext, e agentsession.Entry) bool {
	return func(c *EntryContext, _ agentsession.Entry) bool {
		if it, ok := c.Entry().(*agentsession.ItemEntry); ok {
			return it.Item.ItemType() == typ
		}
		return c.Entry().EntryType() == typ
	}
}

func call(callID string) *agentsession.ItemEntry {
	return agentsession.NewItemEntry(&openresponses.FunctionCall{CallID: callID, Name: "fake_tool", Arguments: `{"path":"` + fakeHome + `/x"}`})
}

// respond appends items as the output of respID and the response, whose
// request hash verifies in the original.
func respond(t *testing.T, s *agentsession.Session, c *clock, respID string, items ...*agentsession.ItemEntry) []string {
	t.Helper()
	var ids []string
	for _, it := range items {
		it.ResponseID = respID
		ids = append(ids, appendAt(t, s, c, it))
	}
	resp := &agentsession.ResponseEntry{ResponseID: respID, Status: openresponses.ResponseStatusCompleted, RequestHash: "sha256:to-compute"}
	if err := s.SetRequestHash(resp); err != nil {
		t.Fatal(err)
	}
	id := appendAt(t, s, c, resp)
	if err := s.Verify(id); err != nil {
		t.Fatalf("the original's response does not verify: %v", err)
	}
	return append(ids, id)
}

func recordsOriginal(id string) *agentsession.Session {
	return agentsession.New(agentsession.Header{ID: id, CreatedAt: t0, Records: []string{agentsession.TypeRun, agentsession.TypeDispatch}})
}

// callOriginal: a config, then a run holding a call, its dispatch and
// output, then a turn outside the run.
//
//	1 config  2 run start  3 user  4 msg, 5 call c1 (resp-1)  6 resp-1
//	7 dispatch  8 output  9 msg (resp-2)  10 resp-2  11 run end done
//	12 user "drop me"  13 msg  14 resp-3
func callOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := recordsOriginal("orig-call")
	appendAt(t, s, c, &agentsession.ConfigEntry{Model: "fake-model"})
	appendAt(t, s, c, agentsession.NewRunStart("run-1", agentsession.SourceInput, ""))
	appendAt(t, s, c, user("read the file, my key is "+fakeKey))
	ids := respond(t, s, c, "resp-1", agentsession.NewItemEntry(openresponses.AssistantText("reading")), call("call-c1"))
	appendAt(t, s, c, agentsession.NewDispatch("call-c1", ids[1]))
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-c1", "contents with "+fakePassword)))
	respond(t, s, c, "resp-2", agentsession.NewItemEntry(openresponses.AssistantText("done")))
	appendAt(t, s, c, agentsession.NewRunEnd("run-1", agentsession.ReasonDone, "", nil))
	appendAt(t, s, c, user("drop me, "+fakeKey))
	respond(t, s, c, "resp-3", agentsession.NewItemEntry(openresponses.AssistantText("ok")))
	return s
}

// heldOriginal: a run ending input_required on a held call, then a
// turn.
//
//	1 run start  2 user  3 call c2 (resp-1)  4 resp-1  5 hold
//	6 run end input_required [c2]  7 user  8 msg  9 resp-2
func heldOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := recordsOriginal("orig-held")
	appendAt(t, s, c, agentsession.NewRunStart("run-1", agentsession.SourceInput, ""))
	appendAt(t, s, c, user("do it in "+fakeHome))
	ids := respond(t, s, c, "resp-1", call("call-c2"))
	appendAt(t, s, c, agentsession.NewDecision("call-c2", ids[0], agentsession.VerdictHold, agentsession.ByPolicy))
	appendAt(t, s, c, agentsession.NewRunEnd("run-1", agentsession.ReasonInputRequired, "", []string{"call-c2"}))
	appendAt(t, s, c, user("later"))
	respond(t, s, c, "resp-2", agentsession.NewItemEntry(openresponses.AssistantText("fine")))
	return s
}

// treeOriginal holds blocks along branches: 2, 3 and 5 are folded by
// blockProfile, 4 and 6 kept on two branches under 2.
//
//	1 root  2 block a (1)  3 block b (2)  4 kept x (2)  5 block c (3)
//	6 kept y (5)  7 msg, 8 resp-y
func treeOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := newOriginal("orig-tree")
	at := func(parent, text string) string {
		e := user(text)
		e.Parent = parent
		return appendAt(t, s, c, e)
	}
	root := at("", "root "+fakePassword)
	a := at(root, "secret-block a "+fakeKey)
	b := at(a, "secret-block b")
	at(a, "kept x")
	cc := at(b, "secret-block c")
	y := at(cc, "kept y")
	if err := s.Branch(y); err != nil {
		t.Fatal(err)
	}
	respond(t, s, c, "resp-y", agentsession.NewItemEntry(openresponses.AssistantText("y")))
	return s
}

func blockProfile(name string) Profile {
	return structProfile(name, []EntryRedactor{BlockOut(userWith("secret-block"))})
}

// marks returns the redacted member of each entry of s in file order,
// written as markKey writes it.
func marks(t *testing.T, s *agentsession.Session) []string {
	t.Helper()
	var out []string
	for _, e := range agentsession.FileOrder(s) {
		spans, ok := agentsession.RedactedOf(e)
		if !ok {
			t.Errorf("entry %s (%s) carries no redacted member", e.Base().ID, e.EntryType())
		}
		out = append(out, markKey(spans))
	}
	return out
}

// checkStructural holds a fresh redaction that may leave entries out to
// every rule: the marks wanted, each kept entry of its original's type
// and each placeholder counting what it stands for, the file reading
// back with every response verifying, no member naming an entry the
// file lacks, the records verifying where the original's did, and a
// rerun writing the same bytes.
func checkStructural(t *testing.T, p Profile, orig *agentsession.Session, res *Result, want []string) {
	t.Helper()
	red := res.Session
	file := fileOf(t, red)
	for _, v := range planted {
		if bytes.Contains(file, []byte(v)) {
			t.Errorf("the redaction kept %q", v)
		}
	}
	h := red.Header()
	if !h.Redacted || h.RedactedFrom == nil || h.RedactedFrom.Profile != p.Name || h.ID != agentsession.RedactedSessionID(orig.ID(), p.Name) {
		t.Errorf("header %+v", h)
	}
	if got := marks(t, red); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("marks %q, want %q\n%s", got, want, file)
	}
	order := agentsession.FileOrder(orig)
	held := agentsession.FileOrder(red)
	if len(res.Entries) != len(held) {
		t.Errorf("Result.Entries holds %d, the session %d", len(res.Entries), len(held))
	}
	for _, e := range held {
		spans, _ := agentsession.RedactedOf(e)
		if isPlaceholder(e) {
			n := 0
			for _, sp := range spans {
				n += sp.To - sp.From + 1
			}
			var data struct {
				Redacted string `json:"redacted"`
				Entries  int    `json:"entries"`
			}
			dec := json.NewDecoder(bytes.NewReader(e.(*agentsession.CustomEntry).Data))
			dec.DisallowUnknownFields() // a placeholder carries nothing else
			if err := dec.Decode(&data); err != nil || data.Redacted != "block" || data.Entries != n {
				t.Errorf("placeholder %s data %s, want a block of %d", markKey(spans), e.(*agentsession.CustomEntry).Data, n)
			}
			continue
		}
		if len(spans) == 1 && spans[0].From == spans[0].To {
			if o := order[spans[0].From-1]; o.EntryType() != e.EntryType() {
				t.Errorf("entry marked %d is a %s, the original's a %s", spans[0].From, e.EntryType(), o.EntryType())
			}
		}
	}
	back, err := agentsession.Read(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("the redacted file does not read: %v\n%s", err, file)
	}
	verified := 0
	for _, e := range back.Entries() {
		if r, ok := e.(*agentsession.ResponseEntry); ok && r.RequestHash != "" {
			verified++
			if err := back.Verify(r.ID); err != nil {
				t.Errorf("response %s does not verify: %v", r.ResponseID, err)
			}
		}
		_, err := agentsession.RemapRefs(e, agentsession.Remap{Entry: func(session, id string) (string, bool) {
			if session == "" || session == back.ID() {
				if _, ok := back.Entry(id); !ok {
					t.Errorf("entry %s (%s) names %s, which the file does not hold", e.Base().ID, e.EntryType(), id)
				}
			}
			return id, true
		}})
		if err != nil {
			t.Fatal(err)
		}
	}
	if verified == 0 {
		t.Error("no response with a request_hash; the case proves nothing")
	}
	origOK := true
	for _, leaf := range orig.Leaves() {
		if orig.VerifyRecords(leaf) != nil {
			origOK = false
		}
	}
	if origOK {
		for _, leaf := range back.Leaves() {
			if err := back.VerifyRecords(leaf); err != nil {
				t.Errorf("the records on the path to %s do not verify: %v", leaf, err)
			}
		}
	}
	if again := redact(t, p, orig, nil); !bytes.Equal(fileOf(t, again.Session), file) {
		t.Errorf("a rerun wrote other bytes:\n%s\n---\n%s", file, fileOf(t, again.Session))
	}
}

// resumeEqualsFresh resumes existing, and a copy of it read back from
// its file, over orig, and checks that both equal a fresh redaction of
// orig byte for byte; it returns the resumed session.
func resumeEqualsFresh(t *testing.T, p Profile, orig, existing *agentsession.Session) *agentsession.Session {
	t.Helper()
	back, err := agentsession.Read(bytes.NewReader(fileOf(t, existing)))
	if err != nil {
		t.Fatal(err)
	}
	fresh := fileOf(t, redact(t, p, orig, nil).Session)
	grown := redact(t, p, orig, existing)
	if got := fileOf(t, grown.Session); !bytes.Equal(got, fresh) {
		t.Errorf("the resumed redaction differs from a fresh one:\n%s\n---\n%s", got, fresh)
	}
	if got := fileOf(t, redact(t, p, orig, back).Session); !bytes.Equal(got, fresh) {
		t.Errorf("the redaction read back and resumed differs from a fresh one:\n%s\n---\n%s", got, fresh)
	}
	return grown.Session
}

func TestStructural(t *testing.T) {
	for _, tt := range []struct {
		name    string
		build   func(*testing.T, *clock) *agentsession.Session
		entries []EntryRedactor
		want    []string
		gone    []string // left-out text the file must not hold
	}{
		{"single entry left out", callOriginal, []EntryRedactor{LeaveOut(userWith("drop me"))},
			[]string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "13", "14"}, []string{"drop me"}},
		{"single entry folded", callOriginal, []EntryRedactor{BlockOut(userWith("drop me"))},
			[]string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14"}, []string{"drop me"}},
		// The call's dispatch and output leave with it; its response
		// keeps the message beside it.
		{"call group left out", callOriginal, []EntryRedactor{LeaveOut(ofType(openresponses.ItemTypeFunctionCall))},
			[]string{"1", "2", "3", "4", "6", "9", "10", "11", "12", "13", "14"}, []string{"call-c1", "contents with"}},
		{"call group folded", callOriginal, []EntryRedactor{BlockOut(ofType(openresponses.ItemTypeFunctionCall))},
			[]string{"1", "2", "3", "4", "5", "6", "7-8", "9", "10", "11", "12", "13", "14"}, []string{"call-c1", "contents with"}},
		// The call takes its response, all of whose output it was, and
		// its hold; the run end loses it from pending and reads aborted.
		{"held call left out", heldOriginal, []EntryRedactor{LeaveOut(ofType(openresponses.ItemTypeFunctionCall))},
			[]string{"1", "2", "6", "7", "8", "9"}, []string{"call-c2"}},
		{"runs across branches", treeOriginal, nil,
			[]string{"1", "2", "4", "3,5", "6", "7", "8"}, []string{"secret-block"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			orig := tt.build(t, &clock{})
			p := blockProfile("test.struct@1")
			if tt.entries != nil {
				p = structProfile("test.struct@1", tt.entries)
			}
			res := redact(t, p, orig, nil)
			checkStructural(t, p, orig, res, tt.want)
			absent(t, res, tt.gone...)
		})
	}
}

// absent checks that the redacted file holds none of the texts, which
// were only in entries left out.
func absent(t *testing.T, res *Result, texts ...string) {
	t.Helper()
	file := fileOf(t, res.Session)
	for _, x := range texts {
		if bytes.Contains(file, []byte(x)) {
			t.Errorf("the redaction kept %q, left out", x)
		}
	}
}

// TestUnverifiedRunEndPending: a run end whose original did not verify
// keeps its reason as written, but a call left out still leaves its
// pending list.
func TestUnverifiedRunEndPending(t *testing.T) {
	c := &clock{}
	s := recordsOriginal("orig-bad-end")
	appendAt(t, s, c, agentsession.NewRunStart("run-1", agentsession.SourceInput, ""))
	appendAt(t, s, c, user("do it"))
	respond(t, s, c, "resp-1", call("call-bad"))
	appendAt(t, s, c, agentsession.NewRunEnd("run-1", agentsession.ReasonDone, "", []string{"call-bad"})) // reads aborted
	appendAt(t, s, c, user("later"))
	respond(t, s, c, "resp-2", agentsession.NewItemEntry(openresponses.AssistantText("fine")))
	p := structProfile("test.struct@1", []EntryRedactor{LeaveOut(ofType(openresponses.ItemTypeFunctionCall))})
	res := redact(t, p, s, nil)
	absent(t, res, "call-bad")
	for _, e := range res.Session.Entries() {
		if r, ok := e.(*agentsession.RunEntry); ok && r.IsEnd() && (r.Reason != agentsession.ReasonDone || len(r.Pending) != 0) {
			t.Errorf("run end %s %v, want done as written and nothing pending", r.Reason, r.Pending)
		}
	}
}

// TestHeldRunEndCarried: the run end of heldOriginal, once its held
// call is left out, lists nothing pending and gives the reason its
// segment reads.
func TestHeldRunEndCarried(t *testing.T) {
	orig := heldOriginal(t, &clock{})
	p := structProfile("test.struct@1", []EntryRedactor{LeaveOut(ofType(openresponses.ItemTypeFunctionCall))})
	res := redact(t, p, orig, nil)
	for _, e := range res.Session.Entries() {
		if r, ok := e.(*agentsession.RunEntry); ok && r.IsEnd() {
			if r.Reason != agentsession.ReasonAborted || len(r.Pending) != 0 {
				t.Errorf("run end %s %v, want aborted and nothing pending", r.Reason, r.Pending)
			}
		}
	}
}

// TestBlockRun: consecutive entries folded become one placeholder, a
// range, under the entry kept above them, and the entry kept after
// them hangs from it.
func TestBlockRun(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-run")
	appendAt(t, s, c, user("first"))
	turn(t, s, c, "resp-1", "one")
	appendAt(t, s, c, user("secret-block 1 "+fakeKey))
	appendAt(t, s, c, user("secret-block 2"))
	appendAt(t, s, c, user("secret-block 3"))
	appendAt(t, s, c, user("after"))
	turn(t, s, c, "resp-2", "two")
	p := blockProfile("test.block@1")
	res := redact(t, p, s, nil)
	checkStructural(t, p, s, res, []string{"1", "2", "3", "4-6", "7", "8", "9"})
	absent(t, res, "secret-block")
	order := agentsession.FileOrder(res.Session)
	if ph := order[3]; !isPlaceholder(ph) || ph.Base().Parent != order[2].Base().ID || order[4].Base().Parent != ph.Base().ID {
		t.Errorf("the placeholder does not stand between the entries kept around it")
	}
	if ph := order[3]; !ph.Base().Timestamp.Equal(agentsession.FileOrder(s)[3].Base().Timestamp) {
		t.Errorf("the placeholder's timestamp is not the first entry's it stands for")
	}
}

// growthOriginal is redacted, grown and resumed in TestResumeGrowth.
//
//	1 user  2 msg  3 resp-1  4 block 1  5 block 2
func growthOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := newOriginal("orig-growth")
	appendAt(t, s, c, user("start "+fakePassword))
	turn(t, s, c, "resp-1", "one")
	appendAt(t, s, c, user("secret-block 1"))
	appendAt(t, s, c, user("secret-block 2"))
	return s
}

// TestResumeGrowth: a redaction resumed after each way the original can
// grow equals a fresh redaction of it, read back or not: a trailing run
// of folded entries extended, closed, a new branch, and a run left open
// on one branch while another grows past it.
func TestResumeGrowth(t *testing.T) {
	c := &clock{}
	s := growthOriginal(t, c)
	p := blockProfile("test.growth@1")
	first := redact(t, p, s, nil)
	if got := marks(t, first.Session); strings.Join(got, " ") != "1 2 3" {
		t.Fatalf("marks %q: the open run is not withheld", got)
	}
	red := first.Session
	resp1 := agentsession.FileOrder(s)[2].Base().ID

	// Extend the trailing run: still open, nothing new written.
	appendAt(t, s, c, user("secret-block 3")) // 6
	red = resumeEqualsFresh(t, p, s, red)
	if got := marks(t, red); strings.Join(got, " ") != "1 2 3" {
		t.Errorf("after extending, marks %q", got)
	}

	// Close it: one placeholder for the whole run.
	appendAt(t, s, c, user("kept after the block")) // 7
	turn(t, s, c, "resp-2", "two")                  // 8, 9
	red = resumeEqualsFresh(t, p, s, red)
	if got := marks(t, red); strings.Join(got, " ") != "1 2 3 4-6 7 8 9" {
		t.Errorf("after closing, marks %q", got)
	}

	// A new branch from resp-1, with a block of its own, closed.
	b := user("secret-block on a branch")
	b.Parent = resp1
	bID := appendAt(t, s, c, b) // 10
	k := user("kept on the branch")
	k.Parent = bID
	kID := appendAt(t, s, c, k) // 11
	if err := s.Branch(kID); err != nil {
		t.Fatal(err)
	}
	turn(t, s, c, "resp-b", "bee") // 12, 13
	red = resumeEqualsFresh(t, p, s, red)
	if got := marks(t, red); strings.Join(got, " ") != "1 2 3 4-6 7 8 9 10 11 12 13" {
		t.Errorf("after branching, marks %q", got)
	}

	// A run opened on another branch from resp-1 (14), then the main
	// line grows past it (15), so the open run lies below the highest
	// position written; then it is closed (16).
	o := user("secret-block left open")
	o.Parent = resp1
	open := appendAt(t, s, c, o) // 14
	if err := s.Branch(agentsession.FileOrder(s)[12].Base().ID); err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, user("the branch grows")) // 15
	red = resumeEqualsFresh(t, p, s, red)
	if got := marks(t, red); strings.Join(got, " ") != "1 2 3 4-6 7 8 9 10 11 12 13 15" {
		t.Errorf("with a run open below, marks %q", got)
	}
	cl := user("closing the old run")
	cl.Parent = open
	appendAt(t, s, c, cl) // 16
	red = resumeEqualsFresh(t, p, s, red)
	if got := marks(t, red); strings.Join(got, " ") != "1 2 3 4-6 7 8 9 10 11 12 13 15 14 16" {
		t.Errorf("after closing the run below, marks %q", got)
	}
	checkStructural(t, p, s, redact(t, p, s, nil), marks(t, red))
}

// TestResumeLeftOutPastDone: entries left out with nothing in their
// place past the highest position written are decided again on resume,
// the same way, and write nothing.
func TestResumeLeftOutPastDone(t *testing.T) {
	c := &clock{}
	s := growthOriginal(t, c)
	p := structProfile("test.leave@1", []EntryRedactor{LeaveOut(userWith("secret-block"))})
	red := redact(t, p, s, nil).Session
	again := redact(t, p, s, red)
	if len(again.Entries) != 0 {
		t.Fatalf("an up-to-date resume wrote %d entries", len(again.Entries))
	}
	appendAt(t, s, c, user("after"))
	turn(t, s, c, "resp-2", "two")
	red = resumeEqualsFresh(t, p, s, red)
	if got := marks(t, red); strings.Join(got, " ") != "1 2 3 6 7 8" {
		t.Errorf("marks %q", got)
	}
	checkStructural(t, p, s, redact(t, p, s, nil), []string{"1", "2", "3", "6", "7", "8"})
}

// branchesOriginal: a turn, then two branches from its response, the
// leaf on the second.
//
//	1 user  2 msg  3 resp-1  4 branch A (3)  5 msg  6 resp-a
//	7 branch B (3)  8 msg  9 resp-b  10 label naming 5
func branchesOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := newOriginal("orig-branches")
	appendAt(t, s, c, user("question "+fakeKey))
	resp1 := turn(t, s, c, "resp-1", "answer")
	appendAt(t, s, c, user("branch A, in "+fakeHome))
	turn(t, s, c, "resp-a", "on A")
	if err := s.Branch(resp1); err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, user("branch B"))
	turn(t, s, c, "resp-b", "on B")
	appendAt(t, s, c, agentsession.NewLabelEntry(agentsession.FileOrder(s)[4].Base().ID, "seen A"))
	return s
}

func TestKeepLeafPath(t *testing.T) {
	c := &clock{}
	s := branchesOriginal(t, c)
	p := structProfile("test.leaf@1", nil, KeepLeafPath())
	res := redact(t, p, s, nil)
	// The label named an entry on the branch left out, with nothing in
	// its place: it is left out too, never moved to an ancestor.
	checkStructural(t, p, s, res, []string{"1", "2", "3", "7", "8", "9"})

	// The leaf moves along its branch: resuming equals a fresh redaction.
	appendAt(t, s, c, user("more on B")) // 11
	red := resumeEqualsFresh(t, p, s, res.Session)

	// The leaf moves to another branch: what was redacted is off the
	// new path, and resuming is refused.
	if err := s.Branch(agentsession.FileOrder(s)[2].Base().ID); err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, user("branch C"))
	before := fileOf(t, red)
	if _, err := Redact(p, s, red); !errors.Is(err, ErrResumeDiverged) {
		t.Errorf("resuming after the leaf moved: %v, want ErrResumeDiverged", err)
	}
	if !bytes.Equal(fileOf(t, red), before) {
		t.Error("the refused resume wrote to the existing redaction")
	}
}

func TestDropBranches(t *testing.T) {
	c := &clock{}
	s := branchesOriginal(t, c)
	p := structProfile("test.drop@1", nil, DropBranches(func(c *EntryContext) bool {
		return userWith("branch A")(c, nil)
	}))
	res := redact(t, p, s, nil)
	checkStructural(t, p, s, res, []string{"1", "2", "3", "7", "8", "9"})

	// Growth under the dropped branch is dropped too; a new branch is
	// kept; each resume equals a fresh redaction.
	under := user("deeper on A")
	under.Parent = agentsession.FileOrder(s)[5].Base().ID
	appendAt(t, s, c, under) // 11
	red := resumeEqualsFresh(t, p, s, res.Session)
	branch := user("branch C")
	branch.Parent = agentsession.FileOrder(s)[2].Base().ID
	appendAt(t, s, c, branch) // 12
	red = resumeEqualsFresh(t, p, s, red)
	if got := marks(t, red); strings.Join(got, " ") != "1 2 3 7 8 9 12" {
		t.Errorf("marks %q", got)
	}
}

// sessionFunc adapts a function to SessionRedactor, for tests.
type sessionFunc func(*agentsession.Session, []agentsession.Entry) ([]bool, error)

func (f sessionFunc) LeaveOut(s *agentsession.Session, order []agentsession.Entry) ([]bool, error) {
	return f(s, order)
}

// TestSplit: a structural redactor writing several entries in one's
// place, one of them added, marks them [n], [] and [n], and resumes.
func TestSplit(t *testing.T) {
	split := StructureRedactorFunc(func(c *EntryContext, e agentsession.Entry) ([]Made, error) {
		if !userWith("split me")(c, e) {
			return []Made{{Entry: e}}, nil
		}
		note := &agentsession.CustomEntry{NS: "x.fake", Data: json.RawMessage(`{"note":"split"}`)}
		return []Made{{Entry: user("first half")}, {Entry: note, Added: true}, {Entry: e}}, nil
	})
	c := &clock{}
	s := newOriginal("orig-split")
	appendAt(t, s, c, user("split me, "+fakeKey))
	turn(t, s, c, "resp-1", "one")
	p := structProfile("test.split@1", []EntryRedactor{split})
	res := redact(t, p, s, nil)
	checkStructural(t, p, s, res, []string{"1", "", "1", "2", "3"})
	appendAt(t, s, c, user("split me again"))
	turn(t, s, c, "resp-2", "two")
	red := resumeEqualsFresh(t, p, s, res.Session)
	if got := marks(t, red); strings.Join(got, " ") != "1  1 2 3 4  4 5 6" {
		t.Errorf("marks %q", got)
	}
}

// compactionWindow: a fold whose first_kept is 4.
//
//	1 user  2 msg  3 resp-1  4 user (first_kept)  5 msg  6 resp-2
//	7 compaction  8 user  9 msg  10 resp-3
func TestFirstKept(t *testing.T) {
	for _, tt := range []struct {
		name string
		red  EntryRedactor
		want []string
		// keptAt is the position of the entry first_kept must name, 0
		// for the placeholder in its place.
		keptAt int
	}{
		{"left out: the next entry kept", LeaveOut(atPositions(4)), []string{"1", "2", "3", "5", "6", "7", "8", "9", "10"}, 5},
		{"folded: its placeholder", BlockOut(atPositions(4)), []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}, 0},
		{"window left out: the record above", LeaveOut(atPositions(4, 5)), []string{"1", "2", "3", "7", "8", "9", "10"}, 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			orig := compactionOriginal(t, &clock{})
			p := structProfile("test.fold@1", []EntryRedactor{tt.red})
			res := redact(t, p, orig, nil)
			checkStructural(t, p, orig, res, tt.want)
			var comp *agentsession.CompactionEntry
			var want string
			for _, e := range agentsession.FileOrder(res.Session) {
				spans, _ := agentsession.RedactedOf(e)
				if cp, ok := e.(*agentsession.CompactionEntry); ok {
					comp = cp
				}
				if tt.keptAt == 0 && isPlaceholder(e) || len(spans) == 1 && spans[0].From == tt.keptAt && !isPlaceholder(e) {
					want = e.Base().ID
				}
			}
			if comp == nil || comp.FirstKept != want {
				t.Errorf("first_kept %v, want %s", comp, want)
			}
		})
	}
}

// TestPinnedLeaves: a pinned item whose item entry was left out leaves
// the compaction with it; one whose entry is kept stays.
func TestPinnedLeaves(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-pinned")
	appendAt(t, s, c, user("pin me, the secret one"))
	appendAt(t, s, c, user("pin me too"))
	turn(t, s, c, "resp-1", "one")
	kept := appendAt(t, s, c, user("kept window"))
	turn(t, s, c, "resp-2", "two")
	comp, err := s.Compact(kept, openresponses.UserText("summary"))
	if err != nil {
		t.Fatal(err)
	}
	comp.Pinned = openresponses.Items{openresponses.UserText("pin me, the secret one"), openresponses.UserText("pin me too")}
	appendAt(t, s, c, comp)
	appendAt(t, s, c, user("after"))
	turn(t, s, c, "resp-3", "three")
	p := structProfile("test.pin@1", []EntryRedactor{LeaveOut(userWith("the secret one"))})
	res := redact(t, p, s, nil)
	checkStructural(t, p, s, res, []string{"2", "3", "4", "5", "6", "7", "8", "9", "10", "11"})
	file := fileOf(t, res.Session)
	if bytes.Contains(file, []byte("the secret one")) || !bytes.Contains(file, []byte(`"pin me too"`)) {
		t.Errorf("pinned items not carried through:\n%s", file)
	}
}

// TestRefusals: each drop that would break a format rule is refused,
// naming the position.
func TestRefusals(t *testing.T) {
	// summaryOriginal: a branch summary whose from is the root.
	summaryOriginal := func(t *testing.T, c *clock) *agentsession.Session {
		s := newOriginal("orig-summary")
		root := appendAt(t, s, c, user("root"))
		appendAt(t, s, c, user("child"))
		turn(t, s, c, "resp-1", "one")
		bs, err := s.SummarizeBranch(root, openresponses.UserText("we left the root"))
		if err != nil {
			t.Fatal(err)
		}
		appendAt(t, s, c, bs)
		return s
	}
	// resumedOriginal: a run leaves a call pending, the next resumes it.
	//
	//	1 start r1  2 user  3 call c3  4 resp-1  5 end r1 aborted [c3]
	//	6 start r2 resume  7 dispatch  8 output  9 msg  10 resp-2  11 end done
	resumedOriginal := func(t *testing.T, c *clock) *agentsession.Session {
		s := recordsOriginal("orig-resumed")
		appendAt(t, s, c, agentsession.NewRunStart("run-1", agentsession.SourceInput, ""))
		appendAt(t, s, c, user("go"))
		ids := respond(t, s, c, "resp-1", call("call-c3"))
		appendAt(t, s, c, agentsession.NewRunEnd("run-1", agentsession.ReasonAborted, "", []string{"call-c3"}))
		appendAt(t, s, c, agentsession.NewRunStart("run-2", agentsession.SourceResume, ""))
		appendAt(t, s, c, agentsession.NewDispatch("call-c3", ids[0]))
		appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-c3", "out")))
		respond(t, s, c, "resp-2", agentsession.NewItemEntry(openresponses.AssistantText("done")))
		appendAt(t, s, c, agentsession.NewRunEnd("run-2", agentsession.ReasonDone, "", nil))
		if err := s.VerifyRecords(s.Leaf()); err != nil {
			t.Fatalf("the fixture's records do not verify: %v", err)
		}
		return s
	}
	middleOnly := sessionFunc(func(_ *agentsession.Session, order []agentsession.Entry) ([]bool, error) {
		out := make([]bool, len(order))
		out[1] = true
		return out, nil
	})
	for _, tt := range []struct {
		name     string
		build    func(*testing.T, *clock) *agentsession.Session
		entries  []EntryRedactor
		sessions []SessionRedactor
		want     error
		at       string
	}{
		{"an output alone", callOriginal, []EntryRedactor{LeaveOut(atPositions(8))}, nil, ErrSplitsCall, "entry 8 "},
		{"a dispatch alone", callOriginal, []EntryRedactor{LeaveOut(atPositions(7))}, nil, ErrSplitsCall, "entry 7 "},
		{"a decision alone", heldOriginal, []EntryRedactor{LeaveOut(atPositions(5))}, nil, ErrSplitsCall, "entry 5 "},
		{"a response alone", callOriginal, []EntryRedactor{LeaveOut(atPositions(6))}, nil, ErrSplitsResponse, "entry 6 "},
		{"a run end alone", callOriginal, []EntryRedactor{LeaveOut(atPositions(11))}, nil, ErrSplitsRun, "entry 11 "},
		{"a config", callOriginal, []EntryRedactor{LeaveOut(atPositions(1))}, nil, ErrLeavesOutConfig, "entry 1 "},
		{"first_kept with its window and the turn above", compactionOriginal, []EntryRedactor{LeaveOut(atPositions(2, 3, 4, 5))}, nil, ErrFirstKept, "entry 7 "},
		{"a branch summary's from with nothing above", summaryOriginal, []EntryRedactor{LeaveOut(atPositions(1))}, nil, ErrNoPlace, "entry 5 "},
		{"a compaction", compactionOriginal, []EntryRedactor{LeaveOut(ofType(agentsession.TypeCompaction))}, nil, ErrLeavesOutCompaction, "entry 7 "},
		{"a function call made a custom entry", callOriginal, []EntryRedactor{StructureRedactorFunc(func(c *EntryContext, e agentsession.Entry) ([]Made, error) {
			if isFunctionCall(c.Entry()) {
				return []Made{{Entry: &agentsession.CustomEntry{NS: "x.fake", Data: json.RawMessage(`{}`)}}}, nil
			}
			return []Made{{Entry: e}}, nil
		})}, nil, ErrGroupHead, "entry 5 "},
		{"a session redactor keeping a child", callOriginal, nil, []SessionRedactor{middleOnly}, ErrSessionRedactor, "position 2"},
		{"a resumed run's call", resumedOriginal, []EntryRedactor{LeaveOut(ofType(openresponses.ItemTypeFunctionCall))}, nil, ErrBreaksRecords, "entry 11 "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			orig := tt.build(t, &clock{})
			p := structProfile("test.refuse@1", tt.entries, tt.sessions...)
			_, err := Redact(p, orig, nil)
			if !errors.Is(err, tt.want) {
				t.Fatalf("%v, want %v", err, tt.want)
			}
			if !strings.Contains(err.Error(), tt.at) {
				t.Errorf("%v does not name %q", err, tt.at)
			}
		})
	}
}

// TestForkSharedPrefix: a fork and its origin redacted under one
// structural profile whose decisions rest on the path give the entries
// made from their shared prefix the same bytes.
func TestForkSharedPrefix(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-fork-origin")
	appendAt(t, s, c, user("start "+fakeKey))
	appendAt(t, s, c, user("secret-block in the prefix"))
	appendAt(t, s, c, user("kept in the prefix"))
	base := turn(t, s, c, "resp-1", "one") // 4, 5
	appendAt(t, s, c, user("secret-block after the base"))
	appendAt(t, s, c, user("origin goes on"))
	turn(t, s, c, "resp-2", "two")
	d := user("drop this branch")
	d.Parent = base
	appendAt(t, s, c, d)
	f, err := agentsession.Fork(s, base, agentsession.Header{ID: "orig-fork", CreatedAt: t0})
	if err != nil {
		t.Fatal(err)
	}
	appendAt(t, f, c, user("on the fork"))
	turn(t, f, c, "resp-f", "forked")
	p := structProfile("test.fork@1", []EntryRedactor{BlockOut(userWith("secret-block"))},
		DropBranches(func(c *EntryContext) bool { return userWith("drop this")(c, nil) }))
	shared := func(red *agentsession.Session) []string {
		var ids []string
		for _, e := range agentsession.FileOrder(red) {
			spans, _ := agentsession.RedactedOf(e)
			if len(spans) > 0 && spans[len(spans)-1].To <= 5 {
				ids = append(ids, e.Base().ID)
			}
		}
		return ids
	}
	ro := redact(t, p, s, nil)
	rf := redact(t, p, f, nil)
	checkStructural(t, p, s, ro, []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"})
	checkStructural(t, p, f, rf, []string{"1", "2", "3", "4", "5", "6", "7", "8"})
	if a, b := shared(ro.Session), shared(rf.Session); len(a) != 5 || strings.Join(a, " ") != strings.Join(b, " ") {
		t.Errorf("the shared prefix differs:\n%v\n%v", a, b)
	}
}

// TestLeftOutReportsNothing: what the entry redactors report or add for
// an entry a structural redactor then leaves out goes with it: no
// finding names it and no blob is returned for it.
func TestLeftOutReportsNothing(t *testing.T) {
	c := &clock{}
	s := agentsession.New(agentsession.Header{ID: "orig-left-media", CreatedAt: t0, Media: agentsession.MediaSidecar})
	appendAt(t, s, c, user("first"))
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.UserMessage(
		&openresponses.InputImage{ImageURL: "sidecar:" + agentsession.HashText("FAKE-IMAGE-BLOB-0002")},
		&openresponses.InputFile{Filename: "fake.pdf", FileData: "sidecar:" + agentsession.HashText("FAKE-PDF-BLOB-0002")},
	)))
	turn(t, s, c, "resp-1", "one")
	p := structProfile("test.media@1", []EntryRedactor{LeaveOut(atPositions(2))})
	res := redact(t, p, s, nil)
	if len(res.Findings) != 0 || res.Blobs != nil {
		t.Errorf("findings %+v and blobs %v for an entry left out", res.Findings, res.Blobs)
	}
	checkStructural(t, p, s, res, []string{"1", "3", "4"})
}
