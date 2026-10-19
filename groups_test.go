package agentredact

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// queuedOriginal: a queued input, drained, then a turn.
//
//	1 queued "my diagnosis is ..."  2 run start (trigger)  3 item drained
//	from 1 (source)  4 msg  5 resp-1  6 run end done
func queuedOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := recordsOriginal("orig-queued")
	text := "my diagnosis is fake-condition-0001"
	q := agentsession.NewQueued(openresponses.UserText(text), agentsession.ModeFollowUp).WithTrigger("human", "chat:fake-0001", "gateway")
	qID := appendAt(t, s, c, q)
	start := agentsession.NewRunStart("run-1", agentsession.SourceInput, "")
	start.Trigger = q.Trigger.Clone()
	appendAt(t, s, c, start)
	it := user(text)
	it.QueuedFrom = qID
	it.Source = q.Trigger.Clone()
	appendAt(t, s, c, it)
	respond(t, s, c, "resp-1", agentsession.NewItemEntry(openresponses.AssistantText("noted")))
	appendAt(t, s, c, agentsession.NewRunEnd("run-1", agentsession.ReasonDone, "", nil))
	return s
}

// queuedWith selects a queued entry whose original holds sub.
func queuedWith(sub string) func(c *EntryContext, e agentsession.Entry) bool {
	return func(c *EntryContext, _ agentsession.Entry) bool {
		q, ok := c.Entry().(*agentsession.QueuedEntry)
		if !ok {
			return false
		}
		data, err := json.Marshal(q.Item)
		return err == nil && bytes.Contains(data, []byte(sub))
	}
}

// TestQueuedGroup: a queued input and the items drained from it are one
// group, headed by the queued entry, which holds the input verbatim.
func TestQueuedGroup(t *testing.T) {
	// Leaving out the drained item alone would keep its text in the
	// queued entry: refused.
	orig := queuedOriginal(t, &clock{})
	p := structProfile("test.queued@1", []EntryRedactor{LeaveOut(userWith("diagnosis"))})
	if _, err := Redact(p, orig, nil); !errors.Is(err, ErrSplitsQueued) || !strings.Contains(err.Error(), "entry 3 ") {
		t.Errorf("leaving out the drained item alone: %v, want ErrSplitsQueued at entry 3", err)
	}

	// Leaving out the queued entry takes the drained item with it; the
	// run start's copy of its trigger is reported.
	for _, tt := range []struct {
		red  EntryRedactor
		want []string
	}{
		{LeaveOut(queuedWith("diagnosis")), []string{"2", "4", "5", "6"}},
		// The run start closes the queued entry's block, the response's
		// item the drained item's.
		{BlockOut(queuedWith("diagnosis")), []string{"1", "2", "3", "4", "5", "6"}},
	} {
		p := structProfile("test.queued@1", []EntryRedactor{tt.red})
		res := redact(t, p, orig, nil)
		checkStructural(t, p, orig, res, tt.want)
		absent(t, res, "diagnosis")
		if len(res.Findings) != 1 || res.Findings[0].Position != 2 || res.Findings[0].At != "/trigger" || strings.Contains(res.Findings[0].Message, "chat:fake") {
			t.Errorf("findings %+v, want the run start's trigger at 2", res.Findings)
		}
	}
}

// TestSummariesReported: what restates entries left out is reported,
// with no value: a branch summary of a branch left out, a compaction
// over entries left out before first_kept, an entry converging one left
// out.
func TestSummariesReported(t *testing.T) {
	t.Run("branch summary", func(t *testing.T) {
		c := &clock{}
		s := branchesOriginal(t, c)
		order := agentsession.FileOrder(s)
		bs, err := s.SummarizeBranch(order[5].Base().ID, openresponses.UserText("on A we tried things"))
		if err != nil {
			t.Fatal(err)
		}
		appendAt(t, s, c, bs) // 11, under the label on B
		turn(t, s, c, "resp-after", "after")
		p := structProfile("test.leaf@1", nil, KeepLeafPath())
		res := redact(t, p, s, nil)
		checkStructural(t, p, s, res, []string{"1", "2", "3", "7", "8", "9", "11", "12", "13"})
		if !hasFinding(res, 11, "/summary") {
			t.Errorf("findings %+v, want the branch summary at 11", res.Findings)
		}
	})
	t.Run("compaction", func(t *testing.T) {
		orig := compactionOriginal(t, &clock{})
		p := structProfile("test.fold@1", []EntryRedactor{LeaveOut(atPositions(1))})
		res := redact(t, p, orig, nil)
		checkStructural(t, p, orig, res, []string{"2", "3", "4", "5", "6", "7", "8", "9", "10"})
		if !hasFinding(res, 7, "/summary") {
			t.Errorf("findings %+v, want the compaction at 7", res.Findings)
		}
	})
	t.Run("parents", func(t *testing.T) {
		c := &clock{}
		s := newOriginal("orig-parents")
		root := appendAt(t, s, c, user("root"))
		w := user("worker branch")
		w.Parent = root
		wID := appendAt(t, s, c, w) // 2, folded
		k := user("worker kept")
		k.Parent = wID
		appendAt(t, s, c, k) // 3, closes the placeholder for 2
		d := user("dropped worker")
		d.Parent = root
		dID := appendAt(t, s, c, d) // 4, left out
		if err := s.Branch(root); err != nil {
			t.Fatal(err)
		}
		m := user("merged both")
		m.Parents = []agentsession.EntryRef{{Entry: wID}, {Entry: dID}}
		appendAt(t, s, c, m) // 5
		turn(t, s, c, "resp-1", "one")
		p := structProfile("test.parents@1", []EntryRedactor{BlockOut(userWith("worker branch")), LeaveOut(userWith("dropped worker"))})
		res := redact(t, p, s, nil)
		checkStructural(t, p, s, res, []string{"1", "2", "3", "5", "6", "7"})
		absent(t, res, "worker branch", "dropped worker")
		order := agentsession.FileOrder(res.Session)
		merged := order[3]
		if got := merged.Base().Parents; len(got) != 1 || got[0].Entry != order[1].Base().ID {
			t.Errorf("parents %+v, want the placeholder for 2 alone", got)
		}
		if !hasFinding(res, 5, "/parents") {
			t.Errorf("findings %+v, want the converging entry at 5", res.Findings)
		}
	})
}

func hasFinding(res *Result, pos int, at string) bool {
	for _, f := range res.Findings {
		if f.Position == pos && f.At == at {
			return true
		}
	}
	return false
}

// TestTargets: a target left out is named by its placeholder when one
// stands in its place; otherwise a label or outcome naming it is left
// out too, and a judged_by link loses its optional target.
func TestTargets(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-targets")
	appendAt(t, s, c, user("root"))
	sb := appendAt(t, s, c, user("secret-block one")) // 2, folded
	appendAt(t, s, c, user("kept after"))             // 3: placeholder for 2
	appendAt(t, s, c, agentsession.NewLabelEntry(sb, "on the block"))
	gone := appendAt(t, s, c, user("drop me")) // 5, left out
	appendAt(t, s, c, agentsession.NewOutcomeEntry("test", gone).WithPass(false))
	appendAt(t, s, c, agentsession.NewLabelEntry(gone, agentsession.LeafLabel))
	appendAt(t, s, c, agentsession.NewJudgedByLink("judge-session-fake", gone))
	turn(t, s, c, "resp-1", "one")
	p := structProfile("test.targets@1", []EntryRedactor{BlockOut(userWith("secret-block")), LeaveOut(userWith("drop me"))})
	res := redact(t, p, s, nil)
	checkStructural(t, p, s, res, []string{"1", "2", "3", "4", "8", "9", "10"})
	absent(t, res, "drop me", "secret-block")
	order := agentsession.FileOrder(res.Session)
	if l := order[3].(*agentsession.LabelEntry); l.Target != order[1].Base().ID {
		t.Errorf("the label names %s, want the placeholder %s", l.Target, order[1].Base().ID)
	}
	if l := order[4].(*agentsession.LinkEntry); l.Target != "" {
		t.Errorf("the judged_by link names %s, want no target", l.Target)
	}
}

// subsessionOriginal: a call with a subsession link and a cancel notice.
//
//	1 user  2 call c (resp-1)  3 resp-1  4 link  5 cancel  6 output
//	7 msg  8 resp-2
func subsessionOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := newOriginal("orig-sub")
	appendAt(t, s, c, user("spawn"))
	respond(t, s, c, "resp-1", call("call-sub"))
	link := agentsession.NewSubsessionLink(agentsession.SubsessionID("orig-sub", "call-sub"), "call-sub")
	appendAt(t, s, c, link)
	appendAt(t, s, c, agentsession.NewCancelSentLink(link))
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-sub", "cancelled")))
	respond(t, s, c, "resp-2", agentsession.NewItemEntry(openresponses.AssistantText("ok")))
	return s
}

func TestLinkGroup(t *testing.T) {
	orig := subsessionOriginal(t, &clock{})
	// The call takes its link, cancel notice and output with it, and its
	// response, which it was all the output of.
	p := structProfile("test.link@1", []EntryRedactor{LeaveOut(ofType(openresponses.ItemTypeFunctionCall))})
	res := redact(t, p, orig, nil)
	checkStructural(t, p, orig, res, []string{"1", "7", "8"})
	absent(t, res, "call-sub")
	for _, tt := range []struct {
		name string
		at   int
	}{{"a link alone", 4}, {"a cancel notice alone", 5}} {
		p := structProfile("test.link@1", []EntryRedactor{LeaveOut(atPositions(tt.at))})
		if _, err := Redact(p, orig, nil); !errors.Is(err, ErrSplitsCall) {
			t.Errorf("%s: %v, want ErrSplitsCall", tt.name, err)
		}
	}
}

// TestOmitCarried: an omit list loses the IDs left out, an omit that
// only added them is dropped, a checkpoint's omit follows; a keep
// counting over a config entry left out is refused.
func TestOmitCarried(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-omit")
	one := appendAt(t, s, c, user("omit me, and leave me out"))
	two := appendAt(t, s, c, user("omit me"))
	appendAt(t, s, c, &agentsession.ConfigEntry{Omit: &agentsession.Omit{Items: []string{one}}})
	appendAt(t, s, c, &agentsession.ConfigEntry{Omit: &agentsession.Omit{Items: []string{one, two}}})
	kept := appendAt(t, s, c, user("window"))
	turn(t, s, c, "resp-1", "one")
	comp, err := s.Compact(kept, openresponses.UserText("summary"))
	if err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, comp) // 8
	turn(t, s, c, "resp-2", "two")
	p := structProfile("test.omit@1", []EntryRedactor{LeaveOut(atPositions(1))})
	res := redact(t, p, s, nil)
	checkStructural(t, p, s, res, []string{"2", "3", "4", "5", "6", "7", "8", "9", "10"})
	order := agentsession.FileOrder(res.Session)
	twoID := order[0].Base().ID
	if c3 := order[1].(*agentsession.ConfigEntry); c3.Omit != nil {
		t.Errorf("the config that only omitted 1 keeps omit %+v", c3.Omit)
	}
	if c4 := order[2].(*agentsession.ConfigEntry); c4.Omit == nil || len(c4.Omit.Items) != 1 || c4.Omit.Items[0] != twoID {
		t.Errorf("omit %+v, want 2's redaction alone", c4.Omit)
	}
	if cp := order[6].(*agentsession.CompactionEntry); len(cp.Config.Omit.Items) != 1 || cp.Config.Omit.Items[0] != twoID {
		t.Errorf("checkpoint omit %+v, want 2's redaction alone", cp.Config.Omit)
	}

	// A keep counting over a config entry on a branch left out.
	s = newOriginal("orig-omit-of")
	root := appendAt(t, s, c, user("root"))
	appendAt(t, s, c, user("branch A"))
	x := appendAt(t, s, c, &agentsession.ConfigEntry{InstructionsOmitted: []agentsession.OmittedPart{{ID: "fake-part", Reason: "budget"}}})
	if err := s.Branch(root); err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, &agentsession.ConfigEntry{InstructionsOmitted: []agentsession.OmittedPart{{Keep: 1, Of: x}}})
	p = structProfile("test.omit@1", nil, DropBranches(func(c *EntryContext) bool { return userWith("branch A")(c, nil) }))
	if _, err := Redact(p, s, nil); !errors.Is(err, ErrNoPlace) || !strings.Contains(err.Error(), "entry 4 ") {
		t.Errorf("a keep over a config left out: %v, want ErrNoPlace at entry 4", err)
	}
}

// retryAfterRewind grows s, holding a call (2) and its response (3),
// with a retry: the call is dispatched on a branch the user abandons,
// then answered on the leaf's branch, rewound to the response.
//
//	4 dispatch (3)  5 user (4)  6 msg  7 resp-x  [abandoned]
//	8 answer (3)  9 output  10 msg  11 resp-2  [leaf]
//
// With side set, the dispatch hangs from an abandoned user message
// instead: 4 user (3), 5 dispatch (4).
func retryAfterRewind(t *testing.T, s *agentsession.Session, c *clock, side bool) {
	t.Helper()
	order := agentsession.FileOrder(s)
	callID, resp := order[1].Base().ID, order[2].Base().ID
	if side {
		appendAt(t, s, c, user("abandoned side note"))
	}
	appendAt(t, s, c, agentsession.NewDispatch("call-off", callID))
	if !side {
		appendAt(t, s, c, user("abandoned branch text"))
		respond(t, s, c, "resp-x", agentsession.NewItemEntry(openresponses.AssistantText("abandoned reply")))
	}
	if err := s.Branch(resp); err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, agentsession.NewDecision("call-off", callID, agentsession.VerdictAnswer, agentsession.ByHuman))
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-off", "answered")))
	respond(t, s, c, "resp-2", agentsession.NewItemEntry(openresponses.AssistantText("ok")))
	if err := s.VerifyRecords(s.Leaf()); err != nil {
		t.Fatalf("the fixture's records do not verify: %v", err)
	}
}

func callBase(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := recordsOriginal("orig-off-path")
	appendAt(t, s, c, user("go"))
	respond(t, s, c, "resp-1", call("call-off"))
	return s
}

// TestKeepLeafPathKeepsGroups: KeepLeafPath keeps the records of the
// path's own call that sit off it, where they sit, and nothing else of
// the abandoned branch; resuming after growth equals a fresh redaction.
func TestKeepLeafPathKeepsGroups(t *testing.T) {
	c := &clock{}
	s := callBase(t, c)
	p := structProfile("test.leaf@1", nil, KeepLeafPath())
	red := redact(t, p, s, nil).Session
	retryAfterRewind(t, s, c, false)
	res := redact(t, p, s, nil)
	checkStructural(t, p, s, res, []string{"1", "2", "3", "4", "8", "9", "10", "11"})
	absent(t, res, "abandoned")
	order := agentsession.FileOrder(res.Session)
	if d, ok := order[3].(*agentsession.DispatchEntry); !ok || d.Parent != order[2].Base().ID || d.Target != order[1].Base().ID {
		t.Errorf("the off-path dispatch is not kept under resp-1, naming the call: %+v", order[3])
	}
	red = resumeEqualsFresh(t, p, s, red)
	appendAt(t, s, c, user("more on the leaf"))
	resumeEqualsFresh(t, p, s, red)
}

// TestSessionGroupRules: what a session redactor leaves out is held to
// the group rules before anything is written, fresh and on resume.
func TestSessionGroupRules(t *testing.T) {
	// KeepLeafPath cannot keep a dispatch whose parent is the abandoned
	// conversation.
	c := &clock{}
	s := callBase(t, c)
	p := structProfile("test.leaf@1", nil, KeepLeafPath())
	red := redact(t, p, s, nil).Session
	before := fileOf(t, red)
	retryAfterRewind(t, s, c, true)
	if _, err := Redact(p, s, nil); !errors.Is(err, ErrSplitsCall) || !strings.Contains(err.Error(), "entry 5 ") {
		t.Errorf("fresh: %v, want ErrSplitsCall at entry 5", err)
	}
	if _, err := Redact(p, s, red); !errors.Is(err, ErrSplitsCall) {
		t.Errorf("resumed: %v, want ErrSplitsCall", err)
	}
	if !bytes.Equal(fileOf(t, red), before) {
		t.Error("the refused resume wrote to the existing redaction")
	}

	// DropBranches has no such widening: the same retry, with the
	// abandoned branch dropped, is refused.
	c = &clock{}
	s = callBase(t, c)
	retryAfterRewind(t, s, c, false)
	drop := structProfile("test.drop@1", nil, DropBranches(func(c *EntryContext) bool {
		_, ok := c.Entry().(*agentsession.DispatchEntry)
		return ok
	}))
	if _, err := Redact(drop, s, nil); !errors.Is(err, ErrSplitsCall) || !strings.Contains(err.Error(), "entry 4 ") {
		t.Errorf("DropBranches: %v, want ErrSplitsCall at entry 4", err)
	}

	// Everything after a time: the cut falls inside a response.
	orig := callOriginal(t, &clock{})
	cut := agentsession.FileOrder(orig)[5].Base().Timestamp // resp-1's
	after := structProfile("test.after@1", nil, DropBranches(func(c *EntryContext) bool {
		return !c.Entry().Base().Timestamp.Before(cut)
	}))
	if _, err := Redact(after, orig, nil); !errors.Is(err, ErrSplitsResponse) || !strings.Contains(err.Error(), "entry 6 ") {
		t.Errorf("after a time: %v, want ErrSplitsResponse at entry 6", err)
	}
}

// resumedRunsOriginal: a run leaves a call pending, the next resumes it
// and stops.
//
//	1 start r1  2 user  3 call c3 (resp-1)  4 resp-1  5 end r1 aborted [c3]
//	6 start r2 resume  7 dispatch  8 output  9 end r2 stopped
func resumedRunsOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := recordsOriginal("orig-runs")
	appendAt(t, s, c, agentsession.NewRunStart("run-1", agentsession.SourceInput, ""))
	appendAt(t, s, c, user("go"))
	ids := respond(t, s, c, "resp-1", call("call-c3"))
	appendAt(t, s, c, agentsession.NewRunEnd("run-1", agentsession.ReasonAborted, "", []string{"call-c3"}))
	appendAt(t, s, c, agentsession.NewRunStart("run-2", agentsession.SourceResume, ""))
	appendAt(t, s, c, agentsession.NewDispatch("call-c3", ids[0]))
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-c3", "out")))
	appendAt(t, s, c, agentsession.NewRunEnd("run-2", agentsession.ReasonStopped, "", nil))
	if err := s.VerifyRecords(s.Leaf()); err != nil {
		t.Fatalf("the fixture's records do not verify: %v", err)
	}
	return s
}

// TestEmptyResumeSegment: a placeholder that would be all a resumed
// run's segment holds is not written, so BlockOut passes where LeaveOut
// does.
func TestEmptyResumeSegment(t *testing.T) {
	orig := resumedRunsOriginal(t, &clock{})
	for _, tt := range []struct {
		red  EntryRedactor
		want []string
	}{
		{LeaveOut(ofType(openresponses.ItemTypeFunctionCall)), []string{"1", "2", "5", "6", "9"}},
		{BlockOut(ofType(openresponses.ItemTypeFunctionCall)), []string{"1", "2", "3-4", "5", "6", "9"}},
	} {
		p := structProfile("test.runs@1", []EntryRedactor{tt.red})
		res, err := Redact(p, orig, nil)
		if err != nil {
			t.Fatalf("%s: %v", redactorName(tt.red), err)
		}
		if got := marks(t, res.Session); strings.Join(got, " ") != strings.Join(tt.want, " ") {
			t.Errorf("%s: marks %q, want %q", redactorName(tt.red), got, tt.want)
		}
		for _, leaf := range res.Session.Leaves() {
			if err := res.Session.VerifyRecords(leaf); err != nil {
				t.Errorf("%s: records: %v", redactorName(tt.red), err)
			}
		}
	}
}

// pinnedOriginal: two pins, one copying an entry left out.
func pinnedOriginal(t *testing.T, c *clock, pins ...openresponses.Item) *agentsession.Session {
	t.Helper()
	s := newOriginal("orig-pins")
	appendAt(t, s, c, user("pin me, the secret one"))
	appendAt(t, s, c, user("pin me too"))
	turn(t, s, c, "resp-1", "one")
	kept := appendAt(t, s, c, user("kept window"))
	turn(t, s, c, "resp-2", "two")
	comp, err := s.Compact(kept, openresponses.UserText("summary"))
	if err != nil {
		t.Fatal(err)
	}
	comp.Pinned = pins
	appendAt(t, s, c, comp)
	appendAt(t, s, c, user("after"))
	turn(t, s, c, "resp-3", "three")
	return s
}

// TestPinnedFailsClosed: pins are matched by index; when an entry
// redactor changed their number, a pin to remove cannot be told apart,
// so every pin goes; a pin matching nothing is kept and reported.
func TestPinnedFailsClosed(t *testing.T) {
	dropFirstPin := EntryRedactorFunc(func(c *EntryContext, e agentsession.Entry) (agentsession.Entry, error) {
		if cp, ok := e.(*agentsession.CompactionEntry); ok && len(cp.Pinned) > 0 {
			cp.Pinned = cp.Pinned[1:]
		}
		return e, nil
	})
	s := pinnedOriginal(t, &clock{}, openresponses.UserText("pin me too"), openresponses.UserText("pin me, the secret one"))
	p := structProfile("test.pin@1", nil)
	p.Entries = append(p.Entries, dropFirstPin, LeaveOut(userWith("the secret one")))
	res := redact(t, p, s, nil)
	absent(t, res, "the secret one")
	if !hasFinding(res, 8, "/pinned") {
		t.Errorf("findings %+v, want the pins at 8", res.Findings)
	}

	s = pinnedOriginal(t, &clock{}, openresponses.UserText("pinned from nowhere"), openresponses.UserText("pin me too"))
	p = structProfile("test.pin@1", []EntryRedactor{LeaveOut(userWith("the secret one"))})
	res = redact(t, p, s, nil)
	checkStructural(t, p, s, res, []string{"2", "3", "4", "5", "6", "7", "8", "9", "10", "11"})
	if !hasFinding(res, 8, "/pinned/0") || !bytes.Contains(fileOf(t, res.Session), []byte("pinned from nowhere")) {
		t.Errorf("findings %+v: the unmatched pin is not kept and reported", res.Findings)
	}
}

// TestReplayComparesContent: a profile name reused for changed rules is
// refused on resume, whether the content of an entry differs or an entry
// a fresh redaction writes is missing, and nothing is written.
func TestReplayComparesContent(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-drift")
	appendAt(t, s, c, user("hello fake-name-0001"))
	turn(t, s, c, "resp-1", "hi")
	first := Profile{Name: "test.drift@1"}
	red := redact(t, first, s, nil).Session
	appendAt(t, s, c, user("more"))
	before := fileOf(t, red)
	for _, tt := range []struct {
		name string
		p    Profile
	}{
		{"content", Profile{Name: "test.drift@1", Strings: []StringRedactor{Secrets("fake-name-0001")}}},
		{"an entry missing", Profile{Name: "test.drift@1", Entries: []EntryRedactor{LeaveOut(atPositions(1))}}},
	} {
		if _, err := Redact(tt.p, s, red); !errors.Is(err, ErrResumeDiverged) {
			t.Errorf("%s: %v, want ErrResumeDiverged", tt.name, err)
		}
		if !bytes.Equal(fileOf(t, red), before) {
			t.Errorf("%s: the refused resume wrote to the existing redaction", tt.name)
		}
	}
	// The other way: an entry a fresh redaction does not write.
	left := Profile{Name: "test.drift@2", Entries: []EntryRedactor{LeaveOut(atPositions(4))}}
	red2 := redact(t, Profile{Name: "test.drift@2"}, s, nil).Session
	if _, err := Redact(left, s, red2); !errors.Is(err, ErrResumeDiverged) {
		t.Errorf("an entry held that fresh does not write: %v, want ErrResumeDiverged", err)
	}
}

// TestResumeGroupShapes: each group whose head is at or below the
// highest position written and whose member comes after resumes equal
// to a fresh redaction.
func TestResumeGroupShapes(t *testing.T) {
	type stage func(t *testing.T, s *agentsession.Session, c *clock)
	for _, tt := range []struct {
		name   string
		p      Profile
		build  stage
		grow   stage
		marks1 string
		marks2 string
	}{
		{"a call folded, its output later", structProfile("test.g1@1", []EntryRedactor{BlockOut(ofType(openresponses.ItemTypeFunctionCall))}),
			func(t *testing.T, s *agentsession.Session, c *clock) {
				appendAt(t, s, c, user("go"))
				respond(t, s, c, "resp-1", call("call-g1"))
			},
			func(t *testing.T, s *agentsession.Session, c *clock) {
				appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-g1", "out")))
				appendAt(t, s, c, user("next"))
				turn(t, s, c, "resp-2", "two")
			}, "1", "1 2-4 5 6 7"},
		{"a response's items folded, the response later", structProfile("test.g2@1", []EntryRedactor{BlockOut(atPositions(4))}),
			func(t *testing.T, s *agentsession.Session, c *clock) {
				appendAt(t, s, c, user("go"))
				turn(t, s, c, "resp-1", "one")
				reply := agentsession.NewItemEntry(openresponses.AssistantText("folded"))
				reply.ResponseID = "resp-2"
				appendAt(t, s, c, reply)
			},
			func(t *testing.T, s *agentsession.Session, c *clock) {
				resp := &agentsession.ResponseEntry{ResponseID: "resp-2", Status: openresponses.ResponseStatusCompleted}
				appendAt(t, s, c, resp)
				appendAt(t, s, c, user("next"))
				turn(t, s, c, "resp-3", "three")
			}, "1 2 3", "1 2 3 4-5 6 7 8"},
		{"a run start left out, its end later", structProfile("test.g3@1", []EntryRedactor{LeaveOut(func(c *EntryContext, _ agentsession.Entry) bool {
			r, ok := c.Entry().(*agentsession.RunEntry)
			return ok && r.IsStart()
		})}),
			func(t *testing.T, s *agentsession.Session, c *clock) {
				appendAt(t, s, c, agentsession.NewRunStart("run-g3", agentsession.SourceInput, ""))
				appendAt(t, s, c, user("go"))
			},
			func(t *testing.T, s *agentsession.Session, c *clock) {
				turn(t, s, c, "resp-1", "one")
				appendAt(t, s, c, agentsession.NewRunEnd("run-g3", agentsession.ReasonDone, "", nil))
				appendAt(t, s, c, user("next"))
				turn(t, s, c, "resp-2", "two")
			}, "2", "2 3 4 6 7 8"},
		{"a compaction later whose first_kept was left out", structProfile("test.g4@1", []EntryRedactor{LeaveOut(atPositions(4))}),
			func(t *testing.T, s *agentsession.Session, c *clock) {
				appendAt(t, s, c, user("first"))
				turn(t, s, c, "resp-1", "one")
				appendAt(t, s, c, user("first kept, left out"))
			},
			func(t *testing.T, s *agentsession.Session, c *clock) {
				turn(t, s, c, "resp-2", "two")
				comp, err := s.Compact(agentsession.FileOrder(s)[3].Base().ID, openresponses.UserText("summary"))
				if err != nil {
					t.Fatal(err)
				}
				appendAt(t, s, c, comp)
				appendAt(t, s, c, user("after"))
				turn(t, s, c, "resp-3", "three")
			}, "1 2 3", "1 2 3 5 6 7 8 9 10"},
		{"a label later naming a folded entry", blockProfile("test.g5@1"),
			func(t *testing.T, s *agentsession.Session, c *clock) {
				appendAt(t, s, c, user("go"))
				turn(t, s, c, "resp-1", "one")
				appendAt(t, s, c, user("secret-block open"))
			},
			func(t *testing.T, s *agentsession.Session, c *clock) {
				appendAt(t, s, c, agentsession.NewLabelEntry(agentsession.FileOrder(s)[3].Base().ID, "the block"))
				appendAt(t, s, c, user("next"))
				turn(t, s, c, "resp-2", "two")
			}, "1 2 3", "1 2 3 4 6 7 8"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &clock{}
			s := newOriginal("orig-groups")
			tt.build(t, s, c)
			red := redact(t, tt.p, s, nil).Session
			if got := strings.Join(marks(t, red), " "); got != tt.marks1 {
				t.Errorf("first marks %q, want %q", got, tt.marks1)
			}
			tt.grow(t, s, c)
			red = resumeEqualsFresh(t, tt.p, s, red)
			if got := strings.Join(marks(t, red), " "); got != tt.marks2 {
				t.Errorf("grown marks %q, want %q", got, tt.marks2)
			}
		})
	}
}

// TestSidecarResumeBlobs: a resume onto new entries returns the blobs of
// those it wrote alone: the placeholder's for a new sidecar image,
// nothing for an entry without one.
func TestSidecarResumeBlobs(t *testing.T) {
	c := &clock{}
	s := agentsession.New(agentsession.Header{ID: "orig-sidecar-grow", CreatedAt: t0, Media: agentsession.MediaSidecar})
	appendAt(t, s, c, user("first"))
	turn(t, s, c, "resp-1", "one")
	p := testProfile()
	red := redact(t, p, s, nil)
	if red.Blobs != nil {
		t.Fatalf("blobs %v with no image", red.Blobs)
	}
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.UserMessage(&openresponses.InputImage{ImageURL: "sidecar:" + agentsession.HashText("FAKE-IMAGE-BLOB-0003")})))
	grown := redact(t, p, s, red.Session)
	blob, _ := placeholderBytes(DefaultImagePlaceholder)
	if len(grown.Blobs) != 1 || !bytes.Equal(grown.Blobs[agentsession.HashBytes(blob)], blob) {
		t.Errorf("blobs %v, want the placeholder's alone", grown.Blobs)
	}
	appendAt(t, s, c, user("no image"))
	if again := redact(t, p, s, grown.Session); again.Blobs != nil || len(again.Entries) != 1 {
		t.Errorf("blobs %v and %d entries for one entry without an image", again.Blobs, len(again.Entries))
	}
}

// TestZeroTimestamp: an entry a redactor writes with no timestamp, made
// from an entry with none, takes the previous entry's, never a clock.
func TestZeroTimestamp(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-zero-ts")
	appendAt(t, s, c, user("first"))
	turn(t, s, c, "resp-1", "one")
	add := StructureRedactorFunc(func(c *EntryContext, e agentsession.Entry) ([]Made, error) {
		if c.Position != 3 {
			return []Made{{Entry: e}}, nil
		}
		note := &agentsession.CustomEntry{NS: "x.fake", Data: json.RawMessage(`{}`)}
		return []Made{{Entry: e}, {Entry: note, Added: true}, {Entry: user("again")}}, nil
	})
	p := structProfile("test.ts@1", []EntryRedactor{add})
	res := redact(t, p, s, nil)
	for _, e := range agentsession.FileOrder(res.Session) {
		if ts := e.Base().Timestamp; ts.IsZero() || ts.After(t0.Add(time.Hour)) {
			t.Errorf("entry %s has timestamp %s", e.EntryType(), ts)
		}
	}
}
