package publish

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/agentsession/jsonl"
	"github.com/ChristopherDavenport/openresponses"
)

// Every value here is synthetic.

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func key(t *testing.T) agentredact.Key {
	k, err := agentredact.NewKey([]byte("agentredact-publish-test-key-not-secret"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var profile = agentredact.Profile{Name: "publish.test@1", Strings: []agentredact.StringRedactor{agentredact.DefaultPatterns()}}

// session is an original of n user messages, the first holding text.
func session(t *testing.T, id string, texts ...string) *agentsession.Session {
	t.Helper()
	s := agentsession.New(agentsession.Header{ID: id, CreatedAt: t0})
	for i, x := range texts {
		grow(t, s, i, x)
	}
	return s
}

func grow(t *testing.T, s *agentsession.Session, i int, text string) {
	t.Helper()
	e := agentsession.NewItemEntry(openresponses.UserText(text))
	e.Timestamp = t0.Add(time.Duration(i+1) * time.Second)
	if _, err := s.Append(e); err != nil {
		t.Fatal(err)
	}
}

func file(t *testing.T, s *agentsession.Session) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := agentsession.Write(&buf, s); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func load(t *testing.T, st agentsession.Store, s *agentsession.Session) {
	t.Helper()
	if _, err := st.(agentsession.Importer).Import(context.Background(), bytes.NewReader(file(t, s)), true); err != nil {
		t.Fatal(err)
	}
}

func pass(t *testing.T, st agentsession.Store) *agentredact.StoreReport {
	t.Helper()
	rep, err := agentredact.RedactStore(context.Background(), st, profile, key(t), agentredact.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// TestPublish: what is published is exactly the redactions the store
// pass holds publishable and the judges cleared at their judged entry,
// named by their own ID and head; the target, holding only redacted
// entries, refuses an original; a redaction that grew is published
// again by its new entries once judged again (#6).
func TestPublish(t *testing.T) {
	ctx := context.Background()
	private := agentsession.NewMemoryStore()
	clean := session(t, "orig-clean", "hello", "again")
	media := session(t, "orig-media", "data:application/pdf;base64,AAAA") // inline media, kept and reported
	load(t, private, clean)
	load(t, private, media)
	rep := pass(t, private)
	target := agentsession.NewMemoryStore(agentsession.MemoryRedactedOnly())

	cleanRed := agentredact.RedactedID(key(t), clean.ID(), profile.Name)
	mediaRed := agentredact.RedactedID(key(t), media.ID(), profile.Name)
	// A scan is required unless the caller opts out by name; opted out,
	// the store pass's verdict alone decides, into a target of its own.
	alone := agentsession.NewMemoryStore(agentsession.MemoryRedactedOnly())
	res, err := Publish(ctx, private, alone, Options{Profile: profile.Name, Report: rep})
	if err != nil || len(res.Published) != 0 {
		t.Fatalf("no judge named: %+v, %v; want the scan required", res, err)
	}
	res, err = Publish(ctx, private, alone, Options{Profile: profile.Name, Report: rep, Unjudged: true})
	if err != nil || len(res.Published) != 1 || res.Published[0].Session != cleanRed || len(res.Held) != 1 || res.Held[0].Session != mediaRed {
		t.Fatalf("no judges: %+v, %v", res, err)
	}
	res, err = Publish(ctx, private, target, Options{Profile: profile.Name, Report: rep, Judges: []string{"scan"}})
	if err != nil || len(res.Published) != 0 || len(res.Held) != 2 {
		t.Fatalf("unjudged: %+v, %v", res, err)
	}
	red, err := private.Read(ctx, cleanRed)
	if err != nil {
		t.Fatal(err)
	}
	verdict := func(at time.Time) {
		v, err := agentredact.WriteVerdict(red, agentredact.JudgedEntry(red), agentredact.Verdict{Judge: "scan", Kind: "test", Pass: true, Covered: agentredact.StateOf(red)}, at)
		if err != nil {
			t.Fatal(err)
		}
		load(t, private, v)
	}
	verdict(t0.Add(time.Hour))
	res, err = Publish(ctx, private, target, Options{Profile: profile.Name, Report: rep, Judges: []string{"scan"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Published) != 1 || res.Published[0].Session != cleanRed || res.Published[0].Head != red.Leaf() || res.Published[0].Appended != 2 {
		t.Errorf("published %+v, want the clean redaction alone", res.Published)
	}
	if len(res.Held) != 1 || res.Held[0].Session != mediaRed {
		t.Errorf("held %+v, want the redaction keeping media", res.Held)
	}
	var listed []string
	for sum, err := range target.List(ctx, agentsession.ListFilter{}) {
		if err != nil {
			t.Fatal(err)
		}
		listed = append(listed, sum.Header.ID)
	}
	if len(listed) != 1 || listed[0] != cleanRed {
		t.Errorf("the target holds %v", listed)
	}
	if _, err := target.Import(ctx, bytes.NewReader(file(t, clean)), true); err == nil {
		t.Error("the target took an original")
	}

	// The original grows: held until judged again, then appended.
	grow(t, clean, 2, "third")
	held, _ := private.Read(ctx, clean.ID())
	e := agentsession.FileOrder(clean)[2]
	data, _ := agentsession.MarshalEntry(e)
	own, _ := agentsession.UnmarshalEntry(data)
	if _, err := private.Append(ctx, held.ID(), own); err != nil {
		t.Fatal(err)
	}
	rep = pass(t, private)
	if res, err = Publish(ctx, private, target, Options{Profile: profile.Name, Report: rep, Judges: []string{"scan"}}); err != nil || len(res.Published) != 0 {
		t.Errorf("a redaction grown since it was judged: %+v, %v", res, err)
	}
	if red, err = private.Read(ctx, cleanRed); err != nil {
		t.Fatal(err)
	}
	verdict(t0.Add(2 * time.Hour))
	res, err = Publish(ctx, private, target, Options{Profile: profile.Name, Report: rep, Judges: []string{"scan"}})
	if err != nil || len(res.Published) != 1 || res.Published[0].Appended != 1 {
		t.Fatalf("judged again: %+v, %v", res, err)
	}
	got, err := target.Read(ctx, cleanRed)
	if err != nil || !bytes.Equal(file(t, got), file(t, red)) {
		t.Errorf("the target's copy differs from the private redaction: %v", err)
	}
}

// TestPublishBranchAfterVerdict: a verdict clears only the state it
// judged. A branch appended after the scan, which leaves the head where
// it was, is not published on the old verdict (review finding 1).
func TestPublishBranchAfterVerdict(t *testing.T) {
	ctx := context.Background()
	// jsonl keeps the head with a leaf label after a branch append.
	private, err := jsonl.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { private.Close() })
	o := session(t, "orig-branch", "e1", "e2")
	load(t, private, o)
	pass(t, private)
	redID := agentredact.RedactedID(key(t), o.ID(), profile.Name)
	red, err := private.Read(ctx, redID)
	if err != nil {
		t.Fatal(err)
	}
	judged := agentredact.JudgedEntry(red)
	v, err := agentredact.WriteVerdict(red, judged, agentredact.Verdict{Judge: "scan", Kind: "test", Pass: true, Covered: agentredact.StateOf(red)}, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	load(t, private, v)
	// e3 hangs from e1: a branch, which does not move the head.
	e3 := agentsession.NewItemEntry(openresponses.UserText("a branch holding hf_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00"))
	e3.Parent = agentsession.FileOrder(o)[0].Base().ID
	e3.Timestamp = t0.Add(3 * time.Second)
	if _, err := private.Append(ctx, o.ID(), e3); err != nil {
		t.Fatal(err)
	}
	rep := pass(t, private)
	if red, err = private.Read(ctx, redID); err != nil || agentredact.JudgedEntry(red) != judged {
		t.Fatalf("the head moved (%v); the case proves nothing", err)
	}
	target := agentsession.NewMemoryStore(agentsession.MemoryRedactedOnly())
	res, err := Publish(ctx, private, target, Options{Profile: profile.Name, Report: rep, Judges: []string{"scan"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Published) != 0 {
		t.Errorf("published %+v on a verdict that did not judge the branch", res.Published)
	}
}

// TestPublishStaleReport: a report says what was publishable in the
// state the store pass read; one from before the session changed does
// not publish it (review finding 2).
func TestPublishStaleReport(t *testing.T) {
	ctx := context.Background()
	private := agentsession.NewMemoryStore()
	o := session(t, "orig-stale", "first")
	load(t, private, o)
	old := pass(t, private)
	e := agentsession.NewItemEntry(openresponses.UserText("second"))
	e.Timestamp = t0.Add(5 * time.Second)
	if _, err := private.Append(ctx, o.ID(), e); err != nil {
		t.Fatal(err)
	}
	fresh := pass(t, private)
	redID := agentredact.RedactedID(key(t), o.ID(), profile.Name)
	red, err := private.Read(ctx, redID)
	if err != nil {
		t.Fatal(err)
	}
	v, err := agentredact.WriteVerdict(red, agentredact.JudgedEntry(red), agentredact.Verdict{Judge: "scan", Kind: "test", Pass: true, Covered: agentredact.StateOf(red)}, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	load(t, private, v)
	target := agentsession.NewMemoryStore(agentsession.MemoryRedactedOnly())
	res, err := Publish(ctx, private, target, Options{Profile: profile.Name, Report: old, Judges: []string{"scan"}})
	if err != nil || len(res.Published) != 0 {
		t.Errorf("a stale report published %+v, %v", res, err)
	}
	if res, err = Publish(ctx, private, target, Options{Profile: profile.Name, Report: fresh, Judges: []string{"scan"}}); err != nil || len(res.Published) != 1 {
		t.Errorf("the current report: %+v, %v", res, err)
	}
}
