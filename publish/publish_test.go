package publish

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
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

func load(t *testing.T, st *agentsession.MemoryStore, s *agentsession.Session) {
	t.Helper()
	if _, err := st.Import(context.Background(), bytes.NewReader(file(t, s)), true); err != nil {
		t.Fatal(err)
	}
}

func pass(t *testing.T, st *agentsession.MemoryStore) *agentredact.StoreReport {
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
	// With no judge required, the store pass's verdict alone decides,
	// into a target of its own.
	alone := agentsession.NewMemoryStore(agentsession.MemoryRedactedOnly())
	res, err := Publish(ctx, private, alone, Options{Profile: profile.Name, Report: rep})
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
		v, err := agentredact.WriteVerdict(red, agentredact.JudgedEntry(red), agentredact.Verdict{Judge: "scan", Kind: "test", Pass: true}, at)
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
