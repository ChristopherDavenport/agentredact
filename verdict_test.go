package agentredact

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentsession"
)

// TestVerdict: a verdict is an outcome in a fork of the redacted session
// at the entry judged, which carries no redacted, names counts and
// entries and no value, is refused by a store holding only redacted
// entries, is listed for the redaction, is skipped by the store pass,
// and clears the session only at the entry it judged (RFC 0001 0.19).
func TestVerdict(t *testing.T) {
	ctx := context.Background()
	c := &clock{}
	orig := plainOriginal(t, c)
	st := agentsession.NewMemoryStore()
	load(t, st, orig)
	p := testProfile()
	redactStore(t, st, p, StoreOptions{})
	red := read(t, st, redIDOf(orig.ID(), p.Name))
	judged := JudgedEntry(red)
	found := red.Entries()[2].Base().ID
	v, err := WriteVerdict(red, judged, Verdict{Judge: "scan", Kind: "test", Findings: map[string]int{"AWS": 1}, Entries: []string{found, found}}, t0)
	if err != nil {
		t.Fatal(err)
	}
	h := v.Header()
	if h.Redacted || h.Base != judged || h.ParentSession != red.ID() || h.ID != VerdictID(red.ID(), judged, "scan", t0) {
		t.Errorf("verdict header %+v", h)
	}
	own := agentsession.FileOrder(v)[len(agentsession.FileOrder(v))-1].(*agentsession.OutcomeEntry)
	if own.Target != judged || own.Pass == nil || *own.Pass || own.Kind != "test" {
		t.Errorf("outcome %+v", own)
	}
	var d map[string]any
	if err := json.Unmarshal(own.Details, &d); err != nil || len(d["agentredact:entries"].([]any)) != 1 {
		t.Errorf("details %s: %v", own.Details, err)
	}
	file := fileOf(t, v)
	if _, err := st.Import(ctx, bytes.NewReader(file), true); err != nil {
		t.Fatalf("the private store refuses the verdict: %v", err)
	}
	pub := agentsession.NewMemoryStore(agentsession.MemoryRedactedOnly())
	if _, err := pub.Import(ctx, bytes.NewReader(fileOf(t, red)), true); err != nil {
		t.Fatalf("the redacted-only store refuses the redaction: %v", err)
	}
	if _, err := pub.Import(ctx, bytes.NewReader(file), true); err == nil {
		t.Error("the redacted-only store took the verdict")
	}
	got, err := Verdicts(ctx, st, red.ID())
	if err != nil || len(got) != 1 || got[0].Judge != "scan" || got[0].Pass || got[0].Judged != judged || got[0].Findings["AWS"] != 1 {
		t.Fatalf("verdicts %+v, %v", got, err)
	}
	if Cleared(got, red, "scan") {
		t.Error("a failed scan clears the session")
	}
	pass, err := WriteVerdict(red, judged, Verdict{Judge: "scan", Kind: "test", Pass: true}, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Import(ctx, bytes.NewReader(fileOf(t, pass)), true); err != nil {
		t.Fatal(err)
	}
	if got, err = Verdicts(ctx, st, red.ID()); err != nil || len(got) != 2 || !Cleared(got, red, "scan") {
		t.Errorf("a later passing scan does not clear the session: %+v, %v", got, err)
	}
	if Cleared(got, red, "scan", "review") {
		t.Error("cleared with no review")
	}
	rep := redactStore(t, st, p, StoreOptions{})
	if rep.Skipped != 3 || len(rep.Sessions) != 1 {
		t.Errorf("the store pass redacted a verdict: skipped %d, sessions %d", rep.Skipped, len(rep.Sessions))
	}
}
