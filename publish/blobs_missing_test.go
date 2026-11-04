package publish

import (
	"context"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// TestPublishMissingBlob: a session referencing a blob the store never
// held is held, and the reason says which reference and that its blob is
// missing; the public report names the reference by its position, not
// its hash (round 2 review, R2-3, R2-4).
func TestPublishMissingBlob(t *testing.T) {
	private := agentsession.NewMemoryStore()
	h := agentsession.HashText("a blob never stored")
	load(t, private, blobSession(t, "orig-missing", "ok", &openresponses.InputFile{Filename: "gone.txt", FileData: "sidecar:" + h}))
	rep, _ := agentredact.RedactStore(context.Background(), private, profile, key(t), agentredact.StoreOptions{})
	target := agentsession.NewMemoryStore(agentsession.MemoryRedactedOnly())
	res, err := Publish(context.Background(), private, target, Options{Profile: profile.Name, Report: rep, Unjudged: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Held) != 1 {
		t.Fatalf("held %+v", res.Held)
	}
	reason := res.Held[0].Reason
	if !strings.Contains(reason, "missing") || !strings.Contains(reason, "/item/content/1/file_data") || !strings.Contains(reason, "entry 4") {
		t.Errorf("held for %q: want the reference named and the blob said missing", reason)
	}
	pub := rep.Public(key(t))
	if e := pub.Sessions[0].Err; e == nil || strings.Contains(e.Error(), strings.TrimPrefix(h, "sha256:")) || !strings.Contains(e.Error(), "/item/content/1/file_data") {
		t.Errorf("the public report's error %v: want the reference named, not the hash", e)
	}
}
