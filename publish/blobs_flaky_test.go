package publish

import (
	"context"
	"errors"
	"testing"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// flaky fails its first blob reads with an error that is not ErrNoBlob.
type flaky struct {
	*agentsession.MemoryStore
	fail int
}

var errFlaky = errors.New("synthetic: the blob store is briefly away")

func (f *flaky) SessionBlob(ctx context.Context, session, hash string) ([]byte, string, error) {
	if f.fail > 0 {
		f.fail--
		return nil, "", errFlaky
	}
	return f.MemoryStore.SessionBlob(ctx, session, hash)
}

// TestRedactTransientBlobError: a blob read that fails for a while
// writes nothing for the session; the next pass redacts it (review,
// finding 4).
func TestRedactTransientBlobError(t *testing.T) {
	ctx := context.Background()
	private := &flaky{MemoryStore: agentsession.NewMemoryStore(), fail: 1}
	h := putBlob(t, private, "notes "+fakeToken, "text/plain")
	o := blobSession(t, "orig-flaky", "ok", &openresponses.InputFile{Filename: "notes.txt", FileData: "sidecar:" + h})
	load(t, private, o)
	redID := agentredact.RedactedID(key(t), o.ID(), profile.Name)
	rep, _ := agentredact.RedactStore(ctx, private, profile, key(t), agentredact.StoreOptions{})
	if len(rep.Sessions) != 1 || rep.Sessions[0].Err == nil {
		t.Errorf("first pass: %+v, want the session failed", rep.Sessions)
	}
	if _, err := private.Read(ctx, redID); !errors.Is(err, agentsession.ErrNoSession) {
		t.Errorf("the first pass wrote the redaction: %v", err)
	}
	rep, err := agentredact.RedactStore(ctx, private, profile, key(t), agentredact.StoreOptions{})
	if err != nil || !rep.Sessions[0].Publishable() {
		t.Fatalf("second pass: %v, %+v", err, rep.Sessions)
	}
	red, err := private.Read(ctx, redID)
	if err != nil {
		t.Fatal(err)
	}
	if refs, _ := agentredact.SidecarRefs(red); len(refs) != 1 || refs[0] == h {
		t.Errorf("references %v: want the redacted copy", refs)
	}
}
