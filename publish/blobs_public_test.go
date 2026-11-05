package publish

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// pathErrors fails every blob read as a file store does: naming the
// hash, its bare digest and the file's path under the home directory.
type pathErrors struct {
	*agentsession.MemoryStore
	home string
}

func (p pathErrors) SessionBlob(_ context.Context, _, hash string) ([]byte, string, error) {
	hex := strings.TrimPrefix(hash, "sha256:")
	return nil, "", fmt.Errorf("jsonl: blob %s: open %s/store/media/%s: permission denied", hash, p.home, hex)
}

// TestPublicErrorNamesNoPathOrDigest: the public report's error for a
// blob that could not be read names the reference, never the blob's
// digest, bare or not, nor the store's path, which names the user
// (#23 review round 3).
func TestPublicErrorNamesNoPathOrDigest(t *testing.T) {
	home := "/home/fake-user-0001"
	t.Setenv("HOME", home)
	st := pathErrors{MemoryStore: agentsession.NewMemoryStore(), home: home}
	h := putBlob(t, st.MemoryStore, "notes "+fakeToken, "text/plain")
	load(t, st, blobSession(t, "orig-path-error", "ok", &openresponses.InputFile{Filename: "notes.txt", FileData: "sidecar:" + h}))
	rep, _ := agentredact.RedactStore(context.Background(), st, profile, key(t), agentredact.StoreOptions{})
	e := rep.Public(key(t)).Sessions[0].Err
	if e == nil {
		t.Fatal("no error")
	}
	msg := e.Error()
	if strings.Contains(msg, strings.TrimPrefix(h, "sha256:")) || strings.Contains(msg, home) || strings.Contains(msg, "fake-user") || !strings.Contains(msg, "/item/content/1/file_data") {
		t.Errorf("the public error %q: want the reference named, and no digest or path", msg)
	}
}
