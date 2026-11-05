package publish

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentsession"
)

// TestPublishHashNames: a sidecar URL the header holds, or one inside
// text spelled with another case, is not published (review, finding 5).
func TestPublishHashNames(t *testing.T) {
	ctx := context.Background()
	private := agentsession.NewMemoryStore()
	h := putBlob(t, private, "whole output "+fakeToken, "text/plain")
	hex := strings.TrimPrefix(h, "sha256:")
	o := blobSession(t, "orig-hash-names", "whole output at SIDECAR:sha256:"+hex, nil)
	hd := o.Header()
	hd.CWD = "sidecar:" + h
	s := agentsession.New(hd)
	for _, e := range agentsession.FileOrder(o) {
		data, _ := agentsession.MarshalEntry(e)
		own, _ := agentsession.UnmarshalEntry(data)
		if _, err := s.Append(own); err != nil {
			t.Fatal(err)
		}
	}
	load(t, private, s)
	res, target, _ := publishOne(t, private)
	if len(res.Published) != 1 {
		t.Fatalf("published %+v, held %+v", res.Published, res.Held)
	}
	got, err := target.Read(ctx, res.Published[0].Session)
	if err != nil {
		t.Fatal(err)
	}
	if f := file(t, got); bytes.Contains(bytes.ToLower(f), []byte(hex)) {
		t.Errorf("the published session names the blob:\n%s", f)
	}
}
