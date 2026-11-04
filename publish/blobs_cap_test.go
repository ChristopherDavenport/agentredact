package publish

import (
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// TestPublishBlobOverCap: a text blob over the default cap is not
// read through the redactors, and never leaves (review, finding 3).
func TestPublishBlobOverCap(t *testing.T) {
	private := agentsession.NewMemoryStore()
	big := strings.Repeat("a line of a large log\n", (8<<20)/22+1) + fakeToken
	h := putBlob(t, private, big, "text/plain")
	load(t, private, blobSession(t, "orig-big", "ok", &openresponses.InputFile{Filename: "big.log", FileData: "sidecar:" + h}))
	res, target, _ := publishOne(t, private, everyKind...)
	if len(res.Published) != 0 || len(res.Held) != 1 {
		t.Errorf("published %+v, held %+v: want it held", res.Published, res.Held)
	}
	if holds(t, target, h) {
		t.Error("the target holds the large blob")
	}
}
