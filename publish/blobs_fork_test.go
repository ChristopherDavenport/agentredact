package publish

import (
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// Every value here is synthetic.

// fakePDF is the start of a PDF with a binary comment line, as real
// PDFs carry one, and a fake token in it.
const fakePDF = "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj (" + fakeToken + ") endobj\n"

// everyKind is every finding kind a publisher might accept.
var everyKind = []agentredact.FindingKind{"image", "sidecar-media", "unredacted-blob", "blob-too-large", "member-name", "header-member-name"}

// TestPublishForkKeptPrefixBlob: a fork whose prefix references a blob
// the redaction kept by rule is held while that rule's finding is not
// accepted, as its origin is (agentredact#23 review, finding 1).
func TestPublishForkKeptPrefixBlob(t *testing.T) {
	private := agentsession.NewMemoryStore()
	pdf := putBlob(t, private, fakePDF, "application/pdf")
	o := blobSession(t, "orig-fork-pdf", "ok", &openresponses.InputFile{Filename: "fake.pdf", FileData: "sidecar:" + pdf})
	load(t, private, o)
	order := agentsession.FileOrder(o)
	f, err := agentsession.Fork(o, order[len(order)-1].Base().ID, agentsession.Header{ID: "orig-fork-pdf-fork", CreatedAt: t0, Media: agentsession.MediaSidecar})
	if err != nil {
		t.Fatal(err)
	}
	e := agentsession.NewItemEntry(openresponses.UserText("on the fork"))
	e.Timestamp = t0.Add(time.Minute)
	if _, err := f.Append(e); err != nil {
		t.Fatal(err)
	}
	load(t, private, f)
	res, target, rep := publishOne(t, private)
	forkRed := agentredact.RedactedID(key(t), f.ID(), profile.Name)
	for _, r := range rep.Sessions {
		if r.Redaction == forkRed && !r.Fork {
			t.Fatalf("the fork was not redacted as a fork: %+v", r)
		}
	}
	if len(res.Published) != 0 {
		t.Errorf("published %+v: want the origin and the fork held for the kept PDF", res.Published)
	}
	if holds(t, target, pdf) {
		t.Error("the target holds the PDF no one accepted")
	}
}
