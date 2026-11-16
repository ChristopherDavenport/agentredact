package scan

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// TestScanSidecarImageWithATIF: a redacted sidecar session holding an
// image is scanned with its ATIF documents, the image read through the
// scan's blob reader: since agentsession v0.0.38 the ATIF export of
// such a session resolves the image's blob and refuses without a reader.
func TestScanSidecarImageWithATIF(t *testing.T) {
	ctx := context.Background()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(1, 1, color.RGBA{R: 200, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	store := agentsession.NewMemoryStore()
	h, err := store.PutTypedBlob(ctx, buf.Bytes(), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	s := agentsession.New(agentsession.Header{ID: "orig-scan-image", CreatedAt: t0, Media: agentsession.MediaSidecar})
	e := agentsession.NewItemEntry(openresponses.UserMessage(&openresponses.InputText{Text: "see " + fakeAWS}, &openresponses.InputImage{ImageURL: "sidecar:" + h}))
	e.Timestamp = t0.Add(time.Second)
	if _, err := s.Append(e); err != nil {
		t.Fatal(err)
	}
	var file bytes.Buffer
	if err := agentsession.Write(&file, s); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(ctx, &file, true); err != nil {
		t.Fatal(err)
	}
	p := agentredact.Profile{Name: "scan.default@1", Strings: []agentredact.StringRedactor{agentredact.DefaultPatterns()}}
	if _, err := agentredact.RedactStore(ctx, store, p, testKey(t), agentredact.StoreOptions{AcceptFindings: []agentredact.FindingKind{"image"}}); err != nil {
		t.Fatal(err)
	}
	red, err := store.Read(ctx, agentredact.RedactedID(testKey(t), s.ID(), p.Name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stub.Scan(ctx, red, store); err != nil {
		t.Fatalf("scanning a sidecar session with an image and its ATIF: %v", err)
	}
}
