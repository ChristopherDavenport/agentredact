package publish

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// Every value here is synthetic: the tokens are fake and spelled so.

const fakeToken = "hf_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE01"

// blobSession is an original sidecar session in which a tool call's
// output is output, and a user message holds part, when part is not nil.
func blobSession(t *testing.T, id, output string, part openresponses.Content) *agentsession.Session {
	t.Helper()
	s := agentsession.New(agentsession.Header{ID: id, CreatedAt: t0, Media: agentsession.MediaSidecar})
	add := func(i int, e *agentsession.ItemEntry) {
		e.Timestamp = t0.Add(time.Duration(i+1) * time.Second)
		if _, err := s.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	add(0, agentsession.NewItemEntry(openresponses.UserText("run the build")))
	add(1, agentsession.NewItemEntry(&openresponses.FunctionCall{CallID: "call-1", Name: "bash", Arguments: `{"command":"make"}`}))
	add(2, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-1", output)))
	if part != nil {
		add(3, agentsession.NewItemEntry(openresponses.UserMessage(&openresponses.InputText{Text: "and this file"}, part)))
	}
	return s
}

// putBlob stores data in st with mediaType and returns its hash.
func putBlob(t *testing.T, st agentsession.Store, data, mediaType string) string {
	t.Helper()
	h, err := st.(agentsession.TypedBlobWriter).PutTypedBlob(context.Background(), []byte(data), mediaType)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// publishOne runs the store pass over private, accepting accept, and
// publishes unjudged to a new redacted-only target.
func publishOne(t *testing.T, private agentsession.Store, accept ...agentredact.FindingKind) (*Result, *agentsession.MemoryStore, *agentredact.StoreReport) {
	t.Helper()
	rep, err := agentredact.RedactStore(context.Background(), private, profile, key(t), agentredact.StoreOptions{AcceptFindings: accept})
	if err != nil {
		t.Fatal(err)
	}
	target := agentsession.NewMemoryStore(agentsession.MemoryRedactedOnly())
	res, err := Publish(context.Background(), private, target, Options{Profile: profile.Name, Report: rep, Unjudged: true})
	if err != nil {
		t.Fatal(err)
	}
	return res, target, rep
}

func holds(t *testing.T, st agentsession.BlobReader, h string) bool {
	t.Helper()
	_, err := st.Blob(context.Background(), h)
	if err != nil && !errors.Is(err, agentsession.ErrNoBlob) {
		t.Fatal(err)
	}
	return err == nil
}

// TestPublishBlobNamedInText: a tool output that names a kept blob in
// its text, as dax keeps a cut output whole and names it in the cut
// note, publishes without that blob, and the published text no longer
// names it (#23).
func TestPublishBlobNamedInText(t *testing.T) {
	ctx := context.Background()
	private := agentsession.NewMemoryStore()
	kept := putBlob(t, private, "the whole output\nexport HF_TOKEN="+fakeToken+"\n", "text/plain")
	o := blobSession(t, "orig-cut-note", "first lines\n[output cut, 120 bytes left out; whole output: sidecar:"+kept+"]", nil)
	load(t, private, o)
	res, target, _ := publishOne(t, private)
	if len(res.Published) != 1 {
		t.Fatalf("published %+v, held %+v: want the session published", res.Published, res.Held)
	}
	if holds(t, target, kept) {
		t.Error("the target holds the blob the text named: its original bytes were published")
	}
	got, err := target.Read(ctx, res.Published[0].Session)
	if err != nil {
		t.Fatal(err)
	}
	if f := file(t, got); bytes.Contains(f, []byte(kept)) || bytes.Contains(f, []byte(fakeToken)) {
		t.Errorf("the published session names the unredacted blob:\n%s", f)
	}
}

// TestPublishStructuralTextBlob: a text blob a part names by its
// sidecar URL is redacted by the profile's string redactors and
// published as a typed replacement blob; the original's is not.
func TestPublishStructuralTextBlob(t *testing.T) {
	ctx := context.Background()
	private := agentsession.NewMemoryStore()
	orig := putBlob(t, private, "notes\ntoken "+fakeToken+"\n", "text/plain")
	o := blobSession(t, "orig-text-file", "ok", &openresponses.InputFile{Filename: "notes.txt", FileData: "sidecar:" + orig})
	load(t, private, o)
	res, target, _ := publishOne(t, private)
	if len(res.Published) != 1 {
		t.Fatalf("published %+v, held %+v: want the session published", res.Published, res.Held)
	}
	if holds(t, target, orig) {
		t.Error("the target holds the original text blob")
	}
	got, err := target.Read(ctx, res.Published[0].Session)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := agentsession.SessionBlobs(got)
	if err != nil || len(refs) != 1 || refs[0] == orig {
		t.Fatalf("the published session names %v (%v), want one replacement blob", refs, err)
	}
	data, typ, err := agentsession.ReadSessionBlob(ctx, target, got.ID(), refs[0])
	if err != nil {
		t.Fatalf("the replacement blob was not published: %v", err)
	}
	if bytes.Contains(data, []byte(fakeToken)) || !bytes.Contains(data, []byte("[REDACTED huggingface_token#1]")) || typ != "text/plain" {
		t.Errorf("the published blob is %q, %q: want it redacted, typed text/plain", data, typ)
	}
}

// TestPublishUnredactableBlob: a blob a part names that the redaction
// cannot read as text is never carried, whatever findings are
// accepted: the publish refuses the session and names the blob.
func TestPublishUnredactableBlob(t *testing.T) {
	private := agentsession.NewMemoryStore()
	orig := putBlob(t, private, "\xff\xfe not text "+fakeToken, "text/plain")
	o := blobSession(t, "orig-bad-text", "ok", &openresponses.InputFile{Filename: "notes.txt", FileData: "sidecar:" + orig})
	load(t, private, o)
	res, target, _ := publishOne(t, private, "unredacted-blob", "sidecar-media", "image")
	if len(res.Published) != 0 || len(res.Held) != 1 {
		t.Fatalf("published %+v, held %+v: want the session held", res.Published, res.Held)
	}
	if !strings.Contains(res.Held[0].Reason, orig) {
		t.Errorf("held for %q, want the blob named", res.Held[0].Reason)
	}
	if holds(t, target, orig) {
		t.Error("the target holds the unredacted blob")
	}
}

// TestExportBlobs: export holds a session to the same rule: one naming
// a blob in text exports with the text no longer naming it, and one
// naming a blob the redaction could not redact is refused, naming it.
func TestExportBlobs(t *testing.T) {
	ctx := context.Background()
	private := agentsession.NewMemoryStore()
	kept := putBlob(t, private, "the whole output "+fakeToken, "text/plain")
	bad := putBlob(t, private, "\xff\xfe "+fakeToken, "text/plain")
	note := blobSession(t, "orig-export-note", "cut; whole output: sidecar:"+kept, nil)
	file := blobSession(t, "orig-export-bad", "ok", &openresponses.InputFile{Filename: "notes.txt", FileData: "sidecar:" + bad})
	load(t, private, note)
	load(t, private, file)
	accept := []agentredact.FindingKind{"unredacted-blob", "sidecar-media", "image"}
	rep, err := agentredact.RedactStore(ctx, private, profile, key(t), agentredact.StoreOptions{AcceptFindings: accept})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Profile: profile.Name, Report: rep, Unjudged: true}
	manifest := func(id string) Manifest {
		red, err := private.Read(ctx, agentredact.RedactedID(key(t), id, profile.Name))
		if err != nil {
			t.Fatal(err)
		}
		return Manifest{Format: ManifestFormat, Profile: profile.Name, Entries: []ManifestEntry{{Session: red.ID(), Head: red.Leaf()}}}
	}
	dir := filepath.Join(t.TempDir(), "note")
	if err := ExportDataset(ctx, private, manifest(note.ID()), dir, opts, profile.StringFunc()); err != nil {
		t.Fatalf("the session naming a blob in text: %v", err)
	}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte(strings.TrimPrefix(kept, "sha256:"))) {
			t.Errorf("%s names the unredacted blob", filepath.Base(path))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err = ExportDataset(ctx, private, manifest(file.ID()), filepath.Join(t.TempDir(), "bad"), opts, profile.StringFunc())
	if err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("the session naming an unredactable blob: %v, want it refused, naming the blob", err)
	}
}
