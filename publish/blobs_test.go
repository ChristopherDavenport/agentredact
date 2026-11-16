package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/agentsession/atif"
	"github.com/ChristopherDavenport/agentsession/export"
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

// TestExportImageBlobAsFile: a session holding an image exports with
// the image as a file of its own beside the ATIF document, as the
// redaction re-encoded it: the document points at it, no base64 and no
// sidecar reference is left in the document, and nothing of the
// original blob is written.
func TestExportImageBlobAsFile(t *testing.T) {
	ctx := context.Background()
	private := agentsession.NewMemoryStore()
	orig := putBlob(t, private, pngWithText(t), "image/png")
	s := blobSession(t, "orig-export-image", "ok", &openresponses.InputImage{ImageURL: "sidecar:" + orig})
	load(t, private, s)
	rep, err := agentredact.RedactStore(ctx, private, profile, key(t), agentredact.StoreOptions{AcceptFindings: everyKind})
	if err != nil {
		t.Fatal(err)
	}
	red, err := private.Read(ctx, agentredact.RedactedID(key(t), s.ID(), profile.Name))
	if err != nil {
		t.Fatal(err)
	}
	refs, err := agentredact.SidecarRefs(red)
	if err != nil || len(refs) != 1 || refs[0] == orig {
		t.Fatalf("the redacted session names %v (%v), want one replacement blob", refs, err)
	}
	redacted, err := private.Blob(ctx, refs[0])
	if err != nil {
		t.Fatal(err)
	}
	original, err := private.Blob(ctx, orig)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{Format: ManifestFormat, Profile: profile.Name, Entries: []ManifestEntry{{Session: red.ID(), Head: red.Leaf()}}}
	dir := filepath.Join(t.TempDir(), "dataset")
	if err := ExportDataset(ctx, private, m, dir, Options{Profile: profile.Name, Report: rep, Unjudged: true}, profile.StringFunc()); err != nil {
		t.Fatalf("export: %v", err)
	}
	sdir := filepath.Join(dir, red.ID())
	doc, err := os.ReadFile(filepath.Join(sdir, "atif.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(doc, []byte(";base64,")) {
		t.Error("the ATIF document holds base64")
	}
	refHex := strings.TrimPrefix(refs[0], "sha256:")
	if bytes.Contains(doc, []byte("sidecar:")) {
		t.Error("the ATIF document names a sidecar reference, which nothing in the dataset resolves")
	}
	images, err := filepath.Glob(filepath.Join(sdir, "images", refHex+".*"))
	if err != nil || len(images) != 1 {
		t.Fatalf("the image files: %v, %v; want the redacted image", images, err)
	}
	if b, err := os.ReadFile(images[0]); err != nil || !bytes.Equal(b, redacted) {
		t.Errorf("the image file %s: %v; want the redacted bytes", images[0], err)
	}
	if !bytes.Contains(doc, []byte("images/"+filepath.Base(images[0]))) {
		t.Errorf("the document does not point at %s", filepath.Base(images[0]))
	}
	origHex := strings.TrimPrefix(orig, "sha256:")
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(path, origHex) || bytes.Equal(data, original) || bytes.Contains(data, []byte(fakeToken)) {
			t.Errorf("%s holds the original blob or its token", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestExportWithoutBlobsUnchanged: a session naming no blob exports as
// before: atif.json, its main trajectory's document with no passthrough
// and the profile's rules applied again, and trace.jsonl, nothing else.
func TestExportWithoutBlobsUnchanged(t *testing.T) {
	ctx := context.Background()
	private := agentsession.NewMemoryStore()
	s := blobSession(t, "orig-export-plain", "token "+fakeToken, nil)
	load(t, private, s)
	rep, err := agentredact.RedactStore(ctx, private, profile, key(t), agentredact.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	red, err := private.Read(ctx, agentredact.RedactedID(key(t), s.ID(), profile.Name))
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{Format: ManifestFormat, Profile: profile.Name, Entries: []ManifestEntry{{Session: red.ID(), Head: red.Leaf()}}}
	dir := filepath.Join(t.TempDir(), "dataset")
	if err := ExportDataset(ctx, private, m, dir, Options{Profile: profile.Name, Report: rep, Unjudged: true}, profile.StringFunc()); err != nil {
		t.Fatalf("export: %v", err)
	}
	sdir := filepath.Join(dir, red.ID())
	names, err := os.ReadDir(sdir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range names {
		got = append(got, n.Name())
	}
	if strings.Join(got, " ") != "atif.json trace.jsonl" {
		t.Errorf("the session's directory holds %v, want atif.json and trace.jsonl", got)
	}
	var want *atif.Trajectory
	for tr, err := range export.Trajectories(red) {
		if err != nil {
			t.Fatal(err)
		}
		if tr.Main {
			if want, err = export.ToATIF(tr, export.Options{Redactors: []export.Redactor{export.NoPassthrough()}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	rules := profile.StringFunc()
	if err := export.RewriteStrings(want, func(s string) string { return rules(s, nil) }); err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if doc, err := os.ReadFile(filepath.Join(sdir, "atif.json")); err != nil || !bytes.Equal(doc, append(wantJSON, '\n')) {
		t.Errorf("atif.json is not the document as exported before (%v):\n%s", err, doc)
	}
}

// plainPNG is a real 2x2 PNG holding nothing but its pixels.
func plainPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 1, color.RGBA{B: 200, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// inlineSession is an original inline session whose user message holds
// parts.
func inlineSession(t *testing.T, id string, parts ...openresponses.Content) *agentsession.Session {
	t.Helper()
	s := agentsession.New(agentsession.Header{ID: id, CreatedAt: t0})
	e := agentsession.NewItemEntry(openresponses.UserMessage(append([]openresponses.Content{&openresponses.InputText{Text: "look"}}, parts...)...))
	e.Timestamp = t0.Add(time.Second)
	if _, err := s.Append(e); err != nil {
		t.Fatal(err)
	}
	return s
}

// exportOne runs the store pass over private, accepting every finding,
// and exports the redacted sessions of origs, in order, to dir under
// rules.
func exportOne(t *testing.T, private *agentsession.MemoryStore, from agentsession.Store, dir string, rules agentredact.StringRedactor, origs ...*agentsession.Session) ([]*agentsession.Session, error) {
	t.Helper()
	ctx := context.Background()
	rep, err := agentredact.RedactStore(ctx, private, profile, key(t), agentredact.StoreOptions{AcceptFindings: everyKind})
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{Format: ManifestFormat, Profile: profile.Name}
	var reds []*agentsession.Session
	for _, o := range origs {
		red, err := private.Read(ctx, agentredact.RedactedID(key(t), o.ID(), profile.Name))
		if err != nil {
			t.Fatal(err)
		}
		reds = append(reds, red)
		m.Entries = append(m.Entries, ManifestEntry{Session: red.ID(), Head: red.Leaf()})
	}
	return reds, ExportDataset(ctx, from, m, dir, Options{Profile: profile.Name, Report: rep, Unjudged: true}, rules)
}

// TestExportLastPassReadsDataURLText: the export's last pass, run with
// rules the redaction did not have, still reaches what a data URL holds
// as text: a media part's media-type parameter and a data URL that is
// not base64. Only a base64 payload is left to the blob decisions.
func TestExportLastPassReadsDataURLText(t *testing.T) {
	const late = "LATE-RULE-TOKEN"
	private := agentsession.NewMemoryStore()
	payload := base64.StdEncoding.EncodeToString(plainPNG(t))
	s := inlineSession(t, "orig-export-meta",
		&openresponses.InputImage{ImageURL: "data:image/png;name=" + late + ";base64," + payload},
		&openresponses.InputImage{ImageURL: "data:image/svg+xml,<svg><text>" + late + "</text></svg>"})
	load(t, private, s)
	dir := filepath.Join(t.TempDir(), "dataset")
	rules := agentredact.Chain(agentredact.DefaultPatterns(), agentredact.Secrets(late))
	if _, err := exportOne(t, private, private, dir, rules, s); err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte(late)) {
			t.Errorf("%s holds the token the last pass redacts", path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestExportInlineMediaAsFile: media an inline session holds as a part's
// base64 data URL is written as a file beside the document, as a
// sidecar session's blob is, and the part names it.
func TestExportInlineMediaAsFile(t *testing.T) {
	private := agentsession.NewMemoryStore()
	img := plainPNG(t)
	s := inlineSession(t, "orig-export-inline", &openresponses.InputImage{ImageURL: "data:image/png;base64," + base64.StdEncoding.EncodeToString(img)})
	load(t, private, s)
	dir := filepath.Join(t.TempDir(), "dataset")
	reds, err := exportOne(t, private, private, dir, profile.StringFunc(), s)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	sdir := filepath.Join(dir, reds[0].ID())
	doc, err := os.ReadFile(filepath.Join(sdir, "atif.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(doc, []byte(";base64,")) {
		t.Error("the ATIF document holds base64")
	}
	sum := sha256.Sum256(img)
	name := "images/" + hex.EncodeToString(sum[:]) + ".png"
	if b, err := os.ReadFile(filepath.Join(sdir, name)); err != nil || !bytes.Equal(b, img) {
		t.Errorf("%s: %v; want the image's bytes", name, err)
	}
	if !bytes.Contains(doc, []byte(`"`+name+`"`)) {
		t.Errorf("the document does not name %s", name)
	}
}

// noBlobs is a store that reads no blobs.
type noBlobs struct{ agentsession.Store }

// TestExportFailsWhole: an export that fails at a later session (here a
// sidecar session's image, from a store that reads no blobs) writes
// nothing: no dataset directory, and nothing left beside it.
func TestExportFailsWhole(t *testing.T) {
	private := agentsession.NewMemoryStore()
	plain := blobSession(t, "orig-export-first", "ok", nil)
	h := putBlob(t, private, string(plainPNG(t)), "image/png")
	withImage := blobSession(t, "orig-export-second", "ok", &openresponses.InputImage{ImageURL: "sidecar:" + h})
	load(t, private, plain)
	load(t, private, withImage)
	parent := t.TempDir()
	dir := filepath.Join(parent, "dataset")
	_, err := exportOne(t, private, noBlobs{private}, dir, profile.StringFunc(), plain, withImage)
	if err == nil {
		t.Fatal("the export from a store reading no blobs succeeded")
	}
	if left, _ := os.ReadDir(parent); len(left) != 0 {
		t.Errorf("the failed export left %v", left)
	}
}
