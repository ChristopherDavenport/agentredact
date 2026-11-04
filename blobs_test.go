package agentredact

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// blobStore is a reader over synthetic blobs, by hash.
type blobStore map[string]Blob

func (b blobStore) put(data, mediaType string) string {
	h := agentsession.HashBytes([]byte(data))
	b[h] = Blob{Data: []byte(data), MediaType: mediaType}
	return h
}

func (b blobStore) read(h string) ([]byte, string, error) {
	x, ok := b[h]
	if !ok {
		return nil, "", agentsession.ErrNoBlob
	}
	return x.Data, x.MediaType, nil
}

// callOutput is a sidecar session holding one tool call whose output
// is output.
func callOutput(t *testing.T, id, output string) *agentsession.Session {
	t.Helper()
	c := &clock{}
	s := agentsession.New(agentsession.Header{ID: id, CreatedAt: t0, Media: agentsession.MediaSidecar})
	appendAt(t, s, c, user("run it"))
	appendAt(t, s, c, agentsession.NewItemEntry(&openresponses.FunctionCall{CallID: "call-1", Name: "bash", Arguments: "{}"}))
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-1", output)))
	return s
}

// TestRedactSidecarBlobs: each blob a session references is decided by
// its type and bytes (#23): a text blob, typed or not, is redacted by
// the profile's string redactors into a replacement blob of the same
// type; untyped bytes that are not text are kept as media; text that
// cannot be read is kept and marked unredacted. A rerun writes the same
// bytes and a resume returns no blob.
func TestRedactSidecarBlobs(t *testing.T) {
	secretText := "log line\npassword " + fakePassword + "\n"
	cases := []struct {
		name     string
		data     string
		typ      string
		reader   bool
		fate     BlobFate
		finding  FindingKind
		redacted bool
		wantType string
	}{
		{name: "text", data: secretText, typ: "text/plain;charset=utf-8", reader: true, fate: BlobRedacted, redacted: true},
		{name: "json", data: `{"pw":"` + fakePassword + `"}`, typ: "application/json", reader: true, fate: BlobRedacted, redacted: true},
		{name: "untyped text", data: secretText, reader: true, fate: BlobRedacted, redacted: true},
		{name: "untyped binary", data: "\x00\x01" + fakePassword, reader: true, fate: BlobUnredacted, finding: FindingUnredactedBlob},
		{name: "pdf", data: "%PDF-1.7\n%\xe2\xe3\xcf\xd3 " + fakePassword, typ: "application/pdf", reader: true, fate: BlobKeptMedia, finding: FindingSidecarMedia},
		{name: "png", data: "\x89PNG\r\n\x1a\n" + fakePassword, typ: "image/png", reader: true, fate: BlobKeptImage, finding: FindingImage},
		{name: "png as text/plain", data: "\x89PNG\r\n\x1a\n" + fakePassword, typ: "text/plain", reader: true, fate: BlobKeptImage, finding: FindingImage},
		{name: "pdf that is text", data: "%PDF-1.7 " + fakePassword, typ: "application/pdf", reader: true, fate: BlobRedacted, redacted: true, wantType: "text/plain;charset=utf-8"},
		{name: "script", data: "export PW=" + fakePassword, typ: "application/x-sh-fake", reader: true, fate: BlobRedacted, redacted: true},
		{name: "text not utf-8", data: "\xff\xfe" + fakePassword, typ: "text/plain", reader: true, fate: BlobUnredacted, finding: FindingUnredactedBlob},
		{name: "no reader", data: secretText, typ: "text/plain", fate: BlobUnredacted, finding: FindingUnredactedBlob},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blobs := blobStore{}
			h := agentsession.HashText(tc.name + "-not-held")
			if tc.data != "" {
				h = blobs.put(tc.data, tc.typ)
			}
			s := callOutput(t, "orig-blob-"+strings.ReplaceAll(tc.name, " ", "-"), "sidecar:"+h)
			var opts []Option
			if tc.reader {
				opts = append(opts, WithBlobs(blobs.read))
			}
			res, err := Redact(testProfile(), testKey, s, nil, opts...)
			if err != nil {
				t.Fatal(err)
			}
			refs, err := SidecarRefs(res.Session)
			if err != nil || len(refs) != 1 {
				t.Fatalf("references %v, %v", refs, err)
			}
			got := refs[0]
			if res.Sidecar[got] != tc.fate || len(res.Sidecar) != 1 {
				t.Errorf("fates %v, want %s", res.Sidecar, tc.fate)
			}
			var kinds []FindingKind
			for _, f := range res.Findings {
				kinds = append(kinds, f.Kind)
				if strings.Contains(f.Message, "sha256:") {
					t.Errorf("a finding names a hash: %+v", f)
				}
			}
			if want := []FindingKind{tc.finding}; tc.finding != "" && !slices.Equal(kinds, want) || tc.finding == "" && len(kinds) != 0 {
				t.Errorf("findings %v, want %v", kinds, tc.finding)
			}
			if !tc.redacted {
				if got != h || len(res.Blobs) != 0 {
					t.Errorf("the reference names %s and the blobs are %v: want the original's kept, none made", got, res.Blobs)
				}
				return
			}
			b, ok := res.Blobs[got]
			if got == h || !ok || bytes.Contains(b.Data, []byte(fakePassword)) || !bytes.Contains(b.Data, []byte("[REDACTED#1]")) {
				t.Fatalf("the replacement %s: %q, want the text redacted", got, b.Data)
			}
			if want := cmpOr(tc.wantType, tc.typ); b.MediaType != want {
				t.Errorf("the replacement's type %q, want %q", b.MediaType, want)
			}
			if res.Counts["secret"] != 1 {
				t.Errorf("counts %v, want the blob's secret counted", res.Counts)
			}
			again, err := Redact(testProfile(), testKey, s, nil, opts...)
			if err != nil || !bytes.Equal(fileOf(t, again.Session), fileOf(t, res.Session)) {
				t.Errorf("a rerun wrote other bytes: %v", err)
			}
			up, err := Redact(testProfile(), testKey, s, res.Session, opts...)
			if err != nil || len(up.Blobs) != 0 || len(up.Entries) != 0 || up.Sidecar[got] != BlobRedacted {
				t.Errorf("an up-to-date resume: %v, blobs %v, fates %v", err, up.Blobs, up.Sidecar)
			}
		})
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// TestRedactBlobUnread: a blob the reader cannot read, one not held
// included, stops the redaction, which writes nothing for it, rather
// than writing a reference a later run would write otherwise.
func TestRedactBlobUnread(t *testing.T) {
	s := callOutput(t, "orig-blob-unread", "sidecar:"+agentsession.HashText("not-held"))
	_, err := Redact(testProfile(), testKey, s, nil, WithBlobs(blobStore{}.read))
	if !errors.Is(err, ErrBlobUnread) || !errors.Is(err, agentsession.ErrNoBlob) {
		t.Errorf("Redact: %v, want ErrBlobUnread wrapping ErrNoBlob", err)
	}
}

// TestRedactBlobInText: a sidecar reference written inside text, as a
// tool's note naming where its whole output was kept, is not followed:
// it is replaced by a placeholder numbered by its hash, no blob is
// read for it and SidecarRefs does not return it.
func TestRedactBlobInText(t *testing.T) {
	blobs := blobStore{}
	h := blobs.put("whole output "+fakePassword, "text/plain")
	other := agentsession.HashText("another-blob")
	s := callOutput(t, "orig-blob-in-text", "cut; whole output: sidecar:"+h+", again sidecar:"+h+", and sidecar:"+other)
	if refs, err := SidecarRefs(s); err != nil || len(refs) != 0 {
		t.Errorf("SidecarRefs over text: %v, %v", refs, err)
	}
	read := 0
	res, err := Redact(testProfile(), testKey, s, nil, WithBlobs(func(hash string) ([]byte, string, error) {
		read++
		return blobs.read(hash)
	}))
	if err != nil {
		t.Fatal(err)
	}
	file := fileOf(t, res.Session)
	if bytes.Contains(file, []byte(strings.TrimPrefix(h, "sha256:"))) || bytes.Contains(file, []byte(strings.TrimPrefix(other, "sha256:"))) {
		t.Errorf("the redaction names a blob in text:\n%s", file)
	}
	if !bytes.Contains(file, []byte("whole output: [REDACTED blob#1], again [REDACTED blob#1], and [REDACTED blob#2]")) {
		t.Errorf("the placeholders:\n%s", file)
	}
	if read != 0 || res.Sidecar != nil || res.Blobs != nil || len(res.Findings) != 0 {
		t.Errorf("read %d blobs, fates %v, blobs %v, findings %v: want nothing followed", read, res.Sidecar, res.Blobs, res.Findings)
	}
	if res.Counts["blob"] != 3 {
		t.Errorf("counts %v", res.Counts)
	}
}

// TestRedactStoreSidecarFates: the store pass reads blobs from the
// store, writes a text blob's replacement with its type, reports every
// reference's fate, a fork's prefix included, and leaves the fates out
// of the public report.
func TestRedactStoreSidecarFates(t *testing.T) {
	ctx := context.Background()
	c := &clock{}
	st := agentsession.NewMemoryStore()
	h, err := st.PutTypedBlob(ctx, []byte("notes "+fakePassword), "text/markdown")
	if err != nil {
		t.Fatal(err)
	}
	s := agentsession.New(agentsession.Header{ID: "orig-fates", CreatedAt: t0, Media: agentsession.MediaSidecar})
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.UserMessage(
		&openresponses.InputText{Text: "read this"},
		&openresponses.InputFile{Filename: "notes.md", FileData: "sidecar:" + h})))
	base := turn(t, s, c, "resp-1", "read")
	f := fork(t, s, base, "orig-fates-fork")
	appendAt(t, f, c, user("on the fork"))
	load(t, st, s, f)
	rep := redactStore(t, st, testProfile(), StoreOptions{})
	got := bySession(rep)
	red := read(t, st, redIDOf(s.ID(), testProfile().Name))
	refs, err := SidecarRefs(red)
	if err != nil || len(refs) != 1 || refs[0] == h {
		t.Fatalf("references %v, %v: want one replacement", refs, err)
	}
	nh := refs[0]
	data, typ, err := agentsession.ReadSessionBlob(ctx, st, red.ID(), nh)
	if err != nil || bytes.Contains(data, []byte(fakePassword)) || typ != "text/markdown" {
		t.Errorf("the replacement in the store: %q, %q, %v", data, typ, err)
	}
	for _, id := range []string{s.ID(), f.ID()} {
		r := got[id]
		if r.Sidecar[nh] != BlobRedacted || !r.CarriesBlob(nh) || r.CarriesBlob(h) {
			t.Errorf("%s: fates %v, want the replacement carried and the original not", id, r.Sidecar)
		}
	}
	if fr := got[f.ID()]; !fr.Fork {
		t.Error("the fork was not redacted as a fork: its prefix's fates prove nothing")
	}
	for _, r := range rep.Public(testKey).Sessions {
		if r.Sidecar != nil {
			t.Errorf("the public report holds fates %v", r.Sidecar)
		}
	}
}

// TestCarriesBlob: a kept blob leaves only with the redaction
// publishable; an unredacted one, or one the report does not name,
// never.
func TestCarriesBlob(t *testing.T) {
	r := SessionReport{
		Sidecar:  map[string]BlobFate{"sha256:k": BlobKeptMedia, "sha256:u": BlobUnredacted, "sha256:m": BlobMade},
		Findings: []Finding{{Kind: FindingSidecarMedia}, {Kind: FindingUnredactedBlob}},
		accept:   map[FindingKind]bool{},
	}
	if !r.CarriesBlob("sha256:m") || r.CarriesBlob("sha256:k") || r.CarriesBlob("sha256:u") || r.CarriesBlob("sha256:x") {
		t.Error("not accepted")
	}
	r.accept[FindingSidecarMedia], r.accept[FindingUnredactedBlob] = true, true
	if !r.CarriesBlob("sha256:k") || r.CarriesBlob("sha256:u") || r.CarriesBlob("sha256:x") {
		t.Error("accepted")
	}
}

// TestRedactBlobLimits: a profile's caps hold a blob over them, of
// text or media, as too large and never carried; each blob is read
// once, however many references name it.
func TestRedactBlobLimits(t *testing.T) {
	blobs := blobStore{}
	text := blobs.put("a long log "+fakePassword, "text/plain")
	pdf := blobs.put("%PDF-1.7\n%\xe2\xe3\xcf\xd3 a long document", "application/pdf")
	c := &clock{}
	s := agentsession.New(agentsession.Header{ID: "orig-blob-limits", CreatedAt: t0, Media: agentsession.MediaSidecar})
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.UserMessage(
		&openresponses.InputFile{Filename: "a.log", FileData: "sidecar:" + text},
		&openresponses.InputFile{Filename: "b.log", FileData: "sidecar:" + text},
		&openresponses.InputFile{Filename: "c.pdf", FileData: "sidecar:" + pdf})))
	reads := 0
	read := func(h string) ([]byte, string, error) { reads++; return blobs.read(h) }
	p := testProfile()
	p.BlobLimits = BlobLimits{Text: 8, Media: 16}
	res, err := Redact(p, testKey, s, nil, WithBlobs(read))
	if err != nil {
		t.Fatal(err)
	}
	if reads != 2 {
		t.Errorf("read %d times, want each blob once", reads)
	}
	if res.Sidecar[text] != BlobUnredacted || res.Sidecar[pdf] != BlobUnredacted || len(res.Blobs) != 0 {
		t.Errorf("fates %v, blobs %v: want both held as too large", res.Sidecar, res.Blobs)
	}
	n := 0
	for _, f := range res.Findings {
		if f.Kind == FindingBlobTooLarge {
			n++
		}
	}
	if n != 3 {
		t.Errorf("findings %+v, want one too-large per reference", res.Findings)
	}
	p.BlobLimits = BlobLimits{Text: -1}
	if err := p.Validate(); err == nil {
		t.Error("a negative limit validates")
	}
}
