package publish

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// TestPublishArchivesHeld: an archive or compressed stream holds text
// the redaction does not read; it never leaves, whatever is accepted
// (round 2 review, R2-2).
func TestPublishArchivesHeld(t *testing.T) {
	secret := []byte("token " + fakeToken + "\n")
	var zbuf, gbuf, tbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("notes.txt")
	_, _ = w.Write(secret)
	_ = zw.Close()
	gw := gzip.NewWriter(&gbuf)
	_, _ = gw.Write(secret)
	_ = gw.Close()
	tw := tar.NewWriter(&tbuf)
	_ = tw.WriteHeader(&tar.Header{Name: "notes.txt", Mode: 0o600, Size: int64(len(secret))})
	_, _ = tw.Write(secret)
	_ = tw.Close()
	for _, tc := range []struct{ name, data, typ string }{
		{"zip", zbuf.String(), "application/zip"},
		{"docx", zbuf.String(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		{"gzip", gbuf.String(), "application/gzip"},
		{"tar", tbuf.String(), "application/x-tar"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			private := agentsession.NewMemoryStore()
			h := putBlob(t, private, tc.data, tc.typ)
			load(t, private, blobSession(t, "orig-archive", "ok", &openresponses.InputFile{Filename: "a", FileData: "sidecar:" + h}))
			res, target, _ := publishOne(t, private, everyKind...)
			if len(res.Published) != 0 || holds(t, target, h) {
				t.Errorf("published %+v: want the archive held", res.Published)
			}
		})
	}
}
