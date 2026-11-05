package publish

import (
	"bytes"
	"context"
	"testing"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// TestPublishTextByContent: a blob is text by its bytes, not its
// declared type: text under a type the redaction does not list, an SVG,
// text an image_url names, is redacted, whatever kinds are accepted;
// bytes that are neither text nor media it knows never leave (review,
// finding 2).
func TestPublishTextByContent(t *testing.T) {
	text := "notes\ntoken " + fakeToken + "\n"
	cases := []struct {
		name, data, typ string
		part            func(url string) openresponses.Content
		redacted        bool
	}{
		{name: "x-python", data: text, typ: "application/x-python", redacted: true},
		{name: "octet-stream with charset", data: text, typ: "application/octet-stream;charset=utf-8", redacted: true},
		{name: "svg", data: `<svg xmlns="http://www.w3.org/2000/svg"><text>` + fakeToken + `</text></svg>`, typ: "image/svg+xml", redacted: true},
		{name: "text behind image_url", data: text, typ: "image/png", part: func(url string) openresponses.Content {
			return &openresponses.InputImage{ImageURL: url}
		}, redacted: true},
		{name: "text with a NUL", data: text + "\x00", typ: ""},
		{name: "utf-16", data: "\xff\xfet\x00o\x00k\x00", typ: "text/plain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			private := agentsession.NewMemoryStore()
			h := putBlob(t, private, tc.data, tc.typ)
			part := openresponses.Content(&openresponses.InputFile{Filename: "notes", FileData: "sidecar:" + h})
			if tc.part != nil {
				part = tc.part("sidecar:" + h)
			}
			load(t, private, blobSession(t, "orig-by-content", "ok", part))
			res, target, _ := publishOne(t, private, everyKind...)
			if holds(t, target, h) {
				t.Fatal("the target holds the original blob")
			}
			if !tc.redacted {
				if len(res.Published) != 0 {
					t.Errorf("published %+v: want it held", res.Published)
				}
				return
			}
			if len(res.Published) != 1 {
				t.Fatalf("published %+v, held %+v", res.Published, res.Held)
			}
			got, err := target.Read(ctx, res.Published[0].Session)
			if err != nil {
				t.Fatal(err)
			}
			refs, _ := agentredact.SidecarRefs(got)
			if len(refs) != 1 {
				t.Fatalf("references %v", refs)
			}
			data, err := target.Blob(ctx, refs[0])
			if err != nil || bytes.Contains(data, []byte(fakeToken)) {
				t.Errorf("the published blob %q, %v: want it redacted", data, err)
			}
		})
	}
}
