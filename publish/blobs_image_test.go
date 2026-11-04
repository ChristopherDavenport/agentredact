package publish

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// Every value here is synthetic.

// pngWithText is a real 2x2 PNG carrying the fake token twice outside
// its pixels: in a tEXt chunk before IEND, and after the image ends.
func pngWithText(t *testing.T) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(1, 1, color.RGBA{R: 200, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	data := []byte("Comment\x00token " + fakeToken)
	var chunk bytes.Buffer
	_ = binary.Write(&chunk, binary.BigEndian, uint32(len(data)))
	chunk.WriteString("tEXt")
	chunk.Write(data)
	_ = binary.Write(&chunk, binary.BigEndian, crc32.ChecksumIEEE(append([]byte("tEXt"), data...)))
	iend := len(b) - 12
	out := append(append(append([]byte{}, b[:iend]...), chunk.Bytes()...), b[iend:]...)
	return string(out) + "trailing " + fakeToken
}

// TestPublishImageReencoded: a kept image leaves only as its pixels,
// re-encoded: no metadata chunk and nothing after the image's end; an
// image the redaction cannot decode never leaves (round 2 review, R2-1).
func TestPublishImageReencoded(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, data string
		published  bool
	}{
		{name: "png with text", data: pngWithText(t), published: true},
		{name: "png signature and text", data: "\x89PNG\r\n\x1a\npassword=" + fakeToken},
		{name: "webp", data: "RIFF\x10\x00\x00\x00WEBPVP8 " + fakeToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			private := agentsession.NewMemoryStore()
			h := putBlob(t, private, tc.data, "image/png")
			load(t, private, blobSession(t, "orig-image", "ok", &openresponses.InputFile{Filename: "shot.png", FileData: "sidecar:" + h}))
			res, target, _ := publishOne(t, private, everyKind...)
			if holds(t, target, h) {
				t.Fatal("the target holds the original image")
			}
			if !tc.published {
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
			if err != nil || bytes.Contains(data, []byte(fakeToken)) || bytes.Contains(data, []byte("tEXt")) {
				t.Fatalf("the published image %q, %v: want its pixels alone", data, err)
			}
			img, err := png.Decode(bytes.NewReader(data))
			if err != nil || img.Bounds().Dx() != 2 {
				t.Errorf("the published image does not decode as the original's pixels: %v", err)
			}
		})
	}
}
