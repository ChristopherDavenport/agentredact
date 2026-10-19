package agentredact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ChristopherDavenport/agentsession"
)

// DefaultImagePlaceholder is a one-pixel transparent PNG as a data URL,
// the placeholder [Images] is usually given.
const DefaultImagePlaceholder = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="

// Images replaces every image an entry holds with placeholder, a base64
// data URL of an image, such as [DefaultImagePlaceholder], keeping each
// in its form, as RFC 0001 requires of a redaction: an inline image
// stays inline and a sidecar image stays sidecar.
//
// An inline image is a string that is wholly a data URL of an image
// media type (data:image/..., the scheme matched without regard to
// case), wherever the entry holds it: an input_image part's image_url
// in a message, a function call's output given as content parts, a
// compaction's summary or pinned items, a queued item, or a member the
// format does not define. It becomes placeholder itself.
//
// A sidecar image is a sidecar: URL held as an image_url member, as an
// input_image part or a screenshot holds one. Its replacement blob is
// the placeholder's decoded bytes, added with [EntryContext.AddBlob] so
// that [Redact] returns it in [Result.Blobs], and the URL becomes
// sidecar: and that blob's hash, sha256:<hex>, so the item names the
// replacement as the format has a replaced blob named. The caller
// stores the blob beside the redacted session; the original's blob is
// not carried. A sidecar URL anywhere else, such as an input_file's
// file_data or file_url, is media that is not an image: it is kept as
// it is and reported as a [Finding], so the session is not mistaken for
// one with its media redacted.
//
// The item around an image is kept as it was, detail and file_id
// included, so it stays valid. The placeholder is the same for every
// image, so the output depends on nothing but the input.
//
// Only whole strings are replaced. An image data URL inside a longer
// string, such as a tool's text output or markdown, is kept, after the
// string redactors, and [Redact] reports it; so does inline media that
// is not an image, such as an input_file's PDF.
//
// Text inside an image's bytes is not read: an image is replaced or
// kept whole, and no OCR is done. A placeholder that is not a base64
// data URL of an image is an error at the first image it would replace.
func Images(placeholder string) EntryRedactor { return images{placeholder: placeholder} }

type images struct{ placeholder string }

func (images) Name() string { return "images" }

func (r images) RedactEntry(c *EntryContext, e agentsession.Entry) (agentsession.Entry, error) {
	data, err := agentsession.MarshalEntry(e)
	if err != nil {
		return nil, err
	}
	if lower := bytes.ToLower(data); !bytes.Contains(lower, []byte("data:")) && !bytes.Contains(lower, []byte("sidecar:")) {
		return e, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	root, ok := tree.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("agentredact: images: entry %s is not an object", e.Base().ID)
	}
	changed := false
	var walkErr error
	fail := func(err error) {
		if walkErr == nil {
			walkErr = err
		}
	}
	var walk func(v any, at, member string) any
	walk = func(v any, at, member string) any {
		switch x := v.(type) {
		case string:
			switch {
			case isImageDataURL(x):
				if err := checkPlaceholder(r.placeholder); err != nil {
					fail(err)
					return x
				}
				if x != r.placeholder {
					changed = true
				}
				return r.placeholder
			case strings.HasPrefix(x, "sidecar:") && member == "image_url":
				blob, err := placeholderBytes(r.placeholder)
				if err != nil {
					fail(err)
					return x
				}
				url := "sidecar:" + c.AddBlob(blob)
				if x != url {
					changed = true
				}
				return url
			case strings.HasPrefix(x, "sidecar:"):
				c.Report(at, "sidecar media that is not an image left as it is: no redactor replaces it, and text in it is not found")
			}
			return x
		case []any:
			for i := range x {
				x[i] = walk(x[i], at+"/"+strconv.Itoa(i), "")
			}
			return x
		case map[string]any:
			for _, k := range sortedMembers(x) {
				x[k] = walk(x[k], at+"/"+pointerToken(k), k)
			}
			return x
		}
		return v
	}
	for _, k := range sortedMembers(root) {
		if envelopeMember[k] {
			continue
		}
		root[k] = walk(root[k], "/"+pointerToken(k), k)
	}
	if walkErr != nil {
		return nil, walkErr
	}
	if !changed {
		return e, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	out, err := agentsession.UnmarshalEntry(bytes.TrimRight(buf.Bytes(), "\n"))
	if err != nil {
		return nil, fmt.Errorf("agentredact: images: entry %s: %w", e.Base().ID, err)
	}
	return out, nil
}

// envelopeMember are the members of an entry no image is in.
var envelopeMember = map[string]bool{"type": true, "id": true, "parent": true, "parents": true, "ts": true, "redacted": true}

func sortedMembers(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// isImageDataURL reports whether s is a data URL whose media type is
// an image's, matched without regard to case as RFC 2397 has it.
func isImageDataURL(s string) bool {
	return len(s) >= len("data:image/") && strings.EqualFold(s[:len("data:image/")], "data:image/")
}

// checkPlaceholder reports whether p is a base64 data URL of an image.
func checkPlaceholder(p string) error {
	_, err := placeholderBytes(p)
	return err
}

// placeholderBytes returns the bytes of p, a base64 data URL of an
// image, which a sidecar image is replaced with.
func placeholderBytes(p string) ([]byte, error) {
	if !isImageDataURL(p) {
		return nil, fmt.Errorf("agentredact: images: the placeholder is not a data URL of an image")
	}
	meta, payload, ok := strings.Cut(p[len("data:"):], ",")
	if !ok || !strings.HasSuffix(strings.ToLower(meta), ";base64") {
		return nil, fmt.Errorf("agentredact: images: the placeholder is not a base64 data URL")
	}
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("agentredact: images: the placeholder's payload: %w", err)
	}
	return data, nil
}

// pointerToken escapes a member name for an RFC 6901 pointer.
func pointerToken(k string) string {
	return strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
}
