package agentredact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ChristopherDavenport/agentsession"
)

// BlobFate is what a redaction did with a blob its session names by a
// sidecar reference: see [Result.Sidecar]. A publisher carries a blob
// with the session only by its fate ([SessionReport.CarriesBlob]).
type BlobFate string

const (
	// BlobMade: an entry redactor made it, such as the placeholder
	// [Images] puts in a sidecar image's place.
	BlobMade BlobFate = "made"
	// BlobRedacted: a text blob of the original, through the profile's
	// string redactors, written as a replacement blob with the
	// original's type. Its hash is the original's only when the
	// redactors changed nothing.
	BlobRedacted BlobFate = "redacted"
	// BlobKept: the original's blob, kept whole by rule and reported:
	// an image a profile does not replace ([FindingImage], or
	// [FindingSidecarMedia] for one [Images] does not reach), or media
	// that is not text ([FindingSidecarMedia]). It may leave only as its
	// finding's kind is accepted.
	BlobKept BlobFate = "kept"
	// BlobUnredacted: a blob that may hold text the redaction could not
	// read, kept as the original's and reported as a
	// [FindingUnredactedBlob]: no blob reader was given, the store does
	// not hold it, or a text type's bytes are not UTF-8. It never
	// leaves.
	BlobUnredacted BlobFate = "unredacted"
)

// worse reports whether a is a fate a publisher trusts less than b.
func (a BlobFate) worse(b BlobFate) bool {
	rank := map[BlobFate]int{BlobMade: 0, BlobRedacted: 0, BlobKept: 1, BlobUnredacted: 2}
	return rank[a] > rank[b]
}

// mergeFate records f for hash in m, the least trusted fate winning
// when a session names one blob in two ways.
func mergeFate(m map[string]BlobFate, hash string, f BlobFate) {
	if old, ok := m[hash]; !ok || f.worse(old) {
		m[hash] = f
	}
}

// WithBlobs gives [Redact] the original's blobs: read returns the
// bytes of the blob hash and the media type the original holds it
// with, "" for none, as [agentsession.ReadSessionBlob] reads it for the
// original, and an error for one it cannot read. Without it, a blob
// that may hold text is not read, and the redaction keeps it as
// [BlobUnredacted]. [RedactStore] gives it the store's.
func WithBlobs(read func(hash string) ([]byte, string, error)) Option {
	return func(o *options) { o.blobs = read }
}

// SidecarRefs returns the hashes of the blobs s references, each once,
// in the order they first appear, its prefix included: every string of
// an entry that is wholly a sidecar URL, sidecar:sha256:<hex>, which
// is how RFC 0001 has an item name a blob beside the file and which
// agentsession's Rewriter keeps from the string redactors as a
// reference. A hash written inside a longer string, such as a tool's
// note naming where its whole output was kept, is text, not a
// reference: SidecarRefs does not return it, and a publisher never
// follows it. ([agentsession.SessionBlobs] returns both.)
func SidecarRefs(s *agentsession.Session) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, e := range s.Entries() {
		_, err := walkSidecars(e, func(x string, _, _ string) (string, error) {
			if h := strings.TrimPrefix(x, "sidecar:"); !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
			return x, nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// isSidecarURL reports whether s is wholly a sidecar reference.
func isSidecarURL(s string) bool {
	h, ok := strings.CutPrefix(s, "sidecar:")
	return ok && agentsession.ValidHash(h)
}

// walkSidecars calls f on every string of e's body that is wholly a
// sidecar URL, with its RFC 6901 pointer and the member holding it, in
// sorted member order, and returns e with each replaced by what f
// returns: e itself when nothing changed.
func walkSidecars(e agentsession.Entry, f func(url, at, member string) (string, error)) (agentsession.Entry, error) {
	data, err := agentsession.MarshalEntry(e)
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(data, []byte("sidecar:")) {
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
		return nil, fmt.Errorf("agentredact: entry %s is not an object", e.Base().ID)
	}
	changed := false
	var walkErr error
	var walk func(v any, at, member string) any
	walk = func(v any, at, member string) any {
		switch x := v.(type) {
		case string:
			if !isSidecarURL(x) || walkErr != nil {
				return x
			}
			y, err := f(x, at, member)
			if err != nil {
				walkErr = err
				return x
			}
			changed = changed || y != x
			return y
		case []any:
			for i := range x {
				x[i] = walk(x[i], at+"/"+strconv.Itoa(i), "")
			}
		case map[string]any:
			for _, k := range sortedMembers(x) {
				x[k] = walk(x[k], at+"/"+pointerToken(k), k)
			}
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
	return agentsession.UnmarshalEntry(bytes.TrimRight(buf.Bytes(), "\n"))
}

// sidecarInText matches a sidecar reference written inside text.
var sidecarInText = regexp.MustCompile(`sidecar:sha256:[0-9a-f]{64}`)

// blobsInText replaces every sidecar reference inside a string with a
// placeholder numbered by its hash, "[REDACTED blob#<n>]": text names
// no blob in a redacted session, so neither a store nor a publisher
// reads it as one, and no hash of an original's blob is published. A
// string that is wholly a sidecar URL never reaches it: it is a
// reference, which the redaction's blob step decides on.
func blobsInText(s string, ph *Placeholders) string {
	if !strings.Contains(s, "sidecar:sha256:") {
		return s
	}
	return sidecarInText.ReplaceAllStringFunc(s, func(m string) string {
		return ph.For("blob", strings.TrimPrefix(m, "sidecar:"))
	})
}

// sidecars is the redaction's blob step over n, an entry about to be
// written in place of the original's at pos: every sidecar reference
// it holds is decided, and its fate recorded in the result. made holds
// the blobs the entry redactors added for it, and takes the
// replacements written here.
//
//   - A blob an entry redactor made is [BlobMade].
//   - An image, one an image_url names or of an image type, is kept
//     ([BlobKept]); a profile without [Images] reports it as a
//     [FindingImage] when the entry is inspected, and one with Images,
//     which reaches only image_url, as [FindingSidecarMedia].
//   - Media of a known type that is not text is kept and reported as a
//     [FindingSidecarMedia].
//   - A text blob, of a text type, or of none whose bytes are UTF-8 and
//     hold no NUL, is read, given whole to the profile's string
//     redactors, as the entry's strings are, and written as a
//     replacement blob with the original's type; the reference names
//     the replacement ([BlobRedacted]). An untyped blob that is not text
//     is kept as media.
//   - A blob that may be text and cannot be read is kept and reported
//     as a [FindingUnredactedBlob] ([BlobUnredacted]).
func (r *redaction) sidecars(pos int, n agentsession.Entry, made map[string]Blob) (agentsession.Entry, error) {
	report := func(kind FindingKind, at, message string) {
		r.res.Findings = append(r.res.Findings, Finding{Kind: kind, Position: pos, At: at, Redactor: "redact", Message: message})
	}
	return walkSidecars(n, func(url, at, member string) (string, error) {
		h := strings.TrimPrefix(url, "sidecar:")
		if _, ok := made[h]; ok {
			mergeFate(r.res.Sidecar, h, BlobMade)
			return url, nil
		}
		var (
			data    []byte
			typ     string
			readErr error
		)
		if r.readBlob != nil {
			data, typ, readErr = r.readBlob(h)
		}
		if typ == "" && r.mediaType != nil {
			typ = r.mediaType(h)
		}
		if typ, _ = agentsession.BlobMediaType(typ); typ != "" {
			r.types[h] = typ
		}
		keep := func(fate BlobFate, kind FindingKind, message string) (string, error) {
			mergeFate(r.res.Sidecar, h, fate)
			if kind != "" {
				report(kind, at, message)
			}
			return url, nil
		}
		switch {
		case member == "image_url" || isImageType(typ):
			if r.images {
				return keep(BlobKept, FindingSidecarMedia, "a sidecar image Images does not replace, kept as it is: it replaces those an image_url names, and text in it is not found")
			}
			return keep(BlobKept, "", "") // inspect reports it as an image kept
		case typ != "" && !isTextType(typ):
			return keep(BlobKept, FindingSidecarMedia, "sidecar media that is not an image or text left as it is: no redactor replaces it, and text in it is not found")
		case r.readBlob == nil:
			return keep(BlobUnredacted, FindingUnredactedBlob, "a sidecar blob that may hold text kept unredacted: no blob reader was given, so it was not read")
		case readErr != nil:
			return keep(BlobUnredacted, FindingUnredactedBlob, "a sidecar blob that may hold text kept unredacted: it could not be read")
		case typ == "" && !isText(data):
			return keep(BlobKept, FindingSidecarMedia, "an untyped sidecar blob that is not text left as it is: no redactor replaces it, and text in it is not found")
		case !utf8.Valid(data):
			return keep(BlobUnredacted, FindingUnredactedBlob, "a sidecar blob of a text type that is not UTF-8 kept unredacted: the string redactors read UTF-8 text")
		}
		out := []byte(r.f(string(data)))
		nh := agentsession.HashBytes(out)
		made[nh] = Blob{Data: out, MediaType: typ}
		if typ != "" {
			r.types[nh] = typ
		}
		mergeFate(r.res.Sidecar, nh, BlobRedacted)
		return "sidecar:" + nh, nil
	})
}

// typeOf is the media type the redaction knows for the blob hash: the
// one its blob step read, else the one [WithMediaTypes] gives.
func (r *redaction) typeOf(hash string) string {
	if t := r.types[hash]; t != "" {
		return t
	}
	if r.mediaType != nil {
		return r.mediaType(hash)
	}
	return ""
}

// isImageType reports whether t, a media type, is an image's.
func isImageType(t string) bool {
	return strings.HasPrefix(strings.ToLower(t), "image/")
}

// isTextType reports whether t, a media type, is text the string
// redactors can read: text/*, JSON, XML, YAML, NDJSON, TOML,
// JavaScript and shell, and any +json or +xml type.
func isTextType(t string) bool {
	base, _, _ := strings.Cut(strings.ToLower(t), ";")
	base = strings.TrimSpace(base)
	if strings.HasPrefix(base, "text/") || strings.HasSuffix(base, "+json") || strings.HasSuffix(base, "+xml") {
		return true
	}
	switch base {
	case "application/json", "application/xml", "application/x-ndjson", "application/ndjson",
		"application/yaml", "application/x-yaml", "application/toml", "application/javascript",
		"application/x-sh", "application/x-shellscript":
		return true
	}
	return false
}

// isText reports whether data, a blob with no type, reads as text:
// UTF-8 holding no NUL.
func isText(data []byte) bool {
	return utf8.Valid(data) && bytes.IndexByte(data, 0) < 0
}
