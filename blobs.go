package agentredact

import (
	"bytes"
	"encoding/json"
	"errors"
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
	// BlobKeptImage: the original's blob, an image a profile does not
	// replace, kept whole and reported as a [FindingImage]. It leaves
	// only where that kind is accepted.
	BlobKeptImage BlobFate = "kept-image"
	// BlobKeptMedia: the original's blob, media that is not text, kept
	// whole and reported as a [FindingSidecarMedia]. It leaves only
	// where that kind is accepted.
	BlobKeptMedia BlobFate = "kept-media"
	// BlobUnredacted: a blob that may hold text the redaction could not
	// read, kept as the original's and reported as a
	// [FindingUnredactedBlob]: no blob reader was given, or a text
	// type's bytes are not UTF-8. It never leaves.
	BlobUnredacted BlobFate = "unredacted"
)

// worse reports whether a is a fate a publisher trusts less than b.
func (a BlobFate) worse(b BlobFate) bool {
	rank := map[BlobFate]int{BlobMade: 0, BlobRedacted: 0, BlobKeptImage: 1, BlobKeptMedia: 2, BlobUnredacted: 3}
	return rank[a] > rank[b]
}

// mergeFate records f for hash in m, the least trusted fate winning
// when a session names one blob in two ways.
func mergeFate(m map[string]BlobFate, hash string, f BlobFate) {
	if old, ok := m[hash]; !ok || f.worse(old) {
		m[hash] = f
	}
}

// ErrBlobUnread is returned by [Redact] for a blob the original
// references that the reader given by [WithBlobs] could not read, one
// the store does not hold yet included: nothing is written, since what
// the redaction writes for a reference must not depend on whether the
// blob could be read at that moment, and a later run, once the blob
// reads, redacts the session. The store pass reports it in the
// session's Err.
var ErrBlobUnread = errors.New("agentredact: a blob the session references could not be read")

// WithBlobs gives [Redact] the original's blobs: read returns the
// bytes of the blob hash and the media type the original holds it
// with, "" for none, as [agentsession.ReadSessionBlob] reads it for the
// original, and an error for one it cannot read, which stops the
// redaction ([ErrBlobUnread]). Without it, a blob that may hold text is
// not read, and the redaction keeps it as [BlobUnredacted]. [RedactStore] gives it the store's.
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

// sidecarInText matches a sidecar reference written inside text, in
// any case.
var sidecarInText = regexp.MustCompile(`(?i)sidecar:sha256:[0-9a-f]{64}`)

// blobsInText replaces every sidecar reference inside a string, in any
// case, with a placeholder numbered by its hash, "[REDACTED blob#<n>]":
// text names no blob in a redacted session, so neither a store nor a
// publisher reads it as one, and no hash of an original's blob is
// published. A string that is wholly a sidecar URL in an entry never
// reaches it: it is a reference, which the redaction's blob step
// decides on. A member name holding one, which the format keeps as
// written, is reported ([FindingMemberName], [FindingHeaderName]).
func blobsInText(s string, ph *Placeholders) string {
	if !strings.Contains(strings.ToLower(s), "sidecar:sha256:") {
		return s
	}
	return sidecarInText.ReplaceAllStringFunc(s, func(m string) string {
		return ph.For("blob", strings.ToLower(m[len("sidecar:"):]))
	})
}

// blobsInHeader replaces each string of h that is wholly a sidecar URL,
// which the Rewriter keeps from the string redactors as a reference,
// with the placeholder [blobsInText] writes for its hash: a header
// references no blob (RFC 0001 has items name blobs), so a URL there
// is a hash name, which would publish the original blob's hash. The
// envelope of an entry holds IDs, hashes of entries and timestamps,
// never a sidecar URL.
func blobsInHeader(h agentsession.Header, ph *Placeholders) (agentsession.Header, error) {
	data, err := json.Marshal(h)
	if err != nil || !bytes.Contains(data, []byte("sidecar:")) {
		return h, err
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return h, err
	}
	changed := false
	var walk func(v any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			if isSidecarURL(x) {
				changed = true
				return blobsInText(x, ph)
			}
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case map[string]any:
			for _, k := range sortedMembers(x) {
				x[k] = walk(x[k])
			}
		}
		return v
	}
	tree = walk(tree)
	if !changed {
		return h, nil
	}
	if data, err = json.Marshal(tree); err != nil {
		return h, err
	}
	var out agentsession.Header
	if err := json.Unmarshal(data, &out); err != nil {
		return h, err
	}
	return out, nil
}

// sidecars is the redaction's blob step over n, an entry about to be
// written in place of the original's at pos: every sidecar reference
// it holds is decided, and its fate recorded in the result. made holds
// the blobs the entry redactors added for it, and takes the
// replacements written here.
//
// A blob is decided by its bytes, never by the type it is declared
// with or the member naming it, since either can say image or media of
// what is text:
//
//   - A blob an entry redactor made is [BlobMade].
//   - Bytes that read as text, UTF-8 holding no NUL, are given whole to
//     the profile's string redactors, as the entry's strings are, and
//     written as a replacement blob ([BlobRedacted]) of the declared
//     type, or text/plain where that type names an image, audio, video
//     or a binary document: an SVG, a script under a vendor type, text
//     an image_url names.
//   - Bytes that start as an image format it knows (PNG, JPEG, GIF,
//     WebP, TIFF, ICO, AVIF, HEIC) are an image, kept whole
//     ([BlobKeptImage]) and reported as a [FindingImage]: [Images]
//     replaces those an image_url names before this step.
//   - Bytes that start as other media it knows (PDF, an archive or
//     compressed stream, audio, video) are kept whole ([BlobKeptMedia])
//     and reported as a [FindingSidecarMedia].
//   - Any other bytes, UTF-16 text among them, are neither: kept and
//     reported as a [FindingUnredactedBlob] ([BlobUnredacted]), which no
//     publisher carries. So is every blob when no reader was given.
//   - A blob the reader fails to read, one the store does not hold
//     included, is [ErrBlobUnread], and the redaction writes nothing.
//   - A blob over the profile's cap for its kind ([BlobLimits]) is kept
//     and reported as a [FindingBlobTooLarge] ([BlobUnredacted]).
//
// Each blob is read and decided once per redaction, however many
// references name it.
func (r *redaction) sidecars(pos int, n agentsession.Entry, made map[string]Blob) (agentsession.Entry, error) {
	return walkSidecars(n, func(url, at, member string) (string, error) {
		h := strings.TrimPrefix(url, "sidecar:")
		if _, ok := made[h]; ok {
			mergeFate(r.res.Sidecar, h, BlobMade)
			return url, nil
		}
		d, ok := r.decided[h]
		if !ok {
			var err error
			if d, err = r.decide(h); err != nil {
				return "", err
			}
			r.decided[h] = d
		}
		if d.kind != "" {
			r.res.Findings = append(r.res.Findings, Finding{Kind: d.kind, Position: pos, At: at, Redactor: "redact", Message: d.message})
		}
		if d.blob != nil {
			made[d.hash] = *d.blob
		}
		mergeFate(r.res.Sidecar, d.hash, d.fate)
		return "sidecar:" + d.hash, nil
	})
}

// blobDecision is what the blob step made of one blob: the hash the
// reference names after it, the fate, the replacement written when
// there is one, and the finding each reference to it reports.
type blobDecision struct {
	hash    string
	fate    BlobFate
	blob    *Blob
	kind    FindingKind
	message string
}

// decide reads the original's blob h, once per redaction, and decides
// it as [redaction.sidecars] says.
func (r *redaction) decide(h string) (blobDecision, error) {
	keep := func(fate BlobFate, kind FindingKind, message string) (blobDecision, error) {
		return blobDecision{hash: h, fate: fate, kind: kind, message: message}, nil
	}
	if r.readBlob == nil {
		return keep(BlobUnredacted, FindingUnredactedBlob, "a sidecar blob kept unredacted: no blob reader was given, so it was not read")
	}
	data, typ, err := r.readBlob(h)
	if err != nil {
		// Whether a blob can be read now is no input of the redaction:
		// nothing is written, and the next pass decides the reference
		// again.
		return blobDecision{}, fmt.Errorf("%w: %w", ErrBlobUnread, err)
	}
	if typ == "" && r.mediaType != nil {
		typ = r.mediaType(h)
	}
	typ, _ = agentsession.BlobMediaType(typ)
	limits := r.p.BlobLimits.withDefaults()
	tooLarge := func(limit int64) (blobDecision, error) {
		return keep(BlobUnredacted, FindingBlobTooLarge, fmt.Sprintf("a sidecar blob of %d bytes kept unredacted: over the profile's limit of %d for its kind", len(data), limit))
	}
	switch {
	case isText(data):
		if int64(len(data)) > limits.Text {
			return tooLarge(limits.Text)
		}
	case sniffImage(data):
		if int64(len(data)) > limits.Media {
			return tooLarge(limits.Media)
		}
		message := "a sidecar image kept whole: the profile replaces no image, and no string redactor reads the text in its pixels"
		if r.images {
			message = "a sidecar image Images does not replace, kept whole: it replaces those an image_url names, and no string redactor reads the text in its pixels"
		}
		return keep(BlobKeptImage, FindingImage, message)
	case sniffMedia(data):
		if int64(len(data)) > limits.Media {
			return tooLarge(limits.Media)
		}
		return keep(BlobKeptMedia, FindingSidecarMedia, "sidecar media that is not an image or text kept whole: no redactor replaces it, and text in it is not found")
	default:
		return keep(BlobUnredacted, FindingUnredactedBlob, "a sidecar blob kept unredacted: its bytes are neither UTF-8 text nor media the redaction knows")
	}
	out := []byte(r.f(string(data)))
	return blobDecision{hash: agentsession.HashBytes(out), fate: BlobRedacted, blob: &Blob{Data: out, MediaType: textType(typ)}}, nil
}

// BlobLimits caps the bytes of one sidecar blob the redaction takes
// ([Profile.BlobLimits]): Text for one read as text, through the string
// redactors, and Media for an image or other media kept whole. A blob
// over its cap is kept unredacted and reported as a
// [FindingBlobTooLarge], and never leaves. A zero field takes its
// default, [DefaultTextBlobLimit] or [DefaultMediaBlobLimit]. The caps
// are rules of the profile: changing one changes what it writes.
//
// The cap bounds what the redaction holds and rewrites, not what a
// store reads: agentsession serves a blob whole, so the reader returns
// all of it before the cap is checked.
type BlobLimits struct {
	Text  int64
	Media int64
}

// The default caps of [BlobLimits].
const (
	DefaultTextBlobLimit  = 8 << 20
	DefaultMediaBlobLimit = 32 << 20
)

func (l BlobLimits) withDefaults() BlobLimits {
	if l.Text == 0 {
		l.Text = DefaultTextBlobLimit
	}
	if l.Media == 0 {
		l.Media = DefaultMediaBlobLimit
	}
	return l
}

// textType is the type a text blob's replacement is written with, the
// original's declared typ: kept, unless it names an image, audio, video
// or a binary document, which the bytes are not, when it is text/plain.
func textType(typ string) string {
	if typ == "" || isTextType(typ) {
		return typ
	}
	base, _, _ := strings.Cut(strings.ToLower(typ), ";")
	for _, p := range []string{"image/", "audio/", "video/", "font/"} {
		if strings.HasPrefix(base, p) {
			return "text/plain;charset=utf-8"
		}
	}
	switch base {
	case "application/pdf", "application/zip", "application/gzip", "application/x-gzip", "application/octet-stream":
		return "text/plain;charset=utf-8"
	}
	return typ
}

// magic is a format's signature: prefix at offset at.
type magic struct {
	at     int
	prefix string
}

// imageMagic are the image formats the blob step knows by their bytes.
var imageMagic = []magic{
	{0, "\x89PNG\r\n\x1a\n"}, {0, "\xff\xd8\xff"}, {0, "GIF87a"}, {0, "GIF89a"},
	{8, "WEBP"}, {0, "II*\x00"}, {0, "MM\x00*"}, {0, "\x00\x00\x01\x00"},
	{4, "ftypavif"}, {4, "ftypheic"}, {4, "ftypheix"}, {4, "ftypmif1"},
}

// mediaMagic are the other media formats it knows by their bytes.
var mediaMagic = []magic{
	{0, "%PDF-"}, {0, "PK\x03\x04"}, {0, "\x1f\x8b"}, {0, "BZh"}, {0, "\xfd7zXZ\x00"},
	{0, "7z\xbc\xaf\x27\x1c"}, {0, "\x28\xb5\x2f\xfd"}, {4, "ftyp"}, {0, "\x1a\x45\xdf\xa3"},
	{0, "OggS"}, {0, "fLaC"}, {0, "ID3"}, {0, "\xff\xfb"}, {0, "\xff\xf3"}, {0, "\xff\xf2"},
	{8, "WAVE"}, {8, "AVI "},
}

func matches(data []byte, ms []magic) bool {
	for _, m := range ms {
		if len(data) >= m.at+len(m.prefix) && string(data[m.at:m.at+len(m.prefix)]) == m.prefix {
			return true
		}
	}
	return false
}

// sniffImage reports whether data, bytes that are not text, start as
// an image format the blob step knows.
func sniffImage(data []byte) bool { return matches(data, imageMagic) }

// sniffMedia reports whether data, bytes that are not text, start as
// other media the blob step knows.
func sniffMedia(data []byte) bool { return matches(data, mediaMagic) }

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
