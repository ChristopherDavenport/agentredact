// Package secrets replaces known secret values in text and in streams:
// each value in every spelling a JSON encoder writes it in, with a
// placeholder that names the secret, "[REDACTED NAME]" by default.
//
// It is for what a process holding secrets writes back: an MCP server
// given a token, whose env tool or error message quotes it. A
// [Redactor] is built once from the values by name, and then reads a
// stream through [Redactor.Reader], a line at a time, or redacts a
// whole buffer or string. The output depends on the values and the
// input alone: longer spellings are replaced first, spellings of one
// length in byte order, each in what the longer ones left, so neither
// the order the values come in nor a map's order changes a byte, and a
// value holding another is not left half replaced.
//
// It is a backstop, not a guarantee. A value the writer encodes
// otherwise (base64, URL encoding, reversed, split across two
// messages) is not found.
//
// The package imports the standard library alone, so the programs that
// sit between a secret-holding process and an agent (agentworkspace's
// offered servers, dax's box host) can use it without the rest of
// agentredact, which reads sessions. agentredact's [Secrets] is built
// on it, with [Exact] and a fixed placeholder.
//
// [Secrets]: https://pkg.go.dev/github.com/ChristopherDavenport/agentredact#Secrets
package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// lineMax is the longest line a Reader holds whole: a line longer than
// this without its newline is passed on in pieces. A var for the tests.
var lineMax = 1 << 20

// A Redactor replaces secret values. It is not changed after [New], so
// one Redactor may be used from any number of goroutines at once.
type Redactor struct {
	spellings []spelling
	longest   int
}

type spelling struct {
	text        []byte
	name        string
	placeholder []byte
}

// An Option changes how [New] builds a Redactor.
type Option func(*options)

type options struct {
	exact       bool
	placeholder func(name string) string
}

// Exact makes a Redactor find each value only as written, not in its
// JSON spellings: for text that is not JSON, or JSON already decoded.
func Exact() Option { return func(o *options) { o.exact = true } }

// WithPlaceholder sets what a secret called name is replaced with. The
// default is "[REDACTED " + name + "]". It is called once per secret,
// in [New], and must itself be deterministic.
func WithPlaceholder(f func(name string) string) Option {
	return func(o *options) { o.placeholder = f }
}

// New is a Redactor of values, by the secret's name. Empty values are
// skipped. A value two names hold is replaced as the name that sorts
// first.
func New(values map[string]string, opts ...Option) *Redactor {
	o := options{placeholder: func(name string) string { return "[REDACTED " + name + "]" }}
	for _, opt := range opts {
		opt(&o)
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	r := &Redactor{}
	for _, name := range names {
		v := values[name]
		if v == "" {
			continue
		}
		forms := []string{v}
		if !o.exact {
			forms = spellingsOf(v)
		}
		placeholder := []byte(o.placeholder(name))
		for _, s := range forms {
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			r.spellings = append(r.spellings, spelling{text: []byte(s), name: name, placeholder: placeholder})
			r.longest = max(r.longest, len(s))
		}
	}
	sort.Slice(r.spellings, func(i, j int) bool {
		a, b := r.spellings[i].text, r.spellings[j].text
		if len(a) != len(b) {
			return len(a) > len(b)
		}
		return bytes.Compare(a, b) < 0
	})
	return r
}

// Empty reports whether r has nothing to replace.
func (r *Redactor) Empty() bool { return r == nil || len(r.spellings) == 0 }

// spellingsOf is v as written and as JSON encoders write it inside a
// string: Go's with and without HTML escaping, each also with '/' as
// '\/', and the ASCII-only form Python's json.dumps writes (every
// non-ASCII rune as \uXXXX, a surrogate pair above U+FFFF), also with
// '/' as '\/' as PHP's json_encode writes it, with JavaScript's
// JSON.stringify's beside them (short escapes, other control
// characters as \u00XX, the rest as written).
func spellingsOf(v string) []string {
	goJSON := func(html bool) string {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(html)
		if err := enc.Encode(v); err != nil {
			return ""
		}
		s := strings.TrimSuffix(b.String(), "\n")
		return strings.TrimSuffix(strings.TrimPrefix(s, `"`), `"`)
	}
	plain, html := goJSON(false), goJSON(true)
	return []string{
		v,
		plain, html,
		strings.ReplaceAll(plain, "/", `\/`), strings.ReplaceAll(html, "/", `\/`),
		scriptJSON(v, true), strings.ReplaceAll(scriptJSON(v, true), "/", `\/`), scriptJSON(v, false),
	}
}

// scriptJSON is v as Python's json.dumps (ascii, every non-ASCII rune
// as \uXXXX) or JavaScript's JSON.stringify (not ascii) write it inside
// a string: \" \\ \b \f \n \r \t, other control characters as \u00XX,
// lower-case hex as both write it.
func scriptJSON(v string, ascii bool) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(&b, `\u%04x`, r)
			case r < utf8.RuneSelf || !ascii:
				b.WriteRune(r)
			case r > 0xFFFF:
				r -= 0x10000
				fmt.Fprintf(&b, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
			default:
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		}
	}
	return b.String()
}

// Redact is b with every spelling replaced, and how often each secret
// was, by name. b may be changed in place. A shorter spelling is matched
// in what the longer ones wrote too, a placeholder among it: with the
// values "REDACTED" and "ACT" and a fixed placeholder "[REDACTED]",
// "REDACTED" becomes "[RED[REDACTED]ED]" and both are counted.
func (r *Redactor) Redact(b []byte) ([]byte, map[string]int) {
	if r.Empty() {
		return b, nil
	}
	var found map[string]int
	for _, s := range r.spellings {
		n := bytes.Count(b, s.text)
		if n == 0 {
			continue
		}
		if found == nil {
			found = map[string]int{}
		}
		found[s.name] += n
		b = bytes.ReplaceAll(b, s.text, s.placeholder)
	}
	return b, found
}

// String is s with every spelling replaced.
func (r *Redactor) String(s string) string {
	if r.Empty() {
		return s
	}
	b, found := r.Redact([]byte(s))
	if found == nil {
		return s
	}
	return string(b)
}

// Reader is src as r redacts it: a line at a time, newline included, or,
// for a line longer than a megabyte, in pieces split where no spelling
// reaches across, so the output is the whole line's whatever sizes src
// reads in. Spellings that reach across one another in a chain longer
// than the split will follow are held whole until the line ends. found,
// when not nil, is told of the replacements in each piece, by name in
// sorted order.
func (r *Redactor) Reader(src io.Reader, found func(name string, n int)) io.Reader {
	if r.Empty() {
		return src
	}
	return &reader{r: r, src: src, found: found}
}

type reader struct {
	r     *Redactor
	src   io.Reader
	found func(string, int)

	in  []byte // read, not yet redacted
	out []byte // redacted, not yet read
	err error
}

func (rr *reader) Read(p []byte) (int, error) {
	for len(rr.out) == 0 {
		if rr.err != nil {
			if len(rr.in) > 0 {
				rr.emit(rr.in)
				rr.in = nil
				continue
			}
			return 0, rr.err
		}
		if i := bytes.IndexByte(rr.in, '\n'); i >= 0 {
			rr.emit(rr.in[:i+1])
			rr.in = rr.in[i+1:]
			continue
		}
		if len(rr.in) >= lineMax {
			// A cut at 0 is a spelling that may begin at the very start:
			// read on until it is whole or the line ends.
			if cut := rr.r.cut(rr.in); cut > 0 {
				rr.emit(rr.in[:cut])
				rr.in = rr.in[cut:]
				continue
			}
		}
		buf := make([]byte, 32<<10)
		n, err := rr.src.Read(buf)
		rr.in = append(rr.in, buf[:n]...)
		rr.err = err
	}
	n := copy(p, rr.out)
	rr.out = rr.out[n:]
	return n, nil
}

func (rr *reader) emit(b []byte) {
	red, found := rr.r.Redact(bytes.Clone(b))
	rr.out = append(rr.out, red...)
	if rr.found != nil {
		names := make([]string, 0, len(found))
		for name := range found {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			rr.found(name, found[name])
		}
	}
}

// cut is where to split b, a piece of a long line, so that no spelling
// is cut in two: the last longest-1 bytes are held back, and further
// still to the start of a spelling that reaches across the split, again
// and again, since a spelling that starts earlier may reach across the
// new split (one value's end the start of another's). It returns 0, read
// on, when the spellings run back to the start of b or past cutSteps
// moves; a chain that long is held whole until the line ends.
func (r *Redactor) cut(b []byte) int {
	cut := len(b) - (r.longest - 1)
	if cut <= 0 {
		return len(b)
	}
	for range cutSteps {
		s, ok := r.crossing(b, cut)
		if !ok {
			return cut
		}
		if s == 0 {
			return 0
		}
		cut = s
	}
	return 0
}

// cutSteps bounds how far cut follows spellings that reach across one
// another back from the end of a piece.
const cutSteps = 64

// crossing returns the first position before at in b where a spelling
// starts and reaches past at: one whole in b, or one b ends inside.
func (r *Redactor) crossing(b []byte, at int) (int, bool) {
	for e := max(0, at-(r.longest-1)); e < at; e++ {
		for _, s := range r.spellings {
			end := e + len(s.text)
			if end <= at {
				continue
			}
			if bytes.HasPrefix(s.text, b[e:min(end, len(b))]) {
				return e, true
			}
		}
	}
	return 0, false
}
