package secrets

import (
	"bytes"
	"encoding/json"
	"go/build"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
)

// TestImportBoundary holds the module to its one rule: the package and
// its tests import the standard library alone, so a program between a
// secret-holding process and an agent pays for nothing else.
func TestImportBoundary(t *testing.T) {
	pkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range append(append(pkg.Imports, pkg.TestImports...), pkg.XTestImports...) {
		if first, _, _ := strings.Cut(imp, "/"); strings.Contains(first, ".") {
			t.Errorf("secrets imports %q; only the standard library is allowed", imp)
		}
	}
}

// One value, every spelling a JSON encoder writes it in, written out
// by hand rather than by the code under test: a slash, a quote, a
// backslash, HTML's three, a two-byte rune, an astral one, a newline
// and a control character.
func TestSpellings(t *testing.T) {
	const v = "p/q\"r\\s<t>&é😀\n\x01"
	r := New(map[string]string{"T": v})
	for _, tc := range []struct{ name, spelling string }{
		{"as written", v},
		{"Go, no HTML escaping (and JavaScript)", `p/q\"r\\s<t>&é😀\n\u0001`},
		{"Go, HTML escaping", `p/q\"r\\s\u003ct\u003e\u0026é😀\n\u0001`},
		{"slashes escaped", `p\/q\"r\\s<t>&é😀\n\u0001`},
		{"slashes and HTML escaped", `p\/q\"r\\s\u003ct\u003e\u0026é😀\n\u0001`},
		{"Python, ensure_ascii", `p/q\"r\\s<t>&\u00e9\ud83d\ude00\n\u0001`},
		{"PHP, slashes and ASCII escaped", `p\/q\"r\\s<t>&\u00e9\ud83d\ude00\n\u0001`},
	} {
		got, found := r.Redact([]byte("x" + tc.spelling + "y"))
		if string(got) != "x[REDACTED T]y" || found["T"] != 1 {
			t.Errorf("%s: %q, found %v", tc.name, got, found)
		}
	}
	// A JSON line as each encoder writes it holds no part of the value.
	for _, html := range []bool{false, true} {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(html)
		if err := enc.Encode(map[string]string{"env": "T=" + v}); err != nil {
			t.Fatal(err)
		}
		got, _ := r.Redact(b.Bytes())
		if string(got) != `{"env":"T=[REDACTED T]"}`+"\n" {
			t.Errorf("html %v: %s", html, got)
		}
	}
}

func TestValues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values map[string]string
		in     string
		want   string
	}{
		{"a value holding another", map[string]string{"SHORT": "secret", "LONG": "secret-long"}, "secret-long and secret", "[REDACTED LONG] and [REDACTED SHORT]"},
		{"overlapping, one length: byte order", map[string]string{"X": "abcd", "Y": "bcde"}, "abcde", "[REDACTED X]e"},
		{"empty values skipped", map[string]string{"E": "", "F": "f00"}, "a f00 b", "a [REDACTED F] b"},
		{"one value, two names: the first name", map[string]string{"B": "same", "A": "same"}, "same", "[REDACTED A]"},
		{"nothing to find", map[string]string{"A": "absent"}, "present", "present"},
		{"quotes and backslashes", map[string]string{"Q": `a"b\c`}, `{"v":"a\"b\\c"}`, `{"v":"[REDACTED Q]"}`},
		{"a tab and a carriage return", map[string]string{"W": "a\tb\rc"}, `"a\tb\rc"`, `"[REDACTED W]"`},
	} {
		// Built many times, since a map's order is not fixed: the output
		// must not depend on it.
		for range 20 {
			got, _ := New(tc.values).Redact([]byte(tc.in))
			if string(got) != tc.want {
				t.Fatalf("%s: %q, want %q", tc.name, got, tc.want)
			}
			if s := New(tc.values).String(tc.in); s != tc.want {
				t.Fatalf("%s: String %q, want %q", tc.name, s, tc.want)
			}
		}
	}
	if !New(map[string]string{"E": ""}).Empty() || !New(nil).Empty() {
		t.Error("a redactor of nothing is not empty")
	}
	var none *Redactor
	if !none.Empty() || none.String("x") != "x" {
		t.Error("a nil redactor is not empty")
	}
}

// Exact finds a value only as written, and a placeholder of the
// caller's replaces the named one.
func TestOptions(t *testing.T) {
	const v = `a"b`
	exact := New(map[string]string{"Q": v}, Exact())
	if got := exact.String(`raw a"b, JSON a\"b`); got != `raw [REDACTED Q], JSON a\"b` {
		t.Errorf("Exact: %q", got)
	}
	fixed := New(map[string]string{"Q": v, "R": "rr"}, WithPlaceholder(func(string) string { return "[X]" }))
	if got := fixed.String(`a\"b rr`); got != "[X] [X]" {
		t.Errorf("WithPlaceholder: %q", got)
	}
	named := New(map[string]string{"Q": v}, WithPlaceholder(func(name string) string { return "<" + name + ">" }))
	if got := named.String(v); got != "<Q>" {
		t.Errorf("WithPlaceholder by name: %q", got)
	}
}

// A line longer than lineMax is passed on in pieces, and a value split
// across where a piece would end is still found, read a byte at a time
// or all at once.
func TestReaderLongLines(t *testing.T) {
	old := lineMax
	lineMax = 64
	defer func() { lineMax = old }()
	const v = "0123456789-secret-value"
	r := New(map[string]string{"S": v})
	var in strings.Builder
	var want strings.Builder
	for i := range 40 {
		// The value lands at every offset against the pieces' ends.
		pad := strings.Repeat("x", i)
		in.WriteString(pad + v + pad)
		want.WriteString(pad + "[REDACTED S]" + pad)
	}
	in.WriteString("\nnext " + v + "\n" + "no newline at the end " + v)
	want.WriteString("\nnext [REDACTED S]\nno newline at the end [REDACTED S]")
	for name, src := range map[string]func() io.Reader{
		"a byte at a time": func() io.Reader { return iotest.OneByteReader(strings.NewReader(in.String())) },
		"all at once":      func() io.Reader { return strings.NewReader(in.String()) },
	} {
		n := 0
		got, err := io.ReadAll(r.Reader(src(), func(name string, k int) {
			if name != "S" {
				t.Errorf("found %s", name)
			}
			n += k
		}))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want.String() {
			t.Errorf("%s:\n got %q\nwant %q", name, got, want.String())
		}
		if strings.Contains(string(got), v) || n != 42 {
			t.Errorf("%s: the value is left, or %d found, want 42", name, n)
		}
	}
}

// A process's output in JSON lines, its own secret quoted raw and
// escaped: the reader hands on placeholders only, counts each, and
// passes an error from the source on after what came before it.
func TestReaderJSONLines(t *testing.T) {
	const v = `tok"en/1é`
	r := New(map[string]string{"DAX_TEST_TOKEN": v, "OTHER": "o-t-h"})
	in := `{"result":{"env":{"DAX_TEST_TOKEN":"tok\"en/1é"}}}` + "\n" +
		`{"result":{"ascii":"tok\"en\/1\u00e9","raw":"tok"en/1é"}}` + "\n" +
		"err tok\"en/1é o-t-h\n"
	want := `{"result":{"env":{"DAX_TEST_TOKEN":"[REDACTED DAX_TEST_TOKEN]"}}}` + "\n" +
		`{"result":{"ascii":"[REDACTED DAX_TEST_TOKEN]","raw":"[REDACTED DAX_TEST_TOKEN]"}}` + "\n" +
		"err [REDACTED DAX_TEST_TOKEN] [REDACTED OTHER]\n"
	var order []string
	told := map[string]int{}
	src := io.MultiReader(strings.NewReader(in), iotest.ErrReader(io.ErrUnexpectedEOF))
	got, err := io.ReadAll(r.Reader(src, func(name string, n int) {
		order = append(order, name)
		told[name] += n
	}))
	if err != io.ErrUnexpectedEOF {
		t.Errorf("err = %v", err)
	}
	if string(got) != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if told["DAX_TEST_TOKEN"] != 4 || told["OTHER"] != 1 {
		t.Errorf("told %v", told)
	}
	// On the last line both are found; the callback hears them by name.
	if len(order) != 4 || order[2] != "DAX_TEST_TOKEN" || order[3] != "OTHER" {
		t.Errorf("order %v", order)
	}
	// A redactor of nothing hands back the source itself.
	plain := strings.NewReader("x")
	if New(nil).Reader(plain, nil) != io.Reader(plain) {
		t.Error("an empty redactor wrapped its source")
	}
}

// One Redactor serves readers on many goroutines at once.
func TestConcurrentUse(t *testing.T) {
	r := New(map[string]string{"S": "s3cr3t"})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := io.ReadAll(r.Reader(strings.NewReader(strings.Repeat("a s3cr3t b\n", 100)), nil))
			if err != nil || strings.Contains(string(got), "s3cr3t") {
				t.Errorf("err %v, or the value is left", err)
			}
			if r.String("s3cr3t") != "[REDACTED S]" {
				t.Error("String")
			}
		}()
	}
	wg.Wait()
}
