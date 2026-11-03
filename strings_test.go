package agentredact

import (
	"errors"
	"regexp"
	"testing"

	"github.com/ChristopherDavenport/agentpolicy/guard"
)

func TestValidateProfileName(t *testing.T) {
	for _, tt := range []struct {
		name string
		ok   bool
	}{
		{"default@1", true},
		{"example.redact-home@2", true},
		{"a_b@10", true},
		{"9lives@1", true},
		{"", false},
		{"default", false},
		{"default@", false},
		{"default@0", false},
		{"default@01", false},
		{"default@1.2", false},
		{"@1", false},
		{".hidden@1", false},
		{"my profile@1", false},
		{"a@b@1", false},
		{"dé@1", false},
		{string(make([]byte, 130)) + "@1", false},
	} {
		err := ValidateProfileName(tt.name)
		if (err == nil) != tt.ok {
			t.Errorf("ValidateProfileName(%q) = %v, want ok %v", tt.name, err, tt.ok)
		}
		if err != nil && !errors.Is(err, ErrProfileName) {
			t.Errorf("ValidateProfileName(%q) = %v, not ErrProfileName", tt.name, err)
		}
	}
}

func TestSecrets(t *testing.T) {
	r := Secrets("", "fake-token", "fake-token-long", "fake", "fake-token")
	for _, tt := range []struct{ in, want string }{
		{"no secret here", "no secret here"},
		{"a fake-token-long b", "a [REDACTED] b"},
		{"fake-token and fake", "[REDACTED] and [REDACTED]"},
		{"fakefake", "[REDACTED][REDACTED]"},
	} {
		if got := r(tt.in, nil); got != tt.want {
			t.Errorf("Secrets(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	// The order the values are listed in does not change the output.
	a := Secrets("ab", "bc")("xabcx", nil)
	b := Secrets("bc", "ab")("xabcx", nil)
	if a != b {
		t.Errorf("order dependent: %q vs %q", a, b)
	}
	if got := Secrets()("unchanged", nil); got != "unchanged" {
		t.Errorf("no values changed %q", got)
	}
}

func TestHomePaths(t *testing.T) {
	for _, tt := range []struct{ home, in, want string }{
		{"/home/example", "/home/example/src/main.go", "~/src/main.go"},
		{"/home/example/", "cd /home/example/src", "cd ~/src"},
		{"/home/example", "/home/example", "~"},
		{"/home/example", "home is /home/example.", "home is ~."},
		{"/home/example", `"/home/example"`, `"~"`},
		{"/home/example", "/home/example2/x", "/home/example2/x"},
		{"/home/example", "/home/example-old", "/home/example-old"},
		{"/home/example", "a /home/example/b and /home/example/c", "a ~/b and ~/c"},
		{"/home/example", `/home/example\sub`, `~\sub`},
		{`C:\Users\example`, `C:\Users\example\src\x.go`, `~\src\x.go`},
		{`C:\Users\example\`, `C:\Users\example`, `~`},
		{"/home/./example", "/home/example/x", "~/x"},
		{`C:\Users\example`, `c:\Users\example\src`, `~\src`},
		{`C:\Users\example`, `C:/Users/example/src`, `~/src`},
		{`C:\Users\example`, `"C:\\Users\\example\\src"`, `"~\\src"`},
		{"/home/example", `"\/home\/example\/src"`, `"~\/src"`},
		{"/home/example", `/home\example/x`, `~/x`},
		{`C:\Users\example`, `C:\users\example`, `C:\users\example`},
		{"/home/example", "/mnt/backup/home/example/x", "/mnt/backup/home/example/x"},
		{"/home/example", "x/home/example", "x/home/example"},
		{"/home/example", "path:/home/example", "path:~"},
		{"/home/example", "/home//example/x", "/home//example/x"},
		{`C:\`, `C:\x`, `C:\x`},
		{"", "/home/example", "/home/example"},
		{"/", "/etc", "/etc"},
		{".", "./x", "./x"},
		// After an escaped newline or tab, as a string holding JSON or
		// shell source writes one (#12).
		{"/home/example", `"x\n/home/example/p"`, `"x\n~/p"`},
		{"/home/example", `a\t/home/example`, `a\t~`},
		{"/home/example", `a\r\n/home/example/q`, `a\r\n~/q`},
		// The dash-encoded directory a harness names a project by (#12).
		{"/home/example", "-home-example-proj/", "-~-proj/"},
		{"/home/example", "/tmp/claude-1000/-home-example-coding/x", "/tmp/claude-1000/-~-coding/x"},
		{"/home/example", "projects/-home-example", "projects/-~"},
		{"/home/example", `"-home-example"`, `"-~"`},
		{"/home/example", "store/home-example-coding-x/", "store/~-coding-x/"},
		{"/home/example", `x\n-home-example-p`, `x\n-~-p`},
		{`C:\Users\example`, `C--Users-example-src`, `~-src`},
		{"/home/ex.ample", "-home-ex-ample-proj", "-~-proj"},
		{"/home/example", "-home-examplex-", "-home-examplex-"},
		{"/home/example", "-home-example_old", "-home-example_old"},
		{"/home/example", "-srv-home-example-x", "-srv-home-example-x"},
		{"/home/example", "/srv/home/example", "/srv/home/example"},
		{"/home/example", "xhome-example-y", "xhome-example-y"},
		{"/home/example", "-home-example-and-home-example", "-~-and-home-example"},
	} {
		if got := HomePaths(tt.home)(tt.in, nil); got != tt.want {
			t.Errorf("HomePaths(%q)(%q) = %q, want %q", tt.home, tt.in, got, tt.want)
		}
	}
}

func TestPatterns(t *testing.T) {
	const key = "sk-test-0000000000000000000000000000"
	const aws = "AKIAFAKE0000EXAMPLE0"
	r := DefaultPatterns()
	in := "key " + key + " and " + aws + " end"
	want := "key [REDACTED openai_key] and [REDACTED aws_access_key] end"
	if got := r(in, nil); got != want {
		t.Errorf("DefaultPatterns = %q, want %q", got, want)
	}
	// Each pattern runs on what the earlier ones left, and a match is
	// written literally, $ and all.
	custom := Patterns(
		guard.Pattern{Name: "num$1", Regexp: regexp.MustCompile(`[0-9]+`)},
		guard.Pattern{Name: "word", Regexp: regexp.MustCompile(`num`)},
	)
	if got, want := custom("a 42 b", nil), "a [REDACTED [REDACTED word]$1] b"; got != want {
		t.Errorf("Patterns = %q, want %q", got, want)
	}
	if got := Patterns()("sk-test-0000000000000000000000000000", nil); got != "sk-test-0000000000000000000000000000" {
		t.Errorf("no patterns changed %q", got)
	}
	defer func() {
		if recover() == nil {
			t.Error("a pattern with no Regexp did not panic")
		}
	}()
	Patterns(guard.Pattern{Name: "broken"})
}

// TestPlaceholdersNumbered: in a redaction, Secrets and Patterns number
// the distinct values they replace, per kind, in the order met, so one
// value is one placeholder and two are two (#20).
func TestPlaceholdersNumbered(t *testing.T) {
	ph := NewPlaceholders()
	secrets := Secrets("fake-one", "fake-two")
	keys := DefaultPatterns()
	for _, tt := range []struct {
		r        StringRedactor
		in, want string
	}{
		// Values of one length are replaced in byte order, so numbered so.
		{secrets, "fake-two then fake-one", "[REDACTED#2] then [REDACTED#1]"},
		{secrets, "fake-two again", "[REDACTED#2] again"},
		{keys, "sk-test-1111111111111111111111111111 and sk-test-2222222222222222222222222222", "[REDACTED openai_key#1] and [REDACTED openai_key#2]"},
		{keys, "AKIAFAKE0000EXAMPLE0 sk-test-2222222222222222222222222222", "[REDACTED aws_access_key#1] [REDACTED openai_key#2]"},
	} {
		if got := tt.r(tt.in, ph); got != tt.want {
			t.Errorf("%q = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestChain(t *testing.T) {
	r := Chain(Secrets("/home/example"), HomePaths("/home/example"))
	if got := r("/home/example/x", nil); got != "[REDACTED]/x" {
		t.Errorf("Chain = %q", got)
	}
}

// TestDefaultSecretPatternsPinned fails when agentpolicy's
// guard.DefaultSecrets differs from the copy DefaultPatterns uses: take
// the change into DefaultSecretPatterns deliberately, and give every
// profile that uses it a new version.
func TestDefaultSecretPatternsPinned(t *testing.T) {
	ours := DefaultSecretPatterns()
	if len(ours) != len(guard.DefaultSecrets) {
		t.Fatalf("agentpolicy has %d default patterns, the copy %d", len(guard.DefaultSecrets), len(ours))
	}
	for i, p := range guard.DefaultSecrets {
		if ours[i].Name != p.Name || ours[i].Regexp.String() != p.Regexp.String() {
			t.Errorf("pattern %d: agentpolicy has %s %q, the copy %s %q", i, p.Name, p.Regexp, ours[i].Name, ours[i].Regexp)
		}
	}
	// A fresh copy each call: changing one changes nothing else.
	ours[0].Name = "changed"
	if DefaultSecretPatterns()[0].Name == "changed" {
		t.Error("DefaultSecretPatterns shares its list")
	}
}
