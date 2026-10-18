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
		if got := r(tt.in); got != tt.want {
			t.Errorf("Secrets(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	// The order the values are listed in does not change the output.
	a := Secrets("ab", "bc")("xabcx")
	b := Secrets("bc", "ab")("xabcx")
	if a != b {
		t.Errorf("order dependent: %q vs %q", a, b)
	}
	if got := Secrets()("unchanged"); got != "unchanged" {
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
		{"", "/home/example", "/home/example"},
		{"/", "/etc", "/etc"},
		{".", "./x", "./x"},
	} {
		if got := HomePaths(tt.home)(tt.in); got != tt.want {
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
	if got := r(in); got != want {
		t.Errorf("DefaultPatterns = %q, want %q", got, want)
	}
	// Each pattern runs on what the earlier ones left, and a match is
	// written literally, $ and all.
	custom := Patterns(
		guard.Pattern{Name: "num$1", Regexp: regexp.MustCompile(`[0-9]+`)},
		guard.Pattern{Name: "word", Regexp: regexp.MustCompile(`num`)},
	)
	if got, want := custom("a 42 b"), "a [REDACTED [REDACTED word]$1] b"; got != want {
		t.Errorf("Patterns = %q, want %q", got, want)
	}
	if got := Patterns()("sk-test-0000000000000000000000000000"); got != "sk-test-0000000000000000000000000000" {
		t.Errorf("no patterns changed %q", got)
	}
	defer func() {
		if recover() == nil {
			t.Error("a pattern with no Regexp did not panic")
		}
	}()
	Patterns(guard.Pattern{Name: "broken"})
}

func TestChain(t *testing.T) {
	r := Chain(Secrets("/home/example"), HomePaths("/home/example"))
	if got := r("/home/example/x"); got != "[REDACTED]/x" {
		t.Errorf("Chain = %q", got)
	}
}
