package agentredact

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRules(t *testing.T) {
	for _, tt := range []struct {
		name, rules, in, want string
	}{
		{"bare literal", "p455w0rd-fake\n", "pw p455w0rd-fake.", "pw ***REMOVED***."},
		{"literal with replacement", "foo==>bar", "food foo", "bard bar"},
		{"literal prefix", "literal:MM/DD/YYYY==>YYYY-MM-DD", "on MM/DD/YYYY", "on YYYY-MM-DD"},
		{"literal prefix holds regex syntax", "literal:a.b==>X", "a.b axb", "X axb"},
		{"empty replacement", "secret-fake==>", "a secret-fake b", "a  b"},
		{"last ==> splits", "a==>b==>c", "a==>b", "c"},
		{"CRLF line endings", "foo==>bar\r\nbaz\r\n", "foo baz", "bar ***REMOVED***"},
		{"blank lines skipped", "\n\nfoo==>bar\n\n", "foo", "bar"},
		{"a # line is a literal", "#\n", "a # b", "a ***REMOVED*** b"},
		{"regex", `regex:\bdriver\b==>pilot`, "driver drivers", "pilot drivers"},
		{"regex groups", `regex:([0-9]{2})/([0-9]{2})/([0-9]{4})==>\3-\1-\2`, "on 12/31/1999.", "on 1999-12-31."},
		{"named group", `regex:(?P<user>[a-z]+)@example\.com==>\g<user>@redacted`, "mail fake@example.com", "mail fake@redacted"},
		{"g<0>", `regex:k[0-9]==>[\g<0>]`, "k1 k2", "[k1] [k2]"},
		{"escapes in template", `regex:x==>a\tb\\c\-d`, "x", "a\tb\\c\\-d"},
		{"unmatched group is empty", `regex:a(b)?c==>[\1]`, "ac abc", "[] [b]"},
		{"regex default replacement", `regex:tok-[0-9]+`, "tok-123", "***REMOVED***"},
		{"multiline flag", "regex:(?m)^secret.*$==>gone", "a\nsecret line\nb", "a\ngone\nb"},
		{"glob", "glob:*666*==>", "one\nx666y\ntwo", "one\n\ntwo"},
		{"glob ?", "glob:a?c==>X", "abc a\nc", "X a\nc"},
		{"glob class", "glob:id-[0-9][0-9]==>ID", "id-42 id-x1", "ID id-x1"},
		{"glob negated class", "glob:[!a]z==>Q", "az bz", "az Q"},
		{"glob unclosed bracket", "glob:a[b==>X", "a[b", "X"},
		{"glob quotes regex syntax", "glob:a.b==>X", "a.b axb", "X axb"},
		{"literals before regexes", "regex:b+==>R\nab==>L", "ab abb", "L LR"},
		{"BOM dropped", "\ufefffake-secret==>X", "a fake-secret", "a X"},
		{"trailing space kept", "sk-fake ==>X", "sk-fake sk-fake\n", "Xsk-fake\n"},
		{"$ only at the very end", `regex:tok \S+$==>X`, "tok abc\n", "tok abc\n"},
		{"$ with (?m)", `regex:(?m)tok \S+$==>X`, "tok abc\n", "X\n"},
		{"escaped brace", `regex:a\{,2}==>X`, "a{,2}", "X"},
		{"brace in a class", `regex:[{,]==>X`, "{,", "XX"},
		{"bracket first in a class", `regex:[]:]==>X`, "]:", "XX"},
		{"two-digit group", `regex:(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)==>\10`, "abcdefghij", "j"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ParseRules(strings.NewReader(tt.rules))
			if err != nil {
				t.Fatalf("ParseRules: %v", err)
			}
			if got := r(tt.in); got != tt.want {
				t.Errorf("rules %q on %q = %q, want %q", tt.rules, tt.in, got, tt.want)
			}
		})
	}
}

func TestParseRulesErrors(t *testing.T) {
	for _, tt := range []struct {
		name, rules, line string
	}{
		{"bad regex", "ok\nregex:(unclosed", "line 2"},
		{"lookahead", "\n\nregex:a(?=b)", "line 3"},
		{"backreference in pattern", `regex:(a)\1`, "line 1"},
		{"empty regex", "regex:==>x", "line 1"},
		{"empty glob", "glob:", "line 1"},
		{"nothing to match", "a\n==>x", "line 2"},
		{"empty literal prefix", "literal:", "line 1"},
		{"group past the pattern's", `regex:(a)==>\2`, "line 1"},
		{"unknown named group", `regex:(a)==>\g<nope>`, "line 1"},
		{"unclosed g", `regex:(a)==>\g<1`, "line 1"},
		{"letter escape", `regex:a==>\q`, "line 1"},
		{"octal escape", `regex:a==>\0`, "line 1"},
		{"trailing backslash", `regex:a==>b\`, "line 1"},
		{"not UTF-8", "ok\n\xff\xfe", "line 2"},
		{"{,n}", "regex:sk-[a-z0-9]{,40}", "line 1"},
		{"POSIX class", "ok\nregex:[[:alpha:]]+", "line 2"},
		{"POSIX class after a member", "regex:[a[:digit:]]", "line 1"},
		{"three-digit octal", `regex:(a)==>\101`, "line 1"},
		{"signed group number", `regex:(a)==>\g<+1>`, "line 1"},
		{"whitespace line", "ok\n \t\n", "line 2"},
		{"bare CR", "one\rtwo\nthree", "line 1"},
		{"CR inside a CRLF file", "a\r\nb\rc\r\n", "line 2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRules(strings.NewReader(tt.rules))
			if err == nil {
				t.Fatal("no error")
			}
			if !errors.Is(err, ErrRules) {
				t.Errorf("%v does not wrap ErrRules", err)
			}
			if !strings.Contains(err.Error(), tt.line+":") && !strings.Contains(err.Error(), tt.line+" ") {
				t.Errorf("%v does not name %s", err, tt.line)
			}
		})
	}
}
