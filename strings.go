package agentredact

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/ChristopherDavenport/agentpolicy/guard"
	"github.com/ChristopherDavenport/agentredact/secrets"
)

// SecretReplacement is what [Secrets] writes in place of each value
// outside a redaction; in one it writes "[REDACTED#<n>]", n numbering
// the distinct values it replaced in the redacted session
// ([Placeholders]).
const SecretReplacement = "[REDACTED]"

// Secrets replaces every occurrence of each value with a placeholder:
// ph.For("", value), "[REDACTED#<n>]" in a redaction, so two values are
// two placeholders, and [SecretReplacement] outside one. Empty values
// are skipped. Longer values are replaced first, so a value holding
// another is not left half redacted; values of one length go in byte
// order, so the order the caller lists them in does not change the
// output. Each value is replaced in what the longer ones left. Values
// are matched as written: a session's strings reach a redactor decoded,
// so their JSON spellings are not looked for here. Outside a redaction
// it is the secrets package's Redactor, exact and with one placeholder
// for every value, which the programs that redact a stream, a JSON one
// among them, use directly.
func Secrets(values ...string) StringRedactor {
	byValue := make(map[string]string, len(values))
	for _, v := range values {
		byValue[v] = v
	}
	plain := secrets.New(byValue, secrets.Exact(), secrets.WithPlaceholder(func(string) string { return SecretReplacement }))
	ordered := make([]string, 0, len(byValue))
	for v := range byValue {
		if v != "" {
			ordered = append(ordered, v)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) != len(ordered[j]) {
			return len(ordered[i]) > len(ordered[j])
		}
		return ordered[i] < ordered[j]
	})
	return func(s string, ph *Placeholders) string {
		if ph == nil {
			return plain.String(s)
		}
		for _, v := range ordered {
			if strings.Contains(s, v) {
				s = strings.ReplaceAll(s, v, ph.For("", v))
			}
		}
		return s
	}
}

// HomePaths shortens paths under the home directory home: home followed
// by a separator becomes "~" and that separator, so /home/example/src
// becomes ~/src and C:\Users\example\src becomes ~\src, and home itself
// becomes "~" where it ends the string or is followed by anything but a
// letter, a digit, '_' or '-', which would make it part of a longer
// name. So /home/example2, another user's home, is left alone, where
// agentsession's export.HomePaths would have written ~2, while
// "/home/example." ending a sentence, and /home/example.bak, become "~."
// and ~.bak. Home must also start the string or follow a character that
// cannot be part of a path segment, so /mnt/backup/home/example is left
// alone; anything but a letter, a digit, '.', '_' or '-' will do, a
// quote, a space or a colon.
//
// Between home's segments any separator matches, whatever home was
// given with: '/', '\', and the JSON-escaped spellings '\\' and '\/',
// as a tool's JSON output or a repr holds them; so C:/Users/example/src
// and C:\\Users\\example\\src are shortened too. A drive letter matches
// in either case (c:\Users\example), as Windows tools write it; the
// other segments match as written. A spelling with a doubled separator,
// /home//example, is not matched.
//
// A backslash and one of the escape letters n, t, r, b and f before
// home is a boundary too, as a string holding JSON or shell source
// writes a newline or a tab before a path: x\n/home/example/src, with
// a literal backslash, becomes x\n~/src.
//
// Home is also found in its dash-encoded form, the directory name
// several harnesses give a project, every character of home but an
// ASCII letter or digit written '-': Claude Code's project directory
// -home-example-coding-proj, and the same inside its scratchpad paths,
// becomes -~-coding-proj, and an agentsession jsonl store's
// home-example-coding-proj, after a separator, becomes ~-coding-proj.
// The encoded form must start the string or follow a character that is
// not a letter, a digit, '.', '_' or '-' (or an escape, as above), and
// be followed by '-', a separator, the end, or anything but a letter, a
// digit or '_', so -srv-home-example, a path under another root, and
// -home-example2, another user's, are left alone. "-~" is written
// because no harness's encoding writes a '~', so it cannot be taken for
// a directory of its own.
//
// home is taken as written, trailing separators trimmed, and a home
// holding no backslash is cleaned as a slash path; the result does not
// depend on the platform it runs on. An empty home, ".", "/", "\" or a
// drive alone changes nothing.
func HomePaths(home string) StringRedactor {
	if !strings.Contains(home, `\`) && home != "" {
		home = path.Clean(home)
	}
	for len(home) > 1 && (strings.HasSuffix(home, "/") || strings.HasSuffix(home, `\`)) {
		home = home[:len(home)-1]
	}
	re := homePattern(home)
	if re == nil {
		return func(s string, _ *Placeholders) string { return s }
	}
	encoded := dashEncoded(home)
	return func(s string, ph *Placeholders) string {
		s, n := replaceHome(s, re.FindAllStringIndex(s, -1), "~", func(c byte) bool {
			return c == '/' || c == '\\' || !continuesSegment(c)
		})
		defer func() { ph.Count("home", n) }()
		if encoded == "" || !strings.Contains(s, encoded[1:]) {
			return s
		}
		dashAfter := func(c byte) bool { return c == '-' || c == '/' || c == '\\' || !continuesSegment(c) }
		var k int
		if encoded[0] == '-' {
			s, k = replaceHome(s, indexAll(s, encoded), "-~", dashAfter)
			n += k
			// The form without the leading dash, after a separator alone.
			var after [][]int
			for _, m := range indexAll(s, encoded[1:]) {
				if m[0] > 0 && (s[m[0]-1] == '/' || s[m[0]-1] == '\\') {
					after = append(after, m)
				}
			}
			s, k = replaceHome(s, after, "~", dashAfter)
			n += k
			return s
		}
		s, k = replaceHome(s, indexAll(s, encoded), "~", dashAfter)
		n += k
		return s
	}
}

// replaceHome writes with in place of each match of s, [from, to), that
// stands on its own: what precedes it is no part of a path segment, or
// is an escape, and endsHome accepts the byte following it, if any.
func replaceHome(s string, matches [][]int, with string, endsHome func(c byte) bool) (string, int) {
	if matches == nil {
		return s, 0
	}
	var b strings.Builder
	last, n := 0, 0
	for _, m := range matches {
		if m[0] < last {
			continue
		}
		before := m[0] == 0 || !partOfSegment(s[m[0]-1]) || escapeBefore(s, m[0])
		after := m[1] == len(s) || endsHome(s[m[1]])
		if !before || !after {
			continue
		}
		b.WriteString(s[last:m[0]])
		b.WriteString(with)
		last = m[1]
		n++
	}
	if n == 0 {
		return s, 0
	}
	b.WriteString(s[last:])
	return b.String(), n
}

// escapeBefore reports whether s holds, just before i, a backslash and
// an escape letter, as a string holding JSON or C source writes a
// newline, a tab, a return, a backspace or a form feed.
func escapeBefore(s string, i int) bool {
	return i >= 2 && s[i-2] == '\\' && strings.IndexByte("ntrbf", s[i-1]) >= 0
}

// indexAll returns the start and end of each occurrence of sub in s,
// not overlapping, in order.
func indexAll(s, sub string) [][]int {
	var out [][]int
	for from := 0; from <= len(s)-len(sub); {
		i := strings.Index(s[from:], sub)
		if i < 0 {
			break
		}
		out = append(out, []int{from + i, from + i + len(sub)})
		from += i + len(sub)
	}
	return out
}

// dashEncoded is home as a harness encodes a path in a directory name,
// every byte but an ASCII letter or digit written '-', or "" for a home
// with fewer than two letters or digits, which would match too much.
func dashEncoded(home string) string {
	b := []byte(home)
	n := 0
	for i, c := range b {
		if isAlnum(c) {
			n++
		} else {
			b[i] = '-'
		}
	}
	if n < 2 || len(b) < 2 {
		return ""
	}
	return string(b)
}

// homeSeparator matches one separator as a string may spell it: '/',
// '\', and the JSON-escaped '\\' and '\/', the longer spellings first.
const homeSeparator = `(?:\\\\|\\/|/|\\)`

// homePattern is the pattern home's spellings match, or nil for a home
// that changes nothing.
func homePattern(home string) *regexp.Regexp {
	if home == "" || home == "." {
		return nil
	}
	var b strings.Builder
	rest := home
	if len(home) >= 2 && home[1] == ':' && (home[0] >= 'a' && home[0] <= 'z' || home[0] >= 'A' && home[0] <= 'Z') {
		b.WriteString("[" + strings.ToLower(home[:1]) + strings.ToUpper(home[:1]) + "]:")
		rest = home[2:]
	}
	lead := 0
	for lead < len(rest) && (rest[lead] == '/' || rest[lead] == '\\') {
		lead++
	}
	segs := strings.FieldsFunc(rest[lead:], func(r rune) bool { return r == '/' || r == '\\' })
	if len(segs) == 0 {
		return nil
	}
	b.WriteString(strings.Repeat(homeSeparator, lead))
	for i, seg := range segs {
		if i > 0 {
			b.WriteString(homeSeparator)
		}
		b.WriteString(regexp.QuoteMeta(seg))
	}
	return regexp.MustCompile(b.String())
}

// partOfSegment reports whether c, before a home directory, makes it
// the tail of a longer path rather than the directory itself.
func partOfSegment(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '-' || c >= 0x80
}

// continuesSegment reports whether c, after a home directory, makes it
// part of a longer path segment rather than the directory itself.
func continuesSegment(c byte) bool {
	return isAlnum(c) || c == '_' || c == '-' || c >= 0x80
}

// Patterns replaces each match of each pattern, in order, with
// "[REDACTED <name>]", as agentpolicy's guard.Redact writes a match, or
// in a redaction "[REDACTED <name>#<n>]", n numbering the distinct
// matches of that name in the redacted session ([Placeholders]), each
// pattern applied to what the earlier ones left. With no patterns
// it changes nothing; [DefaultPatterns] is the default set. A pattern
// with no Regexp panics here, when the redactor is made, rather than
// being skipped, since a skipped pattern is a secret passed.
func Patterns(patterns ...guard.Pattern) StringRedactor {
	ps := make([]guard.Pattern, len(patterns))
	copy(ps, patterns)
	for _, p := range ps {
		if p.Regexp == nil {
			panic("agentredact: pattern " + p.Name + " has no Regexp")
		}
	}
	return func(s string, ph *Placeholders) string {
		for _, p := range ps {
			s = p.Regexp.ReplaceAllStringFunc(s, func(m string) string { return ph.For(p.Name, m) })
		}
		return s
	}
}

// DefaultPatterns is [Patterns] over [DefaultSecretPatterns].
func DefaultPatterns() StringRedactor {
	return Patterns(DefaultSecretPatterns()...)
}

// DefaultSecretPatterns returns, afresh on each call, the patterns
// [DefaultPatterns] uses: a copy of agentpolicy v0.0.17's
// guard.DefaultSecrets, cloud and API keys with a recognisable prefix,
// the common hosting and chat services' tokens, private key blocks and
// JSON web tokens. It is a copy, not guard.DefaultSecrets itself, which
// is a variable any linked package may append to and an agentpolicy
// upgrade may change: either would change what a profile writes under
// the same name. A test fails when agentpolicy's list differs from this
// one, so a change is taken here deliberately, with the profiles that
// use it given a new version.
func DefaultSecretPatterns() []guard.Pattern {
	return []guard.Pattern{
		{Name: "aws_access_key", Regexp: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{Name: "github_token", Regexp: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
		{Name: "github_pat", Regexp: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
		{Name: "slack_token", Regexp: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
		{Name: "google_api_key", Regexp: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
		{Name: "openai_key", Regexp: regexp.MustCompile(`\bsk-(?:[A-Za-z0-9]+-)?[A-Za-z0-9_-]{20,}\b`)},
		{Name: "private_key", Regexp: regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----`)},
		{Name: "jwt", Regexp: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	}
}
