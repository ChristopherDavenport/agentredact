package agentredact

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/ChristopherDavenport/agentpolicy/guard"
)

// SecretReplacement is what [Secrets] writes in place of each value.
const SecretReplacement = "[REDACTED]"

// Secrets replaces every occurrence of each value with
// [SecretReplacement]. Empty values are skipped. Longer values are
// replaced first, so a value holding another is not left half
// redacted; values of one length go in byte order, so the order the
// caller lists them in does not change the output. Each value is
// replaced in what the longer ones left.
func Secrets(values ...string) StringRedactor {
	var secrets []string
	for _, v := range values {
		if v != "" {
			secrets = append(secrets, v)
		}
	}
	sort.Slice(secrets, func(i, j int) bool {
		if len(secrets[i]) != len(secrets[j]) {
			return len(secrets[i]) > len(secrets[j])
		}
		return secrets[i] < secrets[j]
	})
	secrets = compactSorted(secrets)
	return func(s string) string {
		for _, secret := range secrets {
			s = strings.ReplaceAll(s, secret, SecretReplacement)
		}
		return s
	}
}

// compactSorted drops adjacent duplicates.
func compactSorted(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
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
		return func(s string) string { return s }
	}
	return func(s string) string {
		matches := re.FindAllStringIndex(s, -1)
		if matches == nil {
			return s
		}
		var b strings.Builder
		last := 0
		for _, m := range matches {
			before := m[0] == 0 || !partOfSegment(s[m[0]-1])
			rest := s[m[1]:]
			after := rest == "" || rest[0] == '/' || rest[0] == '\\' || !continuesSegment(rest[0])
			if !before || !after {
				continue
			}
			b.WriteString(s[last:m[0]])
			b.WriteString("~")
			last = m[1]
		}
		b.WriteString(s[last:])
		return b.String()
	}
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
// "[REDACTED <name>]", as agentpolicy's guard.Redact writes a match,
// each pattern applied to what the earlier ones left. With no patterns
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
	return func(s string) string {
		for _, p := range ps {
			s = p.Regexp.ReplaceAllLiteralString(s, "[REDACTED "+p.Name+"]")
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
