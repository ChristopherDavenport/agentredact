package agentredact

import (
	"path"
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
// by a separator, '/' or '\', becomes "~" and that separator, so
// /home/example/src becomes ~/src and C:\Users\example\src becomes
// ~\src, and home itself becomes "~" where it ends the string or is
// followed by anything but a letter, a digit, '_' or '-', which would
// make it part of a longer name. So /home/example2, another user's
// home, is left alone, where agentsession's export.HomePaths would have
// written ~2, while "/home/example." ending a sentence, and
// /home/example.bak, become "~." and ~.bak.
//
// home is taken as written, trailing separators trimmed, and a home
// holding no backslash is cleaned as a slash path; the result does not
// depend on the platform it runs on. An empty home, ".", "/" or "\"
// changes nothing.
func HomePaths(home string) StringRedactor {
	if !strings.Contains(home, `\`) && home != "" {
		home = path.Clean(home)
	}
	for len(home) > 1 && (strings.HasSuffix(home, "/") || strings.HasSuffix(home, `\`)) {
		home = home[:len(home)-1]
	}
	if home == "" || home == "." || home == "/" || home == `\` {
		return func(s string) string { return s }
	}
	return func(s string) string {
		if !strings.Contains(s, home) {
			return s
		}
		var b strings.Builder
		for {
			i := strings.Index(s, home)
			if i < 0 {
				b.WriteString(s)
				return b.String()
			}
			b.WriteString(s[:i])
			rest := s[i+len(home):]
			if rest == "" || !continuesSegment(rest[0]) {
				b.WriteString("~")
			} else {
				b.WriteString(home)
			}
			s = rest
		}
	}
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

// DefaultPatterns is [Patterns] over agentpolicy's guard.DefaultSecrets
// as they are when it is called: cloud and API keys with a recognisable
// prefix, the common hosting and chat services' tokens, private key
// blocks and JSON web tokens.
func DefaultPatterns() StringRedactor {
	return Patterns(guard.DefaultSecrets...)
}
