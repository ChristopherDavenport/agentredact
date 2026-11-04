package agentredact

import (
	"encoding/json"
	"path"
	"regexp"
	"slices"
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
// are matched as written and in their JSON spellings, once and twice
// escaped, as a session's strings hold JSON text, a function call's
// arguments among them, whose escapes the Rewriter does not decode.
// Outside a redaction it is the secrets package's Redactor, with one
// placeholder for every value, which the programs that redact a stream,
// a JSON one among them, use directly.
func Secrets(values ...string) StringRedactor {
	byValue := make(map[string]string, len(values))
	for _, v := range values {
		byValue[v] = v
	}
	// The secrets package finds each value in its JSON spellings; given
	// each value's once-escaped spelling as well, it finds the twice
	// escaped ones too.
	named := map[string]string{}
	for v := range byValue {
		named["v:"+v] = v
		if sp := jsonSpellings(v); len(sp) > 1 {
			named["j:"+v] = sp[1]
		}
	}
	plain := secrets.New(named, secrets.WithPlaceholder(func(string) string { return SecretReplacement }))
	// Each spelling of each value, with the value it spells.
	spells := map[string]string{}
	for v := range byValue {
		for _, sp := range jsonSpellings(v) {
			if sp == "" {
				continue
			}
			if was, ok := spells[sp]; !ok || v < was {
				spells[sp] = v
			}
		}
	}
	ordered := make([]string, 0, len(spells))
	for sp := range spells {
		ordered = append(ordered, sp)
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
		for _, sp := range ordered {
			if strings.Contains(s, sp) {
				s = strings.ReplaceAll(s, sp, ph.For("", spells[sp]))
			}
		}
		return s
	}
}

// jsonSpellings are v as written and as JSON text writes it inside a
// string, once and twice escaped, with and without HTML escapes.
func jsonSpellings(v string) []string {
	out := []string{v}
	once := v
	for range 2 {
		for _, html := range []bool{false, true} {
			var b strings.Builder
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(html)
			if enc.Encode(once) != nil {
				continue
			}
			e := strings.TrimSuffix(b.String(), "\n")
			e = e[1 : len(e)-1]
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
		var b strings.Builder
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(once)
		e := strings.TrimSuffix(b.String(), "\n")
		once = e[1 : len(e)-1]
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
	others := otherSideHomes(home, re)
	return func(s string, ph *Placeholders) string {
		endsPath := func(c byte) bool { return c == '/' || c == '\\' || !continuesSegment(c) }
		s, n := replaceHome(s, windowsProfiles(s), "~", endsPath)
		for _, o := range others {
			var k int
			s, k = replaceHome(s, o.FindAllStringIndex(s, -1), "~", endsPath)
			n += k
		}
		s, k := replaceHome(s, re.FindAllStringIndex(s, -1), "~", endsPath)
		n += k
		defer func() { ph.Count("home", n) }()
		if encoded == "" || !strings.Contains(s, encoded[1:]) {
			return s
		}
		dashAfter := func(c byte) bool { return c == '-' || c == '/' || c == '\\' || !continuesSegment(c) }
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

// windowsProfile matches a Windows user's profile seen from WSL,
// /mnt/<drive>/Users/<name>, whatever the name and its case.
var (
	windowsProfile = regexp.MustCompile(`(?:/mnt/[A-Za-z]|\b[A-Za-z]:)` + homeSeparator + `(?i:users)` + homeSeparator + `([^/\\\s"':*?<>|]+)`)
	// spacedProfile is one whose name holds spaces, taken up to the
	// separator that must follow it.
	spacedProfile = regexp.MustCompile(`(?:/mnt/[A-Za-z]|\b[A-Za-z]:)` + homeSeparator + `(?i:users)` + homeSeparator + `([^/\\\n"':*?<>|]+ [^/\\\n"':*?<>|]+)(?:/|\\)`)
)

// sharedProfiles are the profiles under Users no person owns.
var sharedProfiles = map[string]bool{"public": true, "default": true, "all users": true, "default user": true}

// windowsProfiles are the matches in s of a Windows user's profile,
// <drive>:\Users\<name> or /mnt/<drive>/Users/<name>, that name a person's:
// any Windows home is a home, as the Windows name often differs from the
// Linux one. A name holding spaces is taken up to the separator after
// it; one without, up to the first character no name holds.
func windowsProfiles(s string) [][]int {
	var out [][]int
	taken := func(a, b int) bool {
		for _, m := range out {
			if a < m[1] && m[0] < b {
				return true
			}
		}
		return false
	}
	for _, m := range spacedProfile.FindAllStringSubmatchIndex(s, -1) {
		if !sharedProfiles[strings.ToLower(s[m[2]:m[3]])] {
			out = append(out, []int{m[0], m[3]})
		}
	}
	for _, m := range windowsProfile.FindAllStringSubmatchIndex(s, -1) {
		if !sharedProfiles[strings.ToLower(s[m[2]:m[3]])] && !taken(m[0], m[1]) {
			out = append(out, m[:2])
		}
	}
	slices.SortFunc(out, func(a, b []int) int { return a[0] - b[0] })
	return out
}

// otherSideHomes are the patterns of home as the other side of a WSL
// machine spells it: a Linux home through Windows' \\wsl.localhost\<distro>
// or \\wsl$\<distro> share, and the same user's Windows profile,
// <drive>:\Users\<name> or, from Linux, /mnt/<drive>/Users/<name>, for a
// home /home/<name> or /Users/<name>; and for a Windows home, its
// /mnt/<drive> form. The separators match as home's do.
func otherSideHomes(home string, re *regexp.Regexp) []*regexp.Regexp {
	segs := strings.FieldsFunc(home, func(r rune) bool { return r == '/' || r == '\\' })
	if len(segs) < 2 {
		return nil
	}
	user := regexp.QuoteMeta(segs[len(segs)-1])
	profile := `(?:/mnt/[A-Za-z]|[A-Za-z]:)` + homeSeparator + `[Uu]sers` + homeSeparator + user
	switch {
	case strings.HasPrefix(home, "/") && len(segs) == 2 && (segs[0] == "home" || segs[0] == "Users"):
		share := `(?:\\\\|\\){2}wsl(?:\.localhost|\$)(?:\\\\|\\)[A-Za-z0-9._-]+`
		return []*regexp.Regexp{regexp.MustCompile(share + re.String()), regexp.MustCompile(profile)}
	case strings.HasPrefix(home, "/"):
		share := `(?:\\\\|\\){2}wsl(?:\.localhost|\$)(?:\\\\|\\)[A-Za-z0-9._-]+`
		return []*regexp.Regexp{regexp.MustCompile(share + re.String())}
	case len(segs) == 3 && strings.EqualFold(segs[1], "users"):
		return []*regexp.Regexp{regexp.MustCompile(`/mnt/[A-Za-z]` + homeSeparator + `[Uu]sers` + homeSeparator + user)}
	}
	return nil
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
			g := p.Regexp.SubexpIndex("secret")
			if g < 0 {
				s = p.Regexp.ReplaceAllStringFunc(s, func(m string) string { return ph.For(p.Name, m) })
				continue
			}
			s = replaceGroup(s, p.Regexp, g, func(m string) string {
				if notSecret(p.Name, m) {
					return m
				}
				return ph.For(p.Name, m)
			})
		}
		return s
	}
}

// notSecret reports whether m, what a pattern's secret group matched,
// is plainly no secret: a password that is the word password itself, as
// code passing a variable of that name writes password=password.
func notSecret(name, m string) bool {
	if name != "password" {
		return false
	}
	switch strings.ToLower(m) {
	case "password", "passwd", "pwd", "pass", "secret":
		return true
	}
	return false
}

// replaceGroup replaces, in each match of re in s, the text group g
// matched, leaving the rest of the match, as a pattern with a group
// named "secret" asks: the password of a URL, the token after Bearer.
func replaceGroup(s string, re *regexp.Regexp, g int, with func(string) string) string {
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		from, to := m[2*g], m[2*g+1]
		if from < 0 {
			continue
		}
		b.WriteString(s[last:from])
		b.WriteString(with(s[from:to]))
		last = to
	}
	b.WriteString(s[last:])
	return b.String()
}

// DefaultPatterns is [Patterns] over [ExtraSecretPatterns] and then
// [DefaultSecretPatterns].
func DefaultPatterns() StringRedactor {
	return Patterns(append(ExtraSecretPatterns(), DefaultSecretPatterns()...)...)
}

// ExtraSecretPatterns returns, afresh on each call, the secret shapes
// [DefaultPatterns] looks for beyond agentpolicy's list, applied before
// it: a private key block, PEM or PGP, whole or cut off before its END
// line, which is redacted to the end of the string; a token after
// Bearer; Hugging Face, Stripe live, GitLab personal access and Slack
// webhook tokens; an AWS secret access key where a name says it is one;
// the password in a URL's credentials, in a password= keyword or in
// curl -u, a Basic authorization, an AWS secret key and session token
// in name/value pairs, Google OAuth tokens and client secrets, and a
// PEM block in base64. A pattern with a group named
// "secret" replaces that group alone, so "Bearer" and the URL around a
// password stay. A change here changes what a profile using
// DefaultPatterns writes, so it takes a new version.
func ExtraSecretPatterns() []guard.Pattern {
	return []guard.Pattern{
		{Name: "private_key", Regexp: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)},
		{Name: "private_key", Regexp: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*$`)},
		{Name: "bearer_token", Regexp: regexp.MustCompile(`(?i)\bbearer\s+(?P<secret>[A-Za-z0-9._~+/-]{16,}=*)`)},
		{Name: "huggingface_token", Regexp: regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}\b`)},
		{Name: "stripe_key", Regexp: regexp.MustCompile(`\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b`)},
		{Name: "gitlab_token", Regexp: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
		{Name: "slack_webhook", Regexp: regexp.MustCompile(`https:(?:\\?/){2}hooks\.slack\.com(?:\\?/)services(?:\\?/)[A-Za-z0-9_-]+(?:(?:\\?/)[A-Za-z0-9_-]+)*`)},
		{Name: "google_oauth_token", Regexp: regexp.MustCompile(`\bya29\.[A-Za-z0-9_-]{20,}`)},
		{Name: "google_client_secret", Regexp: regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_-]{20,}`)},
		{Name: "pem_base64", Regexp: regexp.MustCompile(`\bLS0tLS1CRUdJT[A-Za-z0-9+/]{16,}={0,2}(?:(?:\r?\n|\\n)(?:[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9+/]{2,}={1,2}))*`)},
		{Name: "aws_secret_key", Regexp: regexp.MustCompile(`(?i)(?:aws_?secret_?(?:access_?)?key|secret_?access_?key)["']?\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9/+]{40})\b`)},
		{Name: "aws_secret_key", Regexp: regexp.MustCompile(`(?i)aws_secret_access_key\\?"\s*,\s*\\?"value\\?"\s*:\s*\\?"(?P<secret>[A-Za-z0-9/+]{40})`)},
		{Name: "aws_secret_key", Regexp: regexp.MustCompile(`(?i)name:[ \t]*["']?aws_secret_access_key["']?[ \t]*\r?\n[ \t-]*value:[ \t]*["']?(?P<secret>[A-Za-z0-9/+]{40})`)},
		{Name: "aws_session_token", Regexp: regexp.MustCompile(`(?i)(?:\\?"session_?token\\?"\s*:\s*\\?"|aws_session_token["']?\s*[:=]\s*["']?)(?P<secret>[A-Za-z0-9/+=]{16,})`)},
		{Name: "url_password", Regexp: regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@"'\\]*:(?P<secret>[^\s@/"'\\]+)@`)},
		{Name: "password", Regexp: regexp.MustCompile(`(?i)\b[A-Za-z0-9_]*(?:password|passwd|pwd)=(?P<secret>[^=;\s"'&,)][^;\s"'&,)]*)`)},
		{Name: "password", Regexp: regexp.MustCompile(`(?i)\\?"[A-Za-z0-9_]*(?:password|passwd|pwd)\\?"\s*:\s*\\?"(?P<secret>[^"\\]+)\\?"`)},
		{Name: "password", Regexp: regexp.MustCompile(`(?im)^[ \t-]*[A-Za-z0-9_]*(?:password|passwd)[ \t]*:[ \t]+["']?(?P<secret>[^\s"'#][^\n"'#]*?)["']?[ \t]*$`)},
		{Name: "basic_auth", Regexp: regexp.MustCompile(`(?:^|\s)(?:-u|--user)\s+["']?[^\s:"']+:(?P<secret>[^\s"']+)`)},
		{Name: "basic_auth", Regexp: regexp.MustCompile(`(?i)authorization\\?["']?\s*[:=]\s*\\?["']?basic\s+(?P<secret>[A-Za-z0-9+/]{8,}={0,2})`)},
	}
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
