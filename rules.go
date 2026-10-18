package agentredact

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// DefaultRuleReplacement is what a rule that names no replacement
// writes, as git-filter-repo's --replace-text does.
const DefaultRuleReplacement = "***REMOVED***"

// ErrRules is wrapped by every error [ParseRules] returns for a rules
// file it refuses, beside the line number.
var ErrRules = errors.New("agentredact: malformed rules")

// rule is one parsed line: a literal or a regex, and its replacement.
type rule struct {
	literal string
	re      *regexp.Regexp
	// repl is a literal's replacement, or a regex's template parsed.
	repl     string
	template []templatePart
}

// templatePart is a piece of a regex replacement: literal text, or the
// text of a group, by index (group >= 0) or by name.
type templatePart struct {
	text  string
	group int
	name  string
}

// ParseRules reads a rules file in git-filter-repo's --replace-text
// format and returns the redactor it describes. Each line is one rule:
//
//	p455w0rd                     the literal, replaced with ***REMOVED***
//	foo==>bar                    the literal foo, replaced with bar
//	literal:MM/DD/YYYY==>X       the literal after "literal:"
//	regex:\bdriver\b==>pilot     a regular expression
//	glob:*666*==>                a glob, here replaced with nothing
//
// As filter-repo reads it: lines are split on LF, and a CR before the
// LF is trimmed; the replacement is what follows the last "==>" on the
// line, and a line without one is replaced with
// [DefaultRuleReplacement]; a "regex:" or "glob:" prefix makes the rest
// a pattern and a "literal:" prefix, or none, a literal; a blank line is
// skipped; whitespace inside a line, trailing whitespace included, is
// part of the rule, so "sk-abc " matches only with the space. filter-repo
// has no comment syntax in this file, unlike in its --paths-from-file,
// so neither has this: a line starting with "#" is a literal and
// replaces every "#" it matches. Every literal is applied, in file
// order, before every pattern, in file order, as filter-repo applies
// them, each to what the rules before it left.
//
// Where filter-repo would read a file in a way no one means, this
// refuses or repairs it instead: a leading UTF-8 byte order mark, which
// Windows editors write and which would make the first rule never
// match, is dropped; a line of whitespace alone, which would replace
// every space, and a CR not followed by LF, which in a file of bare-CR
// line endings would make the whole file one literal, are errors.
//
// Where filter-repo uses Python, this uses Go:
//
//   - A regex is Go's RE2 syntax, which shares Python's common
//     constructs, (?P<name>...) and (?m) among them; one Go cannot
//     compile, a lookaround or a backreference, is an error. Two that Go
//     compiles but reads otherwise are errors too: {,n}, which Python
//     reads as 0 to n and Go as the text itself, and a POSIX class such
//     as [[:alpha:]], which Python reads as a plain set.
//   - Differences that remain: without (?m), $ matches in Go only at
//     the very end of the string, and in Python also before a final
//     newline, so regex:token \S+$ misses "token abc\n" here; . and a
//     class match one character, where filter-repo, which reads bytes,
//     matches one byte; and an empty match just after another match is
//     replaced in Python 3.7 and later, not in Go.
//   - A regex's replacement takes Python's group references, \1 to \99,
//     \g<n> (n digits alone) and \g<name>, and the escapes \\, \n, \t,
//     \r, \f, \v, \a and \b. An octal escape, \0 or three octal digits
//     such as \101, which Python reads as a character, is an error, as
//     is a backslash before any other ASCII letter or digit; before
//     anything else the backslash stays as written. A literal's
//     replacement is taken as written.
//   - A glob is translated as Python's fnmatch.translate does, without
//     its anchors, as filter-repo strips them: * is any run of
//     characters but a newline, ? one character but a newline, and
//     [...] a class, [!...] a negated one; an unclosed [ is the
//     character itself.
//
// Each of these is an error naming the line, counted from 1, and
// wrapping [ErrRules]: a regex or a glob that does not compile, or uses
// a construct Go reads otherwise; a replacement template that does not
// parse or names a group the pattern does not have; a line that is not
// UTF-8, that holds a bare CR, or that is whitespace alone; and a line
// that is not blank but leaves nothing to match, such as "==>x",
// "literal:" or "regex:==>x". filter-repo skips an empty literal and
// reads an empty "regex:" as the literal text "regex:"; a rule silently
// dropped is a value passed, so here both are refused.
func ParseRules(r io.Reader) (StringRedactor, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("agentredact: reading rules: %w", err)
	}
	var literals, regexes []rule
	data = bytes.TrimPrefix(data, []byte("\ufeff"))
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1] // the newline ending the last line
	}
	for i, raw := range lines {
		n := i + 1
		line := strings.TrimSuffix(string(raw), "\r")
		if line == "" {
			continue
		}
		if !utf8.ValidString(line) {
			return nil, fmt.Errorf("%w: line %d is not UTF-8", ErrRules, n)
		}
		if strings.Contains(line, "\r") {
			return nil, fmt.Errorf("%w: line %d holds a carriage return not followed by a line feed", ErrRules, n)
		}
		if strings.TrimSpace(line) == "" {
			return nil, fmt.Errorf("%w: line %d is whitespace alone, which would replace every space", ErrRules, n)
		}
		match, repl := line, DefaultRuleReplacement
		if j := strings.LastIndex(line, "==>"); j >= 0 {
			match, repl = line[:j], line[j+len("==>"):]
		}
		var expr string
		switch {
		case strings.HasPrefix(match, "regex:"):
			expr = strings.TrimPrefix(match, "regex:")
			if expr == "" {
				return nil, fmt.Errorf("%w: line %d: an empty regex", ErrRules, n)
			}
			if err := readOtherwise(expr); err != nil {
				return nil, fmt.Errorf("%w: line %d: %v", ErrRules, n, err)
			}
		case strings.HasPrefix(match, "glob:"):
			g := strings.TrimPrefix(match, "glob:")
			if g == "" {
				return nil, fmt.Errorf("%w: line %d: an empty glob", ErrRules, n)
			}
			expr = globToRegex(g)
		default:
			lit := strings.TrimPrefix(match, "literal:")
			if lit == "" {
				return nil, fmt.Errorf("%w: line %d: nothing to match", ErrRules, n)
			}
			literals = append(literals, rule{literal: lit, repl: repl})
			continue
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrRules, n, err)
		}
		tmpl, err := parseTemplate(repl, re)
		if err != nil {
			return nil, fmt.Errorf("%w: line %d: replacement: %v", ErrRules, n, err)
		}
		regexes = append(regexes, rule{re: re, template: tmpl})
	}
	return func(s string) string {
		for _, l := range literals {
			s = strings.ReplaceAll(s, l.literal, l.repl)
		}
		for _, x := range regexes {
			s = x.apply(s)
		}
		return s
	}, nil
}

// apply replaces every match of the rule's regex in s with its
// template expanded.
func (x rule) apply(s string) string {
	matches := x.re.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		b.WriteString(s[last:m[0]])
		for _, p := range x.template {
			g := p.group
			if p.name != "" {
				g = x.re.SubexpIndex(p.name)
			}
			switch {
			case g < 0:
				b.WriteString(p.text)
			case m[2*g] >= 0:
				b.WriteString(s[m[2*g]:m[2*g+1]])
			}
		}
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// parseTemplate parses a Python re.sub replacement against re, whose
// groups its references must name.
func parseTemplate(t string, re *regexp.Regexp) ([]templatePart, error) {
	var (
		out []templatePart
		lit strings.Builder
	)
	flush := func() {
		if lit.Len() > 0 {
			out = append(out, templatePart{text: lit.String(), group: -1})
			lit.Reset()
		}
	}
	group := func(g int) error {
		if g > re.NumSubexp() {
			return fmt.Errorf("group %d, but the pattern has %d", g, re.NumSubexp())
		}
		flush()
		out = append(out, templatePart{group: g})
		return nil
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c != '\\' {
			lit.WriteByte(c)
			continue
		}
		if i+1 >= len(t) {
			return nil, errors.New("a trailing backslash")
		}
		i++
		c = t[i]
		switch {
		case c == 'g':
			if i+1 >= len(t) || t[i+1] != '<' {
				return nil, errors.New(`\g without <`)
			}
			end := strings.IndexByte(t[i+2:], '>')
			if end < 0 {
				return nil, errors.New(`\g< without >`)
			}
			ref := t[i+2 : i+2+end]
			i += 2 + end
			if ref == "" {
				return nil, errors.New(`an empty \g<>`)
			}
			if allDigits(ref) {
				g, err := strconv.Atoi(ref)
				if err != nil {
					return nil, fmt.Errorf(`\g<%s>: %v`, ref, err)
				}
				if err := group(g); err != nil {
					return nil, err
				}
				continue
			}
			if re.SubexpIndex(ref) < 0 {
				return nil, fmt.Errorf("no group named %q", ref)
			}
			flush()
			out = append(out, templatePart{name: ref, group: -1})
		case c == '0' || isOctal(c) && i+2 < len(t) && isOctal(t[i+1]) && isOctal(t[i+2]):
			return nil, errors.New("an octal escape, which Python reads as a character")
		case c >= '1' && c <= '9':
			g := int(c - '0')
			if i+1 < len(t) && t[i+1] >= '0' && t[i+1] <= '9' {
				i++
				g = g*10 + int(t[i]-'0')
			}
			if err := group(g); err != nil {
				return nil, err
			}
		case c == '\\':
			lit.WriteByte('\\')
		case c == 'n':
			lit.WriteByte('\n')
		case c == 't':
			lit.WriteByte('\t')
		case c == 'r':
			lit.WriteByte('\r')
		case c == 'f':
			lit.WriteByte('\f')
		case c == 'v':
			lit.WriteByte('\v')
		case c == 'a':
			lit.WriteByte('\a')
		case c == 'b':
			lit.WriteByte('\b')
		case isAlnum(c):
			return nil, fmt.Errorf(`the escape \%c`, c)
		default:
			lit.WriteByte('\\')
			lit.WriteByte(c)
		}
	}
	flush()
	return out, nil
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// readOtherwise refuses a regex holding a construct Go compiles but
// reads otherwise than Python: {,n} outside a class, and a POSIX class
// [:name:] inside one. Escaped characters are skipped, and a ] first in
// a class is a member of it.
func readOtherwise(expr string) error {
	inClass, first := false, 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c == '\\' {
			i++
			continue
		}
		if inClass {
			switch {
			case c == '[' && i+1 < len(expr) && expr[i+1] == ':':
				return errors.New("a POSIX class [:name:], which Python reads as a plain set")
			case c == ']' && i > first:
				inClass = false
			}
			continue
		}
		switch c {
		case '[':
			inClass, first = true, i+1
			if first < len(expr) && expr[first] == '^' {
				first++
			}
		case '{':
			if i+1 < len(expr) && expr[i+1] == ',' {
				return errors.New("{,n}, which Python reads as 0 to n and Go as the text itself")
			}
		}
	}
	return nil
}

// globToRegex translates a glob as Python's fnmatch.translate does,
// without the anchors and the dot-all flag git-filter-repo strips.
func globToRegex(g string) string {
	var b strings.Builder
	for i := 0; i < len(g); {
		c := g[i]
		switch c {
		case '*':
			for i < len(g) && g[i] == '*' {
				i++
			}
			b.WriteString(".*")
			continue
		case '?':
			b.WriteString(".")
		case '[':
			j := i + 1
			if j < len(g) && g[j] == '!' {
				j++
			}
			if j < len(g) && g[j] == ']' {
				j++
			}
			for j < len(g) && g[j] != ']' {
				j++
			}
			if j >= len(g) {
				b.WriteString(`\[`)
				break
			}
			stuff := g[i+1 : j]
			i = j + 1
			switch {
			case stuff == "":
				b.WriteString(`[^\x00-\x{10FFFF}]`) // an empty class never matches
			case stuff == "!":
				b.WriteString(".")
			default:
				b.WriteString("[")
				if stuff[0] == '!' {
					b.WriteString("^")
					stuff = stuff[1:]
				}
				for k := 0; k < len(stuff); k++ {
					switch ch := stuff[k]; ch {
					case '\\', '[', ']', '^', '&', '~', '|':
						b.WriteByte('\\')
						b.WriteByte(ch)
					default:
						b.WriteByte(ch)
					}
				}
				b.WriteString("]")
			}
			continue
		default:
			r, size := utf8.DecodeRuneInString(g[i:])
			b.WriteString(regexp.QuoteMeta(string(r)))
			i += size
			continue
		}
		i++
	}
	return b.String()
}
