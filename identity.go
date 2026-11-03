package agentredact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/ChristopherDavenport/agentsession"
)

// IdentityMember names a member of a converted session that holds a
// value identifying the user: an account's email, an organization's ID,
// a login name, a home directory. A converter documents its identity
// members (RFC 0001, Conformance; agentimport's format docs and its
// agentimport/identity report), and a profile lists the ones it
// redacts ([Profile.Identity]): the profile names where the values are,
// never the values, which are read from each original and appear in no
// profile, report or error.
type IdentityMember struct {
	// Header says the member is the header's; Type and NS are then not
	// read.
	Header bool
	// Type is the type of the entries holding it, such as "custom",
	// "item" or "env"; "" for any.
	Type string
	// NS is the namespace of the custom entries holding it; "" for any.
	NS string
	// Pointer is an RFC 6901 JSON Pointer into the entry, or the header,
	// as a file writes it, in which a token "*" stands for every element
	// of an array or member of an object.
	Pointer string
	// Extract, when set, harvests its matches in the member's string
	// rather than the string, as a member holding a sentence names an
	// email address in it.
	Extract *regexp.Regexp
	// Home says the member holds a path, of which the home directory it
	// starts with, /home/<name>, /Users/<name> or <drive>:\Users\<name>,
	// is harvested: a working directory names the user through it.
	Home bool
}

// emailPattern matches an email address, for a member that names one in
// a sentence.
var emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

// ClaudeCodeIdentity is the identity members agentimport v0.0.1's
// Claude Code converter documents (docs/formats/claudecode.md, Identity)
// as they land in the converted session: the working directory, which
// names the home directory, in the header, the env entries and every
// line kept in a custom entry; the organization's UUID of a
// credential_org attachment; the account's email in a session_context
// attachment; the login name and home directory in an api-request
// record's classifier context; the native sub-agent ID; and the home
// directory through an instructions layer's file path. The native
// session ID, the header's id, is rewritten wherever text quotes it by
// every redaction (RFC 0001 0.19), so it is not listed.
func ClaudeCodeIdentity() []IdentityMember {
	return []IdentityMember{
		{Header: true, Pointer: "/cwd", Home: true},
		{Header: true, Pointer: "/agentimport:source/native_id"},
		{Type: agentsession.TypeEnv, Pointer: "/cwd", Home: true},
		{Type: agentsession.TypeCustom, NS: "claudecode", Pointer: "/data/cwd", Home: true},
		{Type: agentsession.TypeCustom, NS: "claudecode", Pointer: "/data/attachment/organizationUuid"},
		{Type: agentsession.TypeCustom, NS: "claudecode", Pointer: "/data/params/safeguards/*/classifier_context/user_identity"},
		{Type: agentsession.TypeCustom, NS: "claudecode", Pointer: "/data/params/safeguards/*/classifier_context/home_dir"},
		{Type: agentsession.TypeItem, Pointer: "/claudecode:attachment/context/userEmail", Extract: emailPattern},
		{Type: agentsession.TypeItem, Pointer: "/instructions_part/id", Home: true},
		{Type: agentsession.TypeItem, Pointer: "/instructions_part/*/id", Home: true},
	}
}

// minIdentity is the shortest value harvested: a shorter one would match
// too much text to replace or to report.
const minIdentity = 3

// validate reports whether m can be read.
func (m IdentityMember) validate() error {
	if m.Pointer != "" && !strings.HasPrefix(m.Pointer, "/") {
		return fmt.Errorf("agentredact: identity member pointer %q does not start with /", m.Pointer)
	}
	return nil
}

// identities is the set of identity values a redaction has harvested,
// and their spellings, matched without regard to ASCII case.
type identities struct {
	values map[string]bool
	// spellings maps each spelling, lowercased, to its value; order holds
	// them longest first, then in byte order.
	spellings map[string]string
	order     []string
}

func newIdentities() *identities {
	return &identities{values: map[string]bool{}, spellings: map[string]string{}}
}

// clone is a copy of ids, so a fork continues its origin's set without
// changing it.
func (ids *identities) clone() *identities {
	c := newIdentities()
	for v := range ids.values {
		c.add(v)
	}
	return c
}

// add adds v and its spellings, unless it is too short.
func (ids *identities) add(v string) {
	if len(v) < minIdentity || ids.values[v] {
		return
	}
	ids.values[v] = true
	for _, sp := range spellingsOf(v) {
		key := asciiLower(sp)
		if _, ok := ids.spellings[key]; ok || len(key) < minIdentity {
			continue
		}
		ids.spellings[key] = v
		ids.order = append(ids.order, key)
	}
	sort.Slice(ids.order, func(i, j int) bool {
		if len(ids.order[i]) != len(ids.order[j]) {
			return len(ids.order[i]) > len(ids.order[j])
		}
		return ids.order[i] < ids.order[j]
	})
}

// spellingsOf are the forms a value takes in a session's text: as
// written; a path's dash-encoded directory name, with and without its
// leading dash, as a harness names a project; the Go module cache's
// escaping, '!' and the lowercase letter for each capital; and its URL
// encodings. Case is not a spelling: every one is matched without regard
// to ASCII case.
func spellingsOf(v string) []string {
	out := []string{v}
	if strings.ContainsAny(v, `/\`) {
		if d := dashEncoded(v); d != "" {
			out = append(out, d, strings.TrimPrefix(d, "-"))
		}
	}
	if strings.ToLower(v) != v {
		var b strings.Builder
		for _, r := range v {
			if r >= 'A' && r <= 'Z' {
				b.WriteByte('!')
				r += 'a' - 'A'
			}
			b.WriteRune(r)
		}
		out = append(out, b.String())
	}
	for _, e := range []string{url.QueryEscape(v), url.PathEscape(v)} {
		if e != v {
			out = append(out, e)
		}
	}
	return out
}

// asciiLower is s with ASCII capitals lowered, every byte in place, so
// an index in one is an index in the other.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// matches returns, in order and not overlapping, where s holds a
// spelling of a value standing on its own, no ASCII letter or digit
// beside it, and the value each names.
func (ids *identities) matches(s string) (spans [][2]int, values []string) {
	if ids == nil || len(ids.order) == 0 {
		return nil, nil
	}
	lower := asciiLower(s)
	taken := make([]bool, len(s))
	type hit struct {
		at    [2]int
		value string
	}
	var hits []hit
	for _, sp := range ids.order {
		for from := 0; from <= len(lower)-len(sp); {
			i := strings.Index(lower[from:], sp)
			if i < 0 {
				break
			}
			a, b := from+i, from+i+len(sp)
			from = b
			if a > 0 && isAlnum(s[a-1]) && isAlnum(s[a]) || b < len(s) && isAlnum(s[b]) && isAlnum(s[b-1]) {
				continue
			}
			free := true
			for k := a; k < b; k++ {
				if taken[k] {
					free = false
					break
				}
			}
			if !free {
				continue
			}
			for k := a; k < b; k++ {
				taken[k] = true
			}
			hits = append(hits, hit{at: [2]int{a, b}, value: ids.spellings[sp]})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].at[0] < hits[j].at[0] })
	for _, h := range hits {
		spans = append(spans, h.at)
		values = append(values, h.value)
	}
	return spans, values
}

// replace is s with every spelling of a value replaced by the value's
// placeholder, ph.For("identity", value).
func (ids *identities) replace(s string, ph *Placeholders) string {
	spans, values := ids.matches(s)
	if spans == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for i, sp := range spans {
		b.WriteString(s[last:sp[0]])
		b.WriteString(ph.For("identity", values[i]))
		last = sp[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// found reports whether s holds a spelling of a value.
func (ids *identities) found(s string) bool {
	spans, _ := ids.matches(s)
	return spans != nil
}

// harvestEntry adds the values members name in the original's entry e.
func (ids *identities) harvestEntry(members []IdentityMember, e agentsession.Entry) error {
	var tree any
	for _, m := range members {
		if m.Header || m.Type != "" && m.Type != e.EntryType() {
			continue
		}
		if m.NS != "" {
			c, ok := e.(*agentsession.CustomEntry)
			if !ok || c.NS != m.NS {
				continue
			}
		}
		if tree == nil {
			data, err := agentsession.MarshalEntry(e)
			if err != nil {
				return err
			}
			if tree, err = decodeTree(data); err != nil {
				return err
			}
		}
		ids.harvest(m, tree)
	}
	return nil
}

// harvestHeader adds the values members name in the header h.
func (ids *identities) harvestHeader(members []IdentityMember, h agentsession.Header) error {
	var tree any
	for _, m := range members {
		if !m.Header {
			continue
		}
		if tree == nil {
			data, err := json.Marshal(h)
			if err != nil {
				return err
			}
			if tree, err = decodeTree(data); err != nil {
				return err
			}
		}
		ids.harvest(m, tree)
	}
	return nil
}

func decodeTree(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var tree any
	err := dec.Decode(&tree)
	return tree, err
}

// harvest adds the values m names in tree.
func (ids *identities) harvest(m IdentityMember, tree any) {
	var tokens []string
	if m.Pointer != "" {
		for _, t := range strings.Split(m.Pointer[1:], "/") {
			tokens = append(tokens, strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~"))
		}
	}
	for _, s := range pointed(tree, tokens) {
		switch {
		case m.Extract != nil:
			for _, v := range m.Extract.FindAllString(s, -1) {
				ids.add(v)
			}
		case m.Home:
			if h := homeOf(s); h != "" {
				ids.add(h)
			}
		default:
			ids.add(s)
		}
	}
}

// pointed returns the strings at tokens in v, "*" taking every element
// or member.
func pointed(v any, tokens []string) []string {
	if len(tokens) == 0 {
		if s, ok := v.(string); ok {
			return []string{s}
		}
		return nil
	}
	t, rest := tokens[0], tokens[1:]
	var out []string
	switch x := v.(type) {
	case map[string]any:
		if t == "*" {
			for _, k := range sortedMembers(x) {
				out = append(out, pointed(x[k], rest)...)
			}
		} else if c, ok := x[t]; ok {
			out = pointed(c, rest)
		}
	case []any:
		for i, c := range x {
			if t == "*" || t == fmt.Sprint(i) {
				out = append(out, pointed(c, rest)...)
			}
		}
	}
	return out
}

// homePrefix matches the home directory a path starts with.
var homePrefix = regexp.MustCompile(`^(?:/home/[^/\\]+|/Users/[^/\\]+|[A-Za-z]:[/\\]Users[/\\][^/\\]+)`)

// homeOf is the home directory the path p starts with, or "".
func homeOf(p string) string {
	return homePrefix.FindString(p)
}
