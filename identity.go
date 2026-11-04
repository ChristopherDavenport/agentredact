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
	"github.com/ChristopherDavenport/openresponses"
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
	// Anywhere reads every string of the entry, at any depth, rather than
	// the member Pointer names; it needs Extract.
	Anywhere bool
	// Extract, when set, harvests its matches in the member's string
	// rather than the string, as a member holding a sentence names an
	// email address in it; of a pattern with groups, each group a match
	// fills.
	Extract *regexp.Regexp
	// Commands harvests what a call running whoami, hostname, uname -n
	// or id -un printed: the lines of its output, paired with the call by
	// its call_id, that are one name each. Pointer and Extract are not
	// read.
	Commands bool
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
	return append([]IdentityMember{
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
	}, TextIdentity()...)
}

// promptPattern finds the login and host names a shell prompt writes,
// login@host:~ or login@host:/path.
var promptPattern = regexp.MustCompile(`(?:^|[\s"'(\[>])([a-z_][a-z0-9_-]{1,31})@([A-Za-z0-9][A-Za-z0-9-]{0,62}):(?:~|/)`)

// More prompt shapes: [login@host dir]$ and login@host dir %.
var (
	bracketPrompt = regexp.MustCompile(`\[([a-z_][a-z0-9_-]{1,31})@([A-Za-z0-9][A-Za-z0-9.-]{0,62})[ :][^\]\n]*\][$#%]`)
	spacePrompt   = regexp.MustCompile(`(?m)(?:^|[\s"'])([a-z_][a-z0-9_-]{1,31})@([A-Za-z0-9][A-Za-z0-9-]{0,62}) [~/][^\s]* ?[%$#]`)
	// idPattern finds the names id prints: uid=1000(name) gid=...(group).
	idPattern = regexp.MustCompile(`\b(?:uid|gid|groups)=[0-9]+\(([^)\s]+)\)`)
	// gitAuthor finds the names and emails git log and git show print.
	gitAuthor = regexp.MustCompile(`(?m)^\s*(?:Author|Commit|Committer):\s+([^<\n]+?)\s+<([^>\s]+@[^>\s]+)>`)
	// transcriptCommand finds a shell transcript's whoami, hostname or
	// uname -n and the name it printed on the next line.
	transcriptCommand = regexp.MustCompile(`(?m)\$ (?:whoami|hostname|uname -n|id -un)\s*\n([A-Za-z0-9_.-]{2,64})\s*$`)
	// identityCommand finds, in a call's arguments, a command printing a
	// login or host name.
	identityCommand = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(?:whoami|hostname|uname -n|id -un)(?:$|[^A-Za-z0-9_-])`)
	// oneName is an output line that is a single login or host name.
	oneName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{1,63}$`)
)

// lsPattern finds the owner and group names an ls -l listing writes.
var lsPattern = regexp.MustCompile(`(?m)^[-dlcbps][rwxsStT-]{9}[.+@]?\s+[0-9]+\s+([A-Za-z_][A-Za-z0-9_.-]*)\s+([A-Za-z_][A-Za-z0-9_.-]*)\s+[0-9]`)

// TextIdentity is the identity members any session's text carries
// whatever wrote it: the login and host names a shell prompt writes,
// the owner and group names an ls -l listing writes, the names id prints,
// git's author and committer names and emails, what whoami, hostname and
// uname -n printed (in a transcript, or as a call's output), and the
// host an env entry's workspace names. A system account's name (root, nobody
// and the like) is never harvested.
func TextIdentity() []IdentityMember {
	return []IdentityMember{
		{Type: agentsession.TypeEnv, Pointer: "/workspace/host"},
		{Anywhere: true, Extract: promptPattern},
		{Anywhere: true, Extract: lsPattern},
		{Anywhere: true, Extract: bracketPrompt},
		{Anywhere: true, Extract: spacePrompt},
		{Anywhere: true, Extract: idPattern},
		{Anywhere: true, Extract: gitAuthor},
		{Anywhere: true, Extract: transcriptCommand},
		{Commands: true},
	}
}

// systemNames are account and group names no one is identified by.
var systemNames = map[string]bool{
	"root": true, "nobody": true, "nogroup": true, "daemon": true, "bin": true, "sys": true, "adm": true,
	"wheel": true, "staff": true, "users": true, "admin": true, "www-data": true, "syslog": true,
	"docker": true, "sudo": true, "messagebus": true, "localhost": true, "ubuntu": true,
}

// minIdentity is the shortest value harvested: a shorter one would match
// too much text to replace or to report.
const minIdentity = 3

// validate reports whether m can be read.
func (m IdentityMember) validate() error {
	if m.Anywhere && m.Extract == nil && !m.Commands {
		return fmt.Errorf("agentredact: an identity member read anywhere needs an Extract pattern")
	}
	if m.Pointer != "" && !strings.HasPrefix(m.Pointer, "/") {
		return fmt.Errorf("agentredact: identity member pointer %q does not start with /", m.Pointer)
	}
	return nil
}

// identities is the set of identity values a redaction has harvested,
// and their spellings, matched without regard to ASCII case.
type identities struct {
	values map[string]bool
	// calls are the calls, by call_id, whose output prints a name.
	calls map[string]bool
	// spellings maps each spelling, lowercased, to its value; order holds
	// them longest first, then in byte order.
	spellings map[string]string
	order     []string
}

func newIdentities() *identities {
	return &identities{values: map[string]bool{}, spellings: map[string]string{}, calls: map[string]bool{}}
}

// clone is a copy of ids, so a fork continues its origin's set without
// changing it.
func (ids *identities) clone() *identities {
	c := newIdentities()
	for v := range ids.values {
		c.add(v)
	}
	for id := range ids.calls {
		c.calls[id] = true
	}
	return c
}

// add adds v and its spellings, unless it is too short.
func (ids *identities) add(v string) {
	if len(v) < minIdentity || ids.values[v] || systemNames[strings.ToLower(v)] || strings.HasPrefix(v, "systemd-") || strings.HasPrefix(v, "_") {
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
		if m.Commands {
			ids.commands(e)
			continue
		}
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

// commands remembers a call that runs a command printing a name, and
// harvests the names its output prints.
func (ids *identities) commands(e agentsession.Entry) {
	it, ok := e.(*agentsession.ItemEntry)
	if !ok {
		return
	}
	switch v := it.Item.(type) {
	case *openresponses.FunctionCall:
		if identityCommand.MatchString(v.Arguments) {
			ids.calls[v.CallID] = true
		}
	case *openresponses.FunctionCallOutput:
		if !ids.calls[v.CallID] {
			return
		}
		data, err := json.Marshal(v)
		if err != nil {
			return
		}
		var tree any
		if tree, err = decodeTree(data); err != nil {
			return
		}
		for _, s := range allStrings(tree, nil) {
			for _, line := range strings.Split(s, "\n") {
				if line = strings.TrimSpace(line); oneName.MatchString(line) && line != v.CallID && line != "function_call_output" {
					ids.add(line)
				}
			}
		}
	}
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
	var strs []string
	if m.Anywhere {
		strs = allStrings(tree, nil)
	} else {
		strs = pointed(tree, tokens)
	}
	for _, s := range strs {
		switch {
		case m.Extract != nil && m.Extract.NumSubexp() > 0:
			for _, ms := range m.Extract.FindAllStringSubmatch(s, -1) {
				for _, g := range ms[1:] {
					ids.add(g)
				}
			}
		case m.Extract != nil:
			for _, v := range m.Extract.FindAllString(s, -1) {
				ids.add(v)
			}
		case m.Home:
			for _, h := range homesIn(s) {
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

// homesPattern finds a home directory anywhere in a string: /home/<name>,
// /Users/<name>, <drive>:\Users\<name>, /mnt/<drive>/Users/<name> and
// \\wsl.localhost\<distro>\home\<name> or \\wsl$\..., in any of the
// separators a path or its JSON spelling writes.
var homesPattern = regexp.MustCompile(`(?:(?:\\\\|\\){2}wsl(?:\.localhost|\$)(?:\\\\|\\)[^\\/\s"']+(?:\\\\|\\)home(?:\\\\|\\)[^\\/\s"']+|/mnt/[A-Za-z]/Users/[^\\/\s"']+|[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/)[^\\/\s"']+|/home/[^\\/\s"']+|/Users/[^\\/\s"']+)`)

// homesIn are the home directories named in s, anywhere in it.
func homesIn(s string) []string {
	return homesPattern.FindAllString(s, -1)
}

// allStrings appends to out every string in v, member names aside.
func allStrings(v any, out []string) []string {
	switch x := v.(type) {
	case string:
		out = append(out, x)
	case []any:
		for _, c := range x {
			out = allStrings(c, out)
		}
	case map[string]any:
		for _, k := range sortedMembers(x) {
			out = allStrings(x[k], out)
		}
	}
	return out
}
