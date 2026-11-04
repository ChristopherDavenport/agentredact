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
	spacePrompt   = regexp.MustCompile(`(?m)(?:^|[\s"'])([a-z_][a-z0-9_-]{1,31})@([A-Za-z0-9][A-Za-z0-9-]{0,62}) [^\s@]+ ?[%$#](?:\s|$)`)
	// idPattern finds the names id prints: uid=1000(name) gid=...(group).
	idPattern = regexp.MustCompile(`\b(?:uid|gid|groups)=[0-9]+\(([^)\s]+)\)`)
	// gitAuthor finds the names and emails git log and git show print.
	gitAuthor = regexp.MustCompile(`(?m)^\s*(?:Author|Commit|Committer):\s+([^<\n]+?)\s+<([^>\s]+@[^>\s]+)>`)
	// transcriptCommand finds a shell transcript's whoami, hostname or
	// uname -n and the name it printed on the next line.
	transcriptCommand = regexp.MustCompile(`(?m)\$ (?:whoami|hostname|uname -n|id -un)\s*\n([A-Za-z0-9_.-]{2,64})\s*$`)
	// oneName is an output line that is a single login or host name.
	oneName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{1,63}$`)
)

// identityCommands is how many commands the call's arguments run first
// that each print a login or host name alone (whoami, hostname, uname
// -n, id -un, joined by && or ;): their output is the output's first
// lines, one each. What any other command prints, a listing's file
// names among it, is never taken for the user's.
func identityCommands(arguments string) int {
	cmd := arguments
	var a struct {
		Command any `json:"command"`
	}
	if json.Unmarshal([]byte(arguments), &a) == nil && a.Command != nil {
		switch c := a.Command.(type) {
		case string:
			cmd = c
		case []any:
			var parts []string
			for _, p := range c {
				if s, ok := p.(string); ok {
					parts = append(parts, s)
				}
			}
			cmd = strings.Join(parts, " ")
			// bash -c, bash -lc (as Codex runs a command), sh -c, zsh -c.
			if len(parts) == 3 && (parts[0] == "bash" || parts[0] == "sh" || parts[0] == "zsh") && shellCommandFlag.MatchString(parts[1]) {
				cmd = parts[2]
			}
		}
	}
	n := 0
	for _, part := range commandSeparator.Split(cmd, -1) {
		switch strings.Join(strings.Fields(part), " ") {
		case "":
		case "whoami", "hostname", "uname -n", "id -un", "id -u -n":
			n++
		default:
			return n // what follows prints what it likes, after these
		}
	}
	return n
}

// shellCommandFlag is a shell's flags ending in the one that takes the
// command: -c, -lc, -ic.
var shellCommandFlag = regexp.MustCompile(`^-[a-z]*c$`)

// commandSeparator splits a shell command into its commands.
var commandSeparator = regexp.MustCompile(`&&|;|\n`)

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
	"wheel": true, "staff": true, "users": true, "admin": true, "administrator": true, "www-data": true,
	"syslog": true, "docker": true, "sudo": true, "messagebus": true, "localhost": true, "ubuntu": true,
	"debian": true, "runner": true, "git": true, "host": true, "hostname": true, "server": true,
	"machine": true, "computer": true, "guest": true, "test": true, "tester": true, "default": true,
	"codespace": true, "vscode": true, "node": true, "app": true, "build": true, "builder": true,
	"actions": true, "web-flow": true, "noreply": true, "example": true, "name": true, "username": true,
	"me": true, "you": true, "your-name": true, "yourname": true, "dev": true, "ec2-user": true,
	"centos": true, "fedora": true, "alpine": true, "kali": true, "pi": true, "raspberrypi": true,
}

// generic reports whether v names no one: a role or other word of the
// format's vocabulary, which the Rewriter hands the string redactors
// with the text (an item's role among them), a system or service
// account, a host every machine has, a forge and its bots, or a no-reply
// address. Harvested, any of them would be replaced across the session,
// corrupting roles and URLs.
func generic(v string) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	if systemNames[l] || vocabulary[l] || strings.HasPrefix(l, "systemd-") || strings.HasPrefix(l, "_") {
		return true
	}
	for _, p := range []string{"github", "gitlab", "bitbucket", "dependabot", "renovate"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	if local, domain, ok := strings.Cut(l, "@"); ok {
		return strings.Contains(local, "noreply") || strings.Contains(local, "no-reply") || !strings.Contains(domain, ".") ||
			strings.HasSuffix(domain, ".local") || domain == "localhost.localdomain"
	}
	return false
}

// vocabulary are words of the format and the payload a string redactor
// is handed as text where the format defines them: roles, item and
// content types, statuses. No identity value is one, so none is ever
// replaced.
var vocabulary = map[string]bool{
	"user": true, "assistant": true, "system": true, "developer": true, "tool": true, "function": true,
	"message": true, "function_call": true, "function_call_output": true, "reasoning": true,
	"input_text": true, "output_text": true, "input_image": true, "input_file": true, "refusal": true,
	"completed": true, "incomplete": true, "in_progress": true, "failed": true,
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
	// calls are the calls, by call_id, whose output prints names, and how
	// many.
	calls map[string]int
	// spellings maps each spelling, lowercased, to its value; order holds
	// them longest first, then in byte order.
	spellings map[string]string
	order     []string
}

func newIdentities() *identities {
	return &identities{values: map[string]bool{}, spellings: map[string]string{}, calls: map[string]int{}}
}

// clone is a copy of ids, so a fork continues its origin's set without
// changing it.
func (ids *identities) clone() *identities {
	c := newIdentities()
	for v := range ids.values {
		c.add(v)
	}
	for id, n := range ids.calls {
		c.calls[id] = n
	}
	return c
}

// add adds v and its spellings, unless it is too short.
func (ids *identities) add(v string) {
	if len(v) < minIdentity || ids.values[v] || generic(v) {
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
	if vocabulary[s] {
		return s // a role or a type, which the Rewriter hands over as text
	}
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
		if n := identityCommands(v.Arguments); n > 0 {
			ids.calls[v.CallID] = n
		}
	case *openresponses.FunctionCallOutput:
		n := ids.calls[v.CallID]
		if n == 0 {
			return
		}
		data, err := json.Marshal(v)
		if err != nil {
			return
		}
		var out struct {
			Output string `json:"output"`
		}
		if json.Unmarshal(data, &out) != nil {
			return
		}
		// The first n lines are what the n commands printed, one name
		// each; anything after them is not taken.
		lines := strings.Split(strings.TrimSpace(out.Output), "\n")
		if len(lines) < n {
			return
		}
		for _, line := range lines[:n] {
			if line = strings.TrimSpace(line); oneName.MatchString(line) {
				ids.add(line)
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

// spacedHomes finds a home whose name holds spaces, up to the separator
// that must follow it, as a macOS or Windows name often does.
var spacedHomes = regexp.MustCompile(`(?:/mnt/[A-Za-z]/Users|/Users|/home|[A-Za-z]:(?:\\\\|\\|/)Users)(?:\\\\|\\|/)[^\\/\r\n"']+ [^\\/\r\n"']+(?:\\|/|$|["'\r\n])`)

// homesIn are the home directories named in s, anywhere in it.
func homesIn(s string) []string {
	out := homesPattern.FindAllString(s, -1)
	for _, h := range spacedHomes.FindAllString(s, -1) {
		out = append(out, strings.TrimRight(h, "/\\\"'\r\n"))
	}
	return out
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
