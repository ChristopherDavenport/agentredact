package agentredact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ChristopherDavenport/agentsession"
)

// Environment blanks what an env entry records of the machine it ran
// on, and the header's cwd. Of an env entry it removes:
//
//   - cwd, the working directory;
//   - vcs, the revision, whether the tree was dirty, and any tree
//     identity a harness recorded in it;
//   - files, the paths read and written and their content hashes,
//     which would let anyone holding a guessed file confirm it;
//   - tools, the tool versions installed;
//   - every member the format does not define, a harness's namespaced
//     members among them;
//   - the normalised records of those members, which hold their
//     original text.
//
// It keeps the envelope, legacy_id, and workspace in a form that keeps
// substitutions (RFC 0001, env) as the original recorded them, but
// says nothing of the file system: kind (local, container or remote),
// as the string redactors left it, is kept, and the rest, ref and the
// members the format leaves to the harness, such as a host, becomes ref
// "[REDACTED workspace <n>]", n counting from 1 the distinct workspaces
// the env entries on the entry's path name, root first, compared in
// canonical form (members sorted, numbers by value, so 1 and 1.0 are
// one). Along a path, two env entries naming one workspace name one
// placeholder, and two naming different ones different placeholders, so
// a reader still sees where a session moved to another file system; and
// since only the path counts, a fork and its origin number their shared
// prefix alike. An absent workspace stays absent. An env entry so blanked is valid:
// every member of one is optional.
//
// It changes no other entry.
func Environment() EntryRedactor { return environment{} }

type environment struct{}

func (environment) Name() string { return "environment" }

// RedactHeader blanks the header's cwd.
func (environment) RedactHeader(h *agentsession.Header) error {
	h.CWD = ""
	return nil
}

func (environment) RedactEntry(c *EntryContext, e agentsession.Entry) (agentsession.Entry, error) {
	env, ok := e.(*agentsession.EnvEntry)
	if !ok {
		return e, nil
	}
	blanked := map[string]bool{"cwd": true, "vcs": true, "files": true, "tools": true, "workspace": true}
	for k := range env.Unknown {
		blanked[k] = true
	}
	kind := ""
	if env.Workspace != nil {
		kind = env.Workspace.Kind // as the string redactors left it
	}
	env.CWD, env.VCS, env.Files, env.Tools, env.Unknown = "", nil, nil, nil, nil
	n, err := workspaceOrdinal(c)
	if err != nil {
		return nil, err
	}
	env.Workspace = nil
	if n > 0 {
		env.Workspace = &agentsession.Workspace{Kind: kind, Ref: fmt.Sprintf("[REDACTED workspace %d]", n)}
	}
	if len(env.Normalised) > 0 {
		var kept []agentsession.Normalisation
		for _, n := range env.Normalised {
			if !blanked[firstToken(n.At)] {
				kept = append(kept, n)
			}
		}
		env.Normalised = kept
	}
	return env, nil
}

// firstToken returns the member name an RFC 6901 pointer starts with.
func firstToken(at string) string {
	t, _, _ := strings.Cut(strings.TrimPrefix(at, "/"), "/")
	return strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
}

// workspaceOrdinal is the number the workspace of the original entry
// at c's position is written with: 0 for an absent one, and otherwise
// the ordinal of its canonical form among the distinct workspaces the
// env entries on the entry's path name, root first.
func workspaceOrdinal(c *EntryContext) (int, error) {
	own, _ := c.Entry().(*agentsession.EnvEntry)
	if own == nil || absentWorkspace(own.Workspace) {
		return 0, nil
	}
	var seen [][]byte
	for _, e := range c.Path() {
		env, ok := e.(*agentsession.EnvEntry)
		if !ok || absentWorkspace(env.Workspace) {
			continue
		}
		key, err := canonicalJSON(env.Workspace)
		if err != nil {
			return 0, fmt.Errorf("agentredact: environment: workspace at position %d: %w", c.Position, err)
		}
		n := 0
		for i, k := range seen {
			if bytes.Equal(k, key) {
				n = i + 1
				break
			}
		}
		if n == 0 {
			seen = append(seen, key)
			n = len(seen)
		}
		if e.Base().ID == own.ID {
			return n, nil
		}
	}
	return 0, fmt.Errorf("agentredact: environment: the entry at position %d is not on its own path", c.Position)
}

// absentWorkspace reports whether w is no workspace, as the
// substitution rule reads one: nil, or no kind, ref or other member.
func absentWorkspace(w *agentsession.Workspace) bool {
	return w == nil || w.Kind == "" && w.Ref == "" && len(w.Unknown) == 0
}

// canonicalJSON encodes v with every object's members sorted and every
// number written by its value as JCS writes it (encoding/json writes a
// float64 as ES6 does), so two values RFC 0001 compares equal give
// equal bytes: 1 and 1.0 are one number.
func canonicalJSON(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(data, &tree); err != nil {
		return nil, err
	}
	return json.Marshal(tree)
}
