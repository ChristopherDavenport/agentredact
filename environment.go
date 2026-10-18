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
// says nothing of the file system: kind (local, container or remote)
// is kept, and the rest, ref and the members the format leaves to the
// harness, such as a host, becomes ref "[REDACTED workspace <n>]", n
// counting the distinct workspaces the original's env entries name, in
// file order, from 1. Two env entries naming one workspace name one
// placeholder, and two naming different ones different placeholders,
// so a reader still sees where a session moved to another file system.
// An absent workspace stays absent. An env entry so blanked is valid:
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
	env.CWD, env.VCS, env.Files, env.Tools, env.Unknown = "", nil, nil, nil, nil
	ws, err := workspacePlaceholder(c)
	if err != nil {
		return nil, err
	}
	env.Workspace = ws
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

// workspacePlaceholder is the workspace the entry at c's position is
// written with: nil for an absent one, and otherwise its kind and the
// ordinal of its canonical form among the distinct workspaces the
// original's env entries name up to it.
func workspacePlaceholder(c *EntryContext) (*agentsession.Workspace, error) {
	own, _ := c.Entry().(*agentsession.EnvEntry)
	if own == nil || absentWorkspace(own.Workspace) {
		return nil, nil
	}
	var seen [][]byte
	for _, e := range c.Order[:c.Position] {
		env, ok := e.(*agentsession.EnvEntry)
		if !ok || absentWorkspace(env.Workspace) {
			continue
		}
		key, err := canonicalJSON(env.Workspace)
		if err != nil {
			return nil, fmt.Errorf("agentredact: environment: workspace of %s: %w", e.Base().ID, err)
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
		if e == own {
			return &agentsession.Workspace{Kind: own.Workspace.Kind, Ref: fmt.Sprintf("[REDACTED workspace %d]", n)}, nil
		}
	}
	return nil, fmt.Errorf("agentredact: environment: entry %s is not at position %d of the original", own.ID, c.Position)
}

// absentWorkspace reports whether w is no workspace, as the
// substitution rule reads one: nil, or no kind, ref or other member.
func absentWorkspace(w *agentsession.Workspace) bool {
	return w == nil || w.Kind == "" && w.Ref == "" && len(w.Unknown) == 0
}

// canonicalJSON encodes v with every object's members sorted, so two
// equal values give equal bytes.
func canonicalJSON(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	return json.Marshal(tree)
}
