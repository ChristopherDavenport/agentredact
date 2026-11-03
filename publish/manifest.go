package publish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/agentsession/atif"
	"github.com/ChristopherDavenport/agentsession/export"
)

// Manifest lists the redacted sessions a publication holds, as RFC 0002
// names them (Redacted sessions): each by its own ID and the hash of its
// head, never by an original's ID or entry hash, the mapping to
// originals staying with the holder of the key. It is deliberately
// minimal: the shape of a shared manifest object is agentsession#70's to
// define, and this one carries no more than that rule and what a
// dataset card needs (the profile, the judges and the replacement
// counts, which hold no value).
type Manifest struct {
	// Format names this shape: "agentredact/manifest@1".
	Format  string          `json:"format"`
	Profile string          `json:"profile"`
	Judges  []string        `json:"judges,omitempty"`
	Entries []ManifestEntry `json:"sessions"`
}

// ManifestEntry is one published session.
type ManifestEntry struct {
	// Session is the redacted session's own ID, and Head the hash of its
	// head entry, as published.
	Session string `json:"session"`
	Head    string `json:"head"`
	// Counts are the store pass's replacement counts by kind.
	Counts map[string]int `json:"counts,omitempty"`
}

// ManifestFormat is the format a Manifest names.
const ManifestFormat = "agentredact/manifest@1"

// NewManifest is the manifest of what res published under opts, with
// the counts the report holds for each session.
func NewManifest(res *Result, opts Options) Manifest {
	m := Manifest{Format: ManifestFormat, Profile: opts.Profile, Judges: slices.Clone(opts.Judges)}
	if !opts.Unjudged && len(m.Judges) == 0 {
		m.Judges = slices.Clone(DefaultJudges)
	}
	counts := map[string]map[string]int{}
	if opts.Report != nil {
		for _, r := range opts.Report.Sessions {
			counts[r.Redaction] = r.Counts
		}
	}
	for _, p := range res.Published {
		m.Entries = append(m.Entries, ManifestEntry{Session: p.Session, Head: p.Head, Counts: counts[p.Session]})
	}
	slices.SortFunc(m.Entries, func(a, b ManifestEntry) int { return strings.Compare(a.Session, b.Session) })
	return m
}

var (
	uuidShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hashShape = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ErrManifest is returned for a manifest that does not keep the naming
// rule.
var ErrManifest = errors.New("publish: manifest")

// Check holds m to the naming rule against the store st it describes:
// each session is a redacted session st holds, named by its derived ID
// ([agentsession.VerifiesAsRedacted]) and its current head; so no entry
// can name an original, whose header would not verify as redacted.
func (m Manifest) Check(ctx context.Context, st agentsession.Store) error {
	if m.Format != ManifestFormat {
		return fmt.Errorf("%w: format %q", ErrManifest, m.Format)
	}
	for _, e := range m.Entries {
		if !uuidShape.MatchString(e.Session) || !hashShape.MatchString(e.Head) {
			return fmt.Errorf("%w: a session is not named by a redacted ID and a head hash", ErrManifest)
		}
		s, err := read(ctx, st, e.Session)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrManifest, e.Session, err)
		}
		if !agentsession.VerifiesAsRedacted(s.Header()) {
			return fmt.Errorf("%w: %s is not a redacted session", ErrManifest, e.Session)
		}
		if s.Leaf() != e.Head {
			return fmt.Errorf("%w: %s's head is not the one listed", ErrManifest, e.Session)
		}
	}
	return nil
}

// ExportDataset writes the sessions m lists, read from the published
// store st, into dir as a dataset a host such as Hugging Face renders:
// for each session <id>/atif.json, its main trajectory's ATIF document
// with no passthrough (export.NoPassthrough), and <id>/trace.jsonl, the
// same path in the shape of Hugging Face's Session Trace Simple Format
// (a "session" line naming the harness and the ID, then a "message"
// line per step and per tool result: role, content, reasoningContent,
// toolCalls, toolCallId, model, timestamp), each sub-agent's in
// <id>/subagents/<n>.jsonl; then manifest.json and a README.md card
// saying what the data is and how it was cleaned. backstop, when not
// nil, is applied to every string of each document
// (export.RewriteStrings), as a last pass of the profile's rules. dir
// must not exist. Nothing is uploaded: that is the user's step.
func ExportDataset(ctx context.Context, st agentsession.Store, m Manifest, dir string, backstop func(string) string) error {
	if err := m.Check(ctx, st); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		return fmt.Errorf("publish: the dataset directory: %w", err)
	}
	for _, e := range m.Entries {
		s, err := read(ctx, st, e.Session)
		if err != nil {
			return err
		}
		if err := ownRedacted(s); err != nil {
			return fmt.Errorf("publish: %s: %w", e.Session, err)
		}
		var doc *atif.Trajectory
		for tr, err := range export.Trajectories(s) {
			if err != nil {
				return fmt.Errorf("publish: %s: %w", e.Session, err)
			}
			if !tr.Main {
				continue
			}
			if doc, err = export.ToATIF(tr, export.Options{Redactors: []export.Redactor{export.NoPassthrough()}}); err != nil {
				return fmt.Errorf("publish: %s: %w", e.Session, err)
			}
		}
		if doc == nil {
			continue
		}
		if backstop != nil {
			if err := export.RewriteStrings(doc, backstop); err != nil {
				return fmt.Errorf("publish: %s: %w", e.Session, err)
			}
		}
		sdir := filepath.Join(dir, e.Session)
		if err := os.Mkdir(sdir, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sdir, "atif.json"), doc); err != nil {
			return err
		}
		if err := writeTrace(filepath.Join(sdir, "trace.jsonl"), doc); err != nil {
			return err
		}
		for i, sub := range doc.SubagentTrajectories {
			if i == 0 {
				if err := os.Mkdir(filepath.Join(sdir, "subagents"), 0o755); err != nil {
					return err
				}
			}
			if err := writeTrace(filepath.Join(sdir, "subagents", fmt.Sprintf("%d.jsonl", i+1)), sub); err != nil {
				return err
			}
		}
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "README.md"), []byte(card(m)), 0o644)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// traceLine is one line of a Session Trace Simple Format file.
type traceLine struct {
	Type             string      `json:"type"`
	ID               string      `json:"id,omitempty"`
	Harness          string      `json:"harness,omitempty"`
	Role             string      `json:"role,omitempty"`
	Content          string      `json:"content,omitempty"`
	ReasoningContent string      `json:"reasoningContent,omitempty"`
	ToolCalls        []traceCall `json:"toolCalls,omitempty"`
	ToolCallID       string      `json:"toolCallId,omitempty"`
	Model            string      `json:"model,omitempty"`
	Timestamp        string      `json:"timestamp,omitempty"`
}

type traceCall struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// writeTrace writes doc as a Session Trace Simple Format file.
func writeTrace(path string, doc *atif.Trajectory) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	werr := enc.Encode(traceLine{Type: "session", ID: doc.SessionID, Harness: doc.Agent.Name})
	for _, st := range doc.Steps {
		if werr != nil {
			break
		}
		role := map[string]string{"user": "user", "agent": "assistant", "system": "system"}[st.Source]
		if role == "" {
			role = st.Source
		}
		l := traceLine{Type: "message", Role: role, Content: st.Message.String(), ReasoningContent: st.ReasoningContent, Model: st.ModelName, Timestamp: st.Timestamp}
		for _, c := range st.ToolCalls {
			l.ToolCalls = append(l.ToolCalls, traceCall{ID: c.ToolCallID, Name: c.FunctionName, Arguments: c.Arguments})
		}
		werr = enc.Encode(l)
		if st.Observation != nil {
			for _, r := range st.Observation.Results {
				if werr = enc.Encode(traceLine{Type: "message", Role: "tool", ToolCallID: r.SourceCallID, Content: r.Content.String(), Timestamp: st.Timestamp}); werr != nil {
					break
				}
			}
		}
	}
	if err := errors.Join(werr, f.Close()); err != nil {
		return fmt.Errorf("publish: writing %s: %w", filepath.Base(path), err)
	}
	return nil
}

// card is the dataset card: what the data is and how it was cleaned,
// from the manifest alone, so it names nothing the manifest does not.
func card(m Manifest) string {
	totals := map[string]int{}
	for _, e := range m.Entries {
		for k, n := range e.Counts {
			totals[k] += n
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Redacted agent sessions\n\n%d sessions, redacted by agentredact under the profile `%s`", len(m.Entries), m.Profile)
	if len(m.Judges) > 0 {
		fmt.Fprintf(&b, " and cleared by: %s", strings.Join(m.Judges, ", "))
	}
	b.WriteString(".\n\nEach session's directory holds its ATIF document (`atif.json`) and the same path in the Session Trace Simple Format (`trace.jsonl`). `manifest.json` names each session by its redacted ID and head hash.\n\n")
	if len(totals) > 0 {
		b.WriteString("Replacements made, by kind:\n\n")
		for _, k := range slices.Sorted(func(yield func(string) bool) {
			for k := range totals {
				if !yield(k) {
					return
				}
			}
		}) {
			fmt.Fprintf(&b, "- %s: %d\n", k, totals[k])
		}
		b.WriteString("\n")
	}
	b.WriteString("Redaction is a best effort: secrets in encodings the rules do not read, and text in images, may remain.\n")
	return b.String()
}
