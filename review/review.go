// Package review has a model read a redacted session for what the
// deterministic redactors missed, a person's name, a host, a customer,
// and records what it flags as a verdict (#5). The model is the
// caller's: any openresponses adapter, a local one or a provider's,
// with a model name the caller chooses; there is no default model. The
// caller also caps what the review may spend, in tokens, and there is
// no default cap. The review fails closed: a model error, an answer it
// cannot read and a review that would pass the cap are errors, and no
// verdict clears the session.
//
// The review is advisory. The text it reads is the session's, which an
// agent's inputs wrote, a web page or a tool's output among them, and
// such text can steer the model, to flag nothing among other things. A
// passing review is therefore no evidence that a session is clean: the
// scan stays the gate publishing requires by default, and a review is a
// further judge a publisher may require beside it.
//
// What the model reads is the redacted session, which may leave the
// machine for a provider, and the project context the caller gives,
// which should be text the caller is content to send there: the
// redaction's own instruction parts ([AgentsMD]) rather than the
// original's.
package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// Judge is the name a review's verdicts are recorded under.
const Judge = "review"

// Model is what the review sends its requests to:
// [openresponses.Adapter]'s Create, which every adapter has.
type Model interface {
	Create(ctx context.Context, req openresponses.Request) (*openresponses.Response, error)
}

// Reviewer reviews redacted sessions with the caller's model.
type Reviewer struct {
	// Model answers the review's requests, and ModelName is the model
	// they name. Both are required.
	Model     Model
	ModelName string
	// MaxTokens caps the tokens, input and output together, the review
	// of one session may spend. It is counted conservatively, every byte
	// sent or received a token, or the response's usage where that is
	// more, and before each request the bytes it sends are counted and
	// its output capped to what is left, so no request can pass it.
	// Required: a review that would pass it stops and fails.
	MaxTokens int
	// Context is the project's context the model is given, such as the
	// AGENTS.md text [AgentsMD] reads.
	Context string
	// ChunkBytes bounds the session text one request carries; 32 KiB
	// when zero.
	ChunkBytes int
}

// Flag is something the model flagged: the redacted entry, by its ID,
// and the kind, never the text.
type Flag struct {
	Entry string
	Kind  string
}

// Result is what one review found.
type Result struct {
	// Judged is the redacted session's entry the review covers up to,
	// and State the session's state the model read, which its verdict
	// records.
	Judged string
	State  agentredact.State
	Flags  []Flag
	// Tokens are what the review spent.
	Tokens int
}

// Verdict is the review's verdict for [agentredact.WriteVerdict]: kind
// "eval", passing when nothing was flagged.
func (r *Result) Verdict() agentredact.Verdict {
	v := agentredact.Verdict{Judge: Judge, Kind: "eval", Pass: len(r.Flags) == 0, Findings: map[string]int{}, Covered: r.State}
	for _, f := range r.Flags {
		v.Findings[f.Kind]++
		v.Entries = append(v.Entries, f.Entry)
	}
	return v
}

var (
	// ErrConfig is returned for a Reviewer with no model, no model name
	// or no cap.
	ErrConfig = errors.New("review: a model, its name and a token cap are required")
	// ErrBudget is returned when the review would pass its cap.
	ErrBudget = errors.New("review: the token cap would be passed")
	// ErrAnswer is returned for a model answer the review cannot read.
	ErrAnswer = errors.New("review: the model's answer is not a review")
)

// kinds are what the model may flag.
var kinds = []string{"person", "host", "organization", "credential", "path", "contact", "other"}

const instructions = `You review a redacted agent session before it is published. Placeholders such as [REDACTED#1] or ~ are already redacted. Flag every entry that still holds something identifying or secret that redaction missed: a person's name, a host or machine name, an organization or customer, a credential, a private path, contact details. Answer with JSON alone: {"flags":[{"entry":"<entry id>","kind":"<kind>"}]}, kind one of: ` +
	"person, host, organization, credential, path, contact, other" + `. Never quote what you flag. Answer {"flags":[]} when nothing is left.`

// Review has the model read red, a redacted session, in chunks of its
// entries, and returns what it flagged. It returns an error, and no
// result, when the model fails, answers what is not a review, names an
// entry the chunk did not hold, or the review would pass MaxTokens.
func (rv Reviewer) Review(ctx context.Context, red *agentsession.Session) (*Result, error) {
	if rv.Model == nil || rv.ModelName == "" || rv.MaxTokens <= 0 {
		return nil, ErrConfig
	}
	if !red.Header().Redacted {
		return nil, fmt.Errorf("%w: %s", agentredact.ErrNotRedacted, red.ID())
	}
	limit := rv.ChunkBytes
	if limit <= 0 {
		limit = 32 << 10
	}
	res := &Result{Judged: agentredact.JudgedEntry(red), State: agentredact.StateOf(red)}
	chunks, err := chunk(red, limit)
	if err != nil {
		return nil, err
	}
	for _, c := range chunks {
		prompt := "Project context:\n" + rv.Context + "\n\nEntries, one JSON object a line:\n" + c.text
		estimate := len(instructions) + len(prompt) // a token a byte: no tokenizer counts more
		if res.Tokens+estimate > rv.MaxTokens {
			return nil, fmt.Errorf("%w: %d spent, %d more to send, cap %d", ErrBudget, res.Tokens, estimate, rv.MaxTokens)
		}
		left := rv.MaxTokens - res.Tokens - estimate
		req := openresponses.Request{
			Model:           rv.ModelName,
			Input:           openresponses.Items{openresponses.DeveloperText(instructions), openresponses.UserText(prompt)},
			MaxOutputTokens: &left,
		}
		resp, err := rv.Model.Create(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("review: the model: %w", err)
		}
		if resp == nil || resp.Status != openresponses.ResponseStatusCompleted {
			return nil, fmt.Errorf("%w: the response did not complete", ErrAnswer)
		}
		spent := estimate + len(resp.OutputText())
		if resp.Usage != nil && resp.Usage.TotalTokens > spent {
			spent = resp.Usage.TotalTokens
		}
		res.Tokens += spent
		if res.Tokens > rv.MaxTokens {
			return nil, fmt.Errorf("%w: %d spent, cap %d", ErrBudget, res.Tokens, rv.MaxTokens)
		}
		flags, err := parse(resp.OutputText(), c.ids)
		if err != nil {
			return nil, err
		}
		res.Flags = append(res.Flags, flags...)
	}
	return res, nil
}

// part is a chunk of a session's entries as the model reads them.
type part struct {
	text string
	ids  map[string]bool
}

// chunk renders red's entries, one JSON line each, into parts of at
// most limit bytes, an entry longer than that in a part of its own.
func chunk(red *agentsession.Session, limit int) ([]part, error) {
	var out []part
	cur := part{ids: map[string]bool{}}
	for _, e := range agentsession.FileOrder(red) {
		data, err := agentsession.MarshalEntry(e)
		if err != nil {
			return nil, err
		}
		if cur.text != "" && len(cur.text)+len(data) > limit {
			out = append(out, cur)
			cur = part{ids: map[string]bool{}}
		}
		cur.text += string(data) + "\n"
		cur.ids[e.Base().ID] = true
	}
	if cur.text != "" {
		out = append(out, cur)
	}
	return out, nil
}

// parse reads the model's answer: {"flags":[{"entry","kind"}]}, each
// entry one the chunk held and each kind a known one, "other" for one
// it is not.
func parse(text string, ids map[string]bool) ([]Flag, error) {
	text = strings.TrimSpace(text)
	text = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(text, "```json"), "```"), "```")
	var a struct {
		Flags *[]struct {
			Entry string `json:"entry"`
			Kind  string `json:"kind"`
		} `json:"flags"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &a); err != nil || a.Flags == nil {
		return nil, ErrAnswer
	}
	var out []Flag
	for _, f := range *a.Flags {
		if !ids[f.Entry] {
			return nil, fmt.Errorf("%w: it flags an entry it was not shown", ErrAnswer)
		}
		kind := f.Kind
		if !slices.Contains(kinds, kind) {
			kind = "other"
		}
		out = append(out, Flag{Entry: f.Entry, Kind: kind})
	}
	return out, nil
}

// AgentsMD is the text of the AGENTS.md instruction parts (source
// agentsmd) in force at s's leaf, in order: the project context a
// review gives its model. Read from a redacted session, it is the
// redacted text.
func AgentsMD(s *agentsession.Session) string {
	ctx, err := s.Context()
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range ctx.Settings.InstructionsParts {
		if p.Source == agentsession.LayerAgentsMD && p.Text != "" {
			b.WriteString(p.Text)
			b.WriteString("\n\n")
		}
	}
	return strings.TrimSpace(b.String())
}
