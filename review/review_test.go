package review

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// Every value here is synthetic.

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// scripted answers each request with the next of its answers, or an
// error, and counts the requests.
type scripted struct {
	answers []string
	tokens  int
	err     error
	reqs    []openresponses.Request
}

func (s *scripted) Create(_ context.Context, req openresponses.Request) (*openresponses.Response, error) {
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	a := s.answers[0]
	if len(s.answers) > 1 {
		s.answers = s.answers[1:]
	}
	return &openresponses.Response{Status: openresponses.ResponseStatusCompleted, Output: openresponses.Items{openresponses.AssistantText(a)},
		Usage: &openresponses.Usage{TotalTokens: s.tokens}}, nil
}

func redacted(t *testing.T) *agentsession.Session {
	t.Helper()
	s := agentsession.New(agentsession.Header{ID: "orig-review", CreatedAt: t0})
	for i, x := range []string{"deploy to fakehost-review-01 for Fake Customer Ltd", "done"} {
		e := agentsession.NewItemEntry(openresponses.UserText(x))
		e.Timestamp = t0.Add(time.Duration(i+1) * time.Second)
		if _, err := s.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	k, err := agentredact.NewKey([]byte("agentredact-review-test-key-not-secret"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := agentredact.Redact(agentredact.Profile{Name: "review.test@1"}, k, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Session
}

// TestReview: a flag blocks, by entry and kind with no text; a clean
// answer passes; the review needs a model, its name and a cap, and fails
// closed on a model error, an unreadable answer, a flag naming an entry
// it was not shown, and the cap (#5).
func TestReview(t *testing.T) {
	ctx := context.Background()
	red := redacted(t)
	first := agentsession.FileOrder(red)[0].Base().ID
	m := &scripted{answers: []string{`{"flags":[{"entry":"` + first + `","kind":"organization"}]}`}, tokens: 50}
	res, err := Reviewer{Model: m, ModelName: "fake-model", MaxTokens: 10000, Context: "a fake project"}.Review(ctx, red)
	if err != nil {
		t.Fatal(err)
	}
	v := res.Verdict()
	if v.Pass || v.Findings["organization"] != 1 || len(v.Entries) != 1 || v.Entries[0] != first || res.Tokens != 50 {
		t.Errorf("verdict %+v, result %+v", v, res)
	}
	if req := m.reqs[0]; req.Model != "fake-model" || req.MaxOutputTokens == nil || !strings.Contains(req.Input[1].(*openresponses.Message).Content[0].(*openresponses.InputText).Text, "a fake project") {
		t.Errorf("request %+v", req)
	}
	clean := &scripted{answers: []string{"```json\n{\"flags\":[]}\n```"}, tokens: 50}
	if res, err := (Reviewer{Model: clean, ModelName: "fake-model", MaxTokens: 10000}).Review(ctx, red); err != nil || !res.Verdict().Pass {
		t.Errorf("a clean answer: %+v, %v", res, err)
	}
	for _, tt := range []struct {
		name string
		rv   Reviewer
		want error
	}{
		{"no cap", Reviewer{Model: clean, ModelName: "fake-model"}, ErrConfig},
		{"no model name", Reviewer{Model: clean, MaxTokens: 10000}, ErrConfig},
		{"no model", Reviewer{ModelName: "fake-model", MaxTokens: 10000}, ErrConfig},
		{"cap before sending", Reviewer{Model: clean, ModelName: "fake-model", MaxTokens: 10}, ErrBudget},
		{"cap on usage", Reviewer{Model: &scripted{answers: []string{`{"flags":[]}`}, tokens: 999999}, ModelName: "fake-model", MaxTokens: 10000}, ErrBudget},
		{"unreadable", Reviewer{Model: &scripted{answers: []string{"looks fine to me"}}, ModelName: "fake-model", MaxTokens: 10000}, ErrAnswer},
		{"unknown entry", Reviewer{Model: &scripted{answers: []string{`{"flags":[{"entry":"sha256:00","kind":"host"}]}`}}, ModelName: "fake-model", MaxTokens: 10000}, ErrAnswer},
		{"model error", Reviewer{Model: &scripted{err: errors.New("fake outage")}, ModelName: "fake-model", MaxTokens: 10000}, nil},
	} {
		res, err := tt.rv.Review(ctx, red)
		if err == nil || res != nil || tt.want != nil && !errors.Is(err, tt.want) {
			t.Errorf("%s: %+v, %v; want %v", tt.name, res, err, tt.want)
		}
	}
}
