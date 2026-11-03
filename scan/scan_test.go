package scan

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// Every value here is synthetic: an AWS-shaped key spelled as a fake.
const fakeAWS = "AKIAFAKE0000EXAMPLE0"

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func testKey(t *testing.T) agentredact.Key {
	k, err := agentredact.NewKey([]byte("agentredact-scan-test-key-not-a-secret"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// original holds the fake key in a user message.
func original(t *testing.T) *agentsession.Session {
	t.Helper()
	s := agentsession.New(agentsession.Header{ID: "orig-scan", CreatedAt: t0})
	for i, it := range []openresponses.Item{openresponses.UserText("my key is " + fakeAWS), openresponses.AssistantText("noted")} {
		e := agentsession.NewItemEntry(it)
		e.Timestamp = t0.Add(time.Duration(i+1) * time.Second)
		if _, err := s.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func redactWith(t *testing.T, p agentredact.Profile) *agentsession.Session {
	t.Helper()
	res, err := agentredact.Redact(p, testKey(t), original(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Session
}

var stub = Scanner{Binary: filepath.Join("testdata", "trufflehog"), ATIF: true}

// TestScanBlocks: a profile with no patterns keeps a fake AWS key, and
// the scan finds it in the session's file, at the redacted entry, and in
// its ATIF document, with no value anywhere in the result; its verdict
// fails. A profile with the default patterns passes (#4).
func TestScanBlocks(t *testing.T) {
	red := redactWith(t, agentredact.Profile{Name: "scan.none@1"})
	res, err := stub.Scan(context.Background(), red, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := agentsession.FileOrder(red)[0].Base().ID
	want := []Finding{{Detector: "AWS", Artifact: ArtifactATIF, Count: 1}, {Detector: "AWS", Artifact: ArtifactSession, Entry: first, Count: 1}}
	if fmt.Sprint(res.Findings) != fmt.Sprint(want) {
		t.Errorf("findings %+v, want %+v", res.Findings, want)
	}
	v := res.Verdict()
	if v.Pass || v.Findings["AWS"] != 2 || len(v.Entries) != 1 || v.Entries[0] != first {
		t.Errorf("verdict %+v", v)
	}
	if strings.Contains(fmt.Sprintf("%+v %+v", res, v), fakeAWS) {
		t.Error("the result holds the value")
	}
	if res.Judged != agentredact.JudgedEntry(red) {
		t.Errorf("judged %s", res.Judged)
	}
	clean := redactWith(t, agentredact.Profile{Name: "scan.default@1", Strings: []agentredact.StringRedactor{agentredact.DefaultPatterns()}})
	res, err = stub.Scan(context.Background(), clean, nil)
	if err != nil || !res.Pass() || !res.Verdict().Pass {
		t.Errorf("a redaction holding no key: %+v, %v", res, err)
	}
}

// TestScanRefuses: an original is not scanned, and a binary that fails
// is an error that quotes nothing it wrote.
func TestScanRefuses(t *testing.T) {
	if _, err := stub.Scan(context.Background(), original(t), nil); !errors.Is(err, agentredact.ErrNotRedacted) {
		t.Errorf("an original: %v, want ErrNotRedacted", err)
	}
	red := redactWith(t, agentredact.Profile{Name: "scan.none@1"})
	if _, err := (Scanner{Binary: filepath.Join("testdata", "missing")}).Scan(context.Background(), red, nil); !errors.Is(err, ErrScan) {
		t.Errorf("a missing binary: %v, want ErrScan", err)
	}
}

// TestScanTruffleHog runs the real binary over the synthetic fixture,
// when it is installed; it is skipped otherwise. TruffleHog's own AWS
// detector may not match a key spelled as a fake, so it asserts only
// that the scan runs and its output parses.
func TestScanTruffleHog(t *testing.T) {
	bin, err := exec.LookPath("trufflehog")
	if err != nil {
		t.Skip("trufflehog is not installed")
	}
	red := redactWith(t, agentredact.Profile{Name: "scan.none@1"})
	if _, err := (Scanner{Binary: bin}).Scan(context.Background(), red, nil); err != nil {
		t.Errorf("Scan: %v", err)
	}
}
