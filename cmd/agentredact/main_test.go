package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/agentsession/jsonl"
	"github.com/ChristopherDavenport/openresponses"
)

// Every value here is synthetic.

// TestCommand runs keygen, redact, scan (with the scan package's stub
// trufflehog), publish and export over a synthetic jsonl store.
func TestCommand(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, target, key := filepath.Join(dir, "store"), filepath.Join(dir, "published"), filepath.Join(dir, "redaction.key")
	st, err := jsonl.Open(store)
	if err != nil {
		t.Fatal(err)
	}
	s := agentsession.New(agentsession.Header{ID: "orig-command", CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)})
	e := agentsession.NewItemEntry(openresponses.UserText("a fake key AKIAFAKE0000EXAMPLE0 in /home/example/x"))
	e.Timestamp = s.Header().CreatedAt.Add(time.Second)
	if _, err := s.Append(e); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := agentsession.Write(&buf, s); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Import(ctx, &buf, true); err != nil {
		t.Fatal(err)
	}
	st.Close()

	var out bytes.Buffer
	do := func(args ...string) error { out.Reset(); return run(ctx, args, &out) }
	if err := do("redact", "-store", store); err == nil || !strings.Contains(err.Error(), "-key") {
		t.Errorf("redact with no key: %v", err)
	}
	if err := do("keygen", "-key", key); err != nil {
		t.Fatal(err)
	}
	if err := do("keygen", "-key", key); err == nil {
		t.Error("keygen overwrote a key")
	}
	if err := do("redact", "-store", store, "-key", key, "-home", "/home/example"); err != nil || !strings.Contains(out.String(), "publishable=true") || strings.Contains(out.String(), "orig-command") {
		t.Errorf("redact: %v\n%s", err, out.String())
	}
	stub, _ := filepath.Abs(filepath.Join("..", "..", "scan", "testdata", "trufflehog"))
	if err := do("scan", "-store", store, "-key", key, "-home", "/home/example", "-trufflehog", stub); err != nil || !strings.Contains(out.String(), "pass=true") {
		t.Errorf("scan: %v\n%s", err, out.String())
	}
	manifest := filepath.Join(dir, "manifest.json")
	if err := do("publish", "-store", store, "-key", key, "-home", "/home/example", "-to", target, "-manifest", manifest); err != nil || !strings.Contains(out.String(), "published ") {
		t.Errorf("publish: %v\n%s", err, out.String())
	}
	if err := do("export", "-store", store, "-key", key, "-home", "/home/example", "-manifest", manifest, "-out", filepath.Join(dir, "dataset")); err != nil {
		t.Errorf("export: %v", err)
	}
	if err := do("export", "-store", store, "-key", key, "-home", "/home/example", "-judges", "scan,review", "-manifest", manifest, "-out", filepath.Join(dir, "dataset2")); err == nil {
		t.Error("exported a session no review cleared")
	}
	m, err := os.ReadFile(manifest)
	if err != nil || bytes.Contains(m, []byte("orig-command")) {
		t.Errorf("the manifest: %v\n%s", err, m)
	}
}
