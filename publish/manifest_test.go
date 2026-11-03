package publish

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentsession"
)

// TestManifestAndExport: the manifest names each published session by
// its redacted ID and head, never an original; it checks against the
// published store; and the dataset written from it holds each session's
// ATIF and trace, a manifest and a card, naming no original (#6).
func TestManifestAndExport(t *testing.T) {
	ctx := context.Background()
	private := agentsession.NewMemoryStore()
	o := session(t, "orig-dataset-native", "hello", "again")
	load(t, private, o)
	opts := Options{Profile: profile.Name, Report: pass(t, private), Unjudged: true}
	target := agentsession.NewMemoryStore(agentsession.MemoryRedactedOnly())
	res, err := Publish(ctx, private, target, opts)
	if err != nil || len(res.Published) != 1 {
		t.Fatalf("%+v, %v", res, err)
	}
	m := NewManifest(res, opts)
	data, _ := json.Marshal(m)
	if strings.Contains(string(data), "orig-") || len(m.Entries) != 1 || m.Entries[0].Head != res.Published[0].Head {
		t.Errorf("manifest %s", data)
	}
	if err := m.Check(ctx, target); err != nil {
		t.Errorf("Check: %v", err)
	}
	bad := m
	bad.Entries = []ManifestEntry{{Session: o.ID(), Head: m.Entries[0].Head}}
	if err := bad.Check(ctx, private); !errors.Is(err, ErrManifest) {
		t.Errorf("a manifest naming an original: %v, want ErrManifest", err)
	}
	dir := filepath.Join(t.TempDir(), "dataset")
	if err := ExportDataset(ctx, target, m, dir, nil); err != nil {
		t.Fatal(err)
	}
	id := m.Entries[0].Session
	for _, f := range []string{"manifest.json", "README.md", filepath.Join(id, "atif.json"), filepath.Join(id, "trace.jsonl")} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if bytes.Contains(b, []byte("orig-")) {
			t.Errorf("%s names an original", f)
		}
	}
	tf, err := os.Open(filepath.Join(dir, id, "trace.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer tf.Close()
	sc := bufio.NewScanner(tf)
	var lines []map[string]any
	for sc.Scan() {
		var l map[string]any
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, l)
	}
	if len(lines) < 3 || lines[0]["type"] != "session" || lines[0]["id"] != id || lines[1]["role"] != "user" || lines[1]["content"] != "hello" {
		t.Errorf("trace %v", lines)
	}
	if err := ExportDataset(ctx, target, m, dir, nil); err == nil {
		t.Error("an export over an existing directory")
	}
}
