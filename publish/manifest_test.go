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
	"time"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
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
	if err := exportFrom(ctx, private, m, dir, opts); err != nil {
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
	if err := exportFrom(ctx, private, m, dir, opts); err == nil {
		t.Error("an export over an existing directory")
	}
}

// TestExportRechecks: an export checks what a publish checks: a session
// that holds no verdict covering its exact state, or whose state is not
// the report's, is not exported, from any store (N1).
func TestExportRechecks(t *testing.T) {
	ctx := context.Background()
	private := agentsession.NewMemoryStore()
	o := session(t, "orig-export-recheck", "hello")
	load(t, private, o)
	opts := Options{Profile: profile.Name, Report: pass(t, private), Unjudged: true}
	target := agentsession.NewMemoryStore(agentsession.MemoryRedactedOnly())
	res, err := Publish(ctx, private, target, opts)
	if err != nil || len(res.Published) != 1 {
		t.Fatalf("%+v, %v", res, err)
	}
	m := NewManifest(res, opts)
	judged := Options{Profile: profile.Name, Report: opts.Report}
	if err := exportFrom(ctx, private, m, filepath.Join(t.TempDir(), "d"), judged); err == nil {
		t.Error("exported a session no scan cleared")
	}
	if err := exportFrom(ctx, private, m, filepath.Join(t.TempDir(), "d"), opts); err != nil {
		t.Errorf("an export the report and the opt-out allow: %v", err)
	}
	// A branch after the report: the session's state is not the report's.
	e := agentsession.NewItemEntry(openresponses.UserText("a branch"))
	e.Parent = agentsession.FileOrder(o)[0].Base().ID
	e.Timestamp = t0.Add(9 * time.Second)
	if _, err := private.Append(ctx, o.ID(), e); err != nil {
		t.Fatal(err)
	}
	pass(t, private)
	if err := exportFrom(ctx, private, m, filepath.Join(t.TempDir(), "d"), opts); err == nil {
		t.Error("exported a session changed since its report")
	}
}
