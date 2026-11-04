// Package scan runs TruffleHog over what a redacted session would
// publish, and records what it finds as a verdict (#4): the bytes that
// would leave, the redacted session's file, the blobs it names and its
// ATIF documents (agentsession/export, NoPassthrough), are written to a
// private temporary directory, the trufflehog binary scans it with
// verification and updates off, and each finding is kept as its
// detector's name, where it was found and a count, never the value.
//
// TruffleHog runs as a binary through os/exec, not as a library: its Go
// packages would bring hundreds of modules into a build that reads
// unredacted sessions (docs/plans/agentredact.md, the dependency rule).
// Its --json output, one finding per line, is the contract. The scan is
// a backstop for what the redactors missed, not a guarantee.
package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/agentsession/export"
)

// Judge is the name a scan's verdicts are recorded under.
const Judge = "scan"

// Scanner runs the trufflehog binary.
type Scanner struct {
	// Binary is the trufflehog binary's path; "trufflehog", found on
	// PATH, when empty.
	Binary string
	// ATIF says the session's ATIF documents are scanned as well, as a
	// dataset export publishes them.
	ATIF bool
}

// Artifact names what a finding was found in.
type Artifact string

const (
	// ArtifactSession is the redacted session's file.
	ArtifactSession Artifact = "session"
	// ArtifactBlob is a sidecar blob the session names.
	ArtifactBlob Artifact = "blob"
	// ArtifactATIF is one of the session's ATIF documents.
	ArtifactATIF Artifact = "atif"
)

// Finding is what TruffleHog found, counted: its detector, the artifact
// and, in the session's file, the redacted session's own entry, by its
// ID there, which names no original. It holds no value.
type Finding struct {
	Detector string
	Artifact Artifact
	// Entry is the redacted entry's ID, "" for the header, a blob or a
	// document.
	Entry string
	Count int
}

// Result is what one scan found.
type Result struct {
	// Judged is the redacted session's entry the scan covers up to
	// ([agentredact.JudgedEntry]), and State the session's state the
	// scan read, which its verdict records.
	Judged   string
	State    agentredact.State
	Findings []Finding
}

// Pass reports whether the scan found nothing.
func (r *Result) Pass() bool { return len(r.Findings) == 0 }

// Verdict is the scan's verdict, for [agentredact.WriteVerdict]: kind
// "test", passing when nothing was found, its findings counted by
// detector and the entries named.
func (r *Result) Verdict() agentredact.Verdict {
	v := agentredact.Verdict{Judge: Judge, Kind: "test", Pass: r.Pass(), Findings: map[string]int{}, Covered: r.State}
	for _, f := range r.Findings {
		v.Findings[f.Detector] += f.Count
		if f.Entry != "" {
			v.Entries = append(v.Entries, f.Entry)
		}
	}
	return v
}

// ErrScan is returned when the binary cannot be run, fails, or writes
// what is not its JSON output. Its message never holds what the binary
// wrote, which may quote a secret.
var ErrScan = errors.New("scan: trufflehog")

// Scan scans what the redacted session red would publish: its file, the
// blobs it names, read through blobs (a store's
// [agentsession.BlobReader], which may be nil only for a session naming
// none), and, with ATIF set, its ATIF documents. It fails closed: a
// run that does not say it finished scanning having read some bytes, a
// line of output that is
// not a finding, and a session whose blobs cannot be read are errors,
// never passes.
func (s Scanner) Scan(ctx context.Context, red *agentsession.Session, blobs agentsession.BlobReader) (*Result, error) {
	if !red.Header().Redacted {
		return nil, fmt.Errorf("%w: %s", agentredact.ErrNotRedacted, red.ID())
	}
	state := agentredact.StateOf(red) // what is staged below, before anything else can change it
	dir, err := os.MkdirTemp("", "agentredact-scan-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	lines, err := s.stage(ctx, dir, red, blobs)
	if err != nil {
		return nil, err
	}
	bin := s.Binary
	if bin == "" {
		bin = "trufflehog"
	}
	cmd := exec.CommandContext(ctx, bin, "filesystem", dir, "--json", "--no-verification", "--no-update")
	var out, logs bytes.Buffer
	cmd.Stdout = &out
	// Its log may quote what it found: it is read for the line saying the
	// scan finished, and never kept or shown.
	cmd.Stderr = &logs
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("%w: exited %d", ErrScan, exit.ExitCode())
		}
		return nil, fmt.Errorf("%w: %v", ErrScan, err)
	}
	res := &Result{Judged: agentredact.JudgedEntry(red), State: state}
	counts := map[Finding]int{}
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r struct {
			DetectorName   string
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string `json:"file"`
						Line int    `json:"line"`
					}
				}
			}
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("%w: a line of its output is not a finding", ErrScan)
		}
		if r.DetectorName == "" {
			return nil, fmt.Errorf("%w: a line of its output is not a finding", ErrScan)
		}
		f := Finding{Detector: r.DetectorName}
		rel, err := filepath.Rel(dir, filepathOf(dir, r.SourceMetadata.Data.Filesystem.File))
		if err != nil {
			rel = ""
		}
		switch {
		case rel == "session.jsonl":
			f.Artifact = ArtifactSession
			if n := r.SourceMetadata.Data.Filesystem.Line; n >= 1 && n <= len(lines) {
				f.Entry = lines[n-1]
			}
		case strings.HasPrefix(rel, "blobs"+string(filepath.Separator)):
			f.Artifact = ArtifactBlob
		default:
			f.Artifact = ArtifactATIF
		}
		counts[f]++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: reading its output: %v", ErrScan, err)
	}
	if !finished(logs.Bytes()) {
		return nil, fmt.Errorf("%w: it did not say it finished scanning", ErrScan)
	}
	for f, n := range counts {
		f.Count = n
		res.Findings = append(res.Findings, f)
	}
	slices.SortFunc(res.Findings, func(a, b Finding) int {
		return strings.Compare(string(a.Artifact)+"\x00"+a.Detector+"\x00"+a.Entry, string(b.Artifact)+"\x00"+b.Detector+"\x00"+b.Entry)
	})
	return res, nil
}

// finished reports whether trufflehog's log, JSON lines on stderr,
// holds the line it writes when a scan completes, "finished scanning",
// with the bytes it read more than none (trufflehog's main logs chunks
// and bytes there). A run without it, cut short, of another program, or
// that read nothing, is not a scan.
func finished(logs []byte) bool {
	for _, l := range bytes.Split(logs, []byte("\n")) {
		var m struct {
			Msg   string `json:"msg"`
			Bytes *int64 `json:"bytes"`
		}
		if json.Unmarshal(bytes.TrimSpace(l), &m) == nil && m.Msg == "finished scanning" && m.Bytes != nil && *m.Bytes > 0 {
			return true
		}
	}
	return false
}

// filepathOf is the file a finding names, which TruffleHog gives
// absolute or relative to the directory scanned.
func filepathOf(dir, file string) string {
	if filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(dir, file)
}

// stage writes what red would publish into dir, and returns the ID of
// the entry on each line of the session's file, "" for the header.
func (s Scanner) stage(ctx context.Context, dir string, red *agentsession.Session, blobs agentsession.BlobReader) ([]string, error) {
	var buf bytes.Buffer
	if err := agentsession.Write(&buf, red); err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n")) {
		var e struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		_ = json.Unmarshal(l, &e)
		if e.Type == "session" {
			e.ID = ""
		}
		lines = append(lines, e.ID)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.jsonl"), buf.Bytes(), 0o600); err != nil {
		return nil, err
	}
	hashes, err := agentsession.SessionBlobs(red)
	if err != nil {
		return nil, err
	}
	if len(hashes) > 0 && blobs == nil {
		return nil, fmt.Errorf("%w: the session names %d blobs and no blob reader was given", ErrScan, len(hashes))
	}
	if blobs != nil {
		if len(hashes) > 0 {
			if err := os.Mkdir(filepath.Join(dir, "blobs"), 0o700); err != nil {
				return nil, err
			}
		}
		for _, h := range hashes {
			data, err := blobs.Blob(ctx, h)
			if err != nil {
				return nil, fmt.Errorf("scan: reading a blob the session names: %w", err)
			}
			name := strings.TrimPrefix(h, "sha256:")
			if _, err := hex.DecodeString(name); err != nil {
				return nil, fmt.Errorf("scan: a blob hash that is not hex")
			}
			if err := os.WriteFile(filepath.Join(dir, "blobs", name), data, 0o600); err != nil {
				return nil, err
			}
		}
	}
	if s.ATIF {
		adir := filepath.Join(dir, "atif")
		if err := os.Mkdir(adir, 0o700); err != nil {
			return nil, err
		}
		i := 0
		for tr, err := range export.Trajectories(red) {
			if err != nil {
				return nil, fmt.Errorf("scan: exporting ATIF: %w", err)
			}
			doc, err := export.ToATIF(tr, export.Options{Redactors: []export.Redactor{export.NoPassthrough()}})
			if err != nil {
				return nil, fmt.Errorf("scan: exporting ATIF: %w", err)
			}
			data, err := json.Marshal(doc)
			if err != nil {
				return nil, err
			}
			i++
			if err := os.WriteFile(filepath.Join(adir, fmt.Sprintf("%d.json", i)), data, 0o600); err != nil {
				return nil, err
			}
		}
	}
	return lines, nil
}
