// Command agentredact redacts a store of agent sessions and decides
// which redactions leave it:
//
//	agentredact keygen  -key FILE
//	agentredact redact  -store DIR -key FILE [-profile NAME] [-home DIR] [-rules FILE] [-accept KIND,...]
//	agentredact scan    -store DIR -key FILE [-profile NAME] [-trufflehog BIN] [-atif]
//	agentredact publish -store DIR -key FILE -to DIR [-profile NAME] [-judges scan,review | -unjudged] [-manifest FILE]
//	agentredact export  -store DIR -key FILE -manifest FILE -out DIR [-profile NAME] [-judges scan,review | -unjudged]
//
// A store is a jsonl store directory, or a cas store with -cas. The key
// file holds the redaction key of the store of originals (keygen writes
// one, mode 0600, and never overwrites one): keep it beside the store,
// out of anything published. Losing it means the redactions made under
// it cannot be resumed. The target of publish is opened to hold only
// redacted entries. export reads the private store, holds each session
// the manifest lists to what publish does (the store pass's report in
// the session's current state, the judges' verdicts on that exact
// state) and runs the profile's rules over the documents once more,
// then writes a local dataset directory; nothing is uploaded.
//
// The profile is the built-in one, named by -profile (default@3): the
// home directory, the default secret patterns and the Claude Code
// identity members, the environment blanked, images replaced and text
// blobs redacted, with a rules file's rules added by -rules. A changed
// rule set takes a new profile version. Secrets in base64, URL encoding or images are not
// found by the rules; the scan and the review are backstops, not
// guarantees.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ChristopherDavenport/agentredact"
	"github.com/ChristopherDavenport/agentredact/publish"
	"github.com/ChristopherDavenport/agentredact/scan"
	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/agentsession/cas"
	"github.com/ChristopherDavenport/agentsession/jsonl"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "agentredact:", err)
		os.Exit(1)
	}
}

const usage = "usage: agentredact keygen|redact|scan|publish|export [flags]; agentredact <command> -h"

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var (
		storeDir  = fs.String("store", "", "the store of originals: a jsonl store directory")
		casStore  = fs.Bool("cas", false, "the stores are cas stores")
		keyFile   = fs.String("key", "", "the redaction key file of the store of originals")
		profile   = fs.String("profile", "default@3", "the profile's name and version")
		home      = fs.String("home", "", "the home directory to shorten to ~ (default: $HOME)")
		rules     = fs.String("rules", "", "a rules file in git-filter-repo's --replace-text form")
		accept    = fs.String("accept", "", "finding kinds a publishable redaction may hold, comma-separated")
		truffle   = fs.String("trufflehog", "", "the trufflehog binary (default: on PATH)")
		withATIF  = fs.Bool("atif", false, "scan the ATIF documents too")
		to        = fs.String("to", "", "publish: the target store, which holds only redacted entries")
		judges    = fs.String("judges", "", "publish: the judges that must clear a session (default: scan)")
		unjudged  = fs.Bool("unjudged", false, "publish: require no verdict at all")
		manifestF = fs.String("manifest", "", "publish: where to write the manifest; export: the manifest to export")
		outDir    = fs.String("out", "", "export: the dataset directory to create")
	)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if args[0] == "keygen" {
		if *keyFile == "" {
			return errors.New("keygen: -key is required")
		}
		k, err := agentredact.GenerateKey()
		if err != nil {
			return err
		}
		if err := agentredact.WriteKeyFile(*keyFile, k); err != nil {
			return err
		}
		fmt.Fprintf(out, "wrote a key to %s; keep it beside the store of originals and back it up with them\n", *keyFile)
		return nil
	}
	if *storeDir == "" {
		return fmt.Errorf("%s: -store is required", args[0])
	}
	st, closeStore, err := openStore(*storeDir, *casStore, false)
	if err != nil {
		return err
	}
	defer closeStore()
	if *keyFile == "" {
		return fmt.Errorf("%s: -key is required: there is no default key", args[0])
	}
	key, err := agentredact.ReadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	p, err := builtIn(*profile, *home, *rules)
	if err != nil {
		return err
	}
	var kinds []agentredact.FindingKind
	for _, k := range split(*accept) {
		kinds = append(kinds, agentredact.FindingKind(k))
	}
	rep, err := agentredact.RedactStore(ctx, st, p, key, agentredact.StoreOptions{AcceptFindings: kinds})
	if rep == nil {
		return err
	}
	switch args[0] {
	case "redact":
		pub := rep.Public(key)
		for _, s := range pub.Sessions {
			fmt.Fprintf(out, "%s created=%v written=%d publishable=%v findings=%d err=%v\n", s.Redaction, s.Created, s.Written, s.Publishable(), len(s.Findings), s.Err)
		}
		return err
	case "scan":
		if err != nil {
			return err
		}
		br, _ := st.(agentsession.BlobReader)
		failed := 0
		for _, s := range rep.Sessions {
			if s.Err != nil || s.WaitingOn != "" {
				continue
			}
			red, err := read(ctx, st, s.Redaction)
			if err != nil {
				return err
			}
			res, err := (scan.Scanner{Binary: *truffle, ATIF: *withATIF}).Scan(ctx, red, br)
			if err != nil {
				return err
			}
			v, err := agentredact.WriteVerdict(red, res.Judged, res.Verdict(), time.Now())
			if err != nil {
				return err
			}
			if err := importSession(ctx, st, v); err != nil {
				return err
			}
			if !res.Pass() {
				failed++
			}
			fmt.Fprintf(out, "%s pass=%v findings=%d\n", s.Redaction, res.Pass(), len(res.Findings))
		}
		if failed > 0 {
			return fmt.Errorf("scan: %d sessions hold findings", failed)
		}
		return nil
	case "export":
		if err != nil {
			return err
		}
		if *manifestF == "" || *outDir == "" {
			return errors.New("export: -manifest and -out are required")
		}
		var m publish.Manifest
		data, err := os.ReadFile(*manifestF)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("export: the manifest: %w", err)
		}
		// From the private store, each session held to what publish
		// holds it to, and the profile's rules run over the documents
		// once more.
		opts := publish.Options{Profile: p.Name, Report: rep, Judges: split(*judges), Unjudged: *unjudged}
		if err := publish.ExportDataset(ctx, st, m, *outDir, opts, p.StringFunc()); err != nil {
			return err
		}
		fmt.Fprintf(out, "exported %d sessions to %s\n", len(m.Entries), *outDir)
		return nil
	case "publish":
		if err != nil {
			return err
		}
		if *to == "" {
			return errors.New("publish: -to is required")
		}
		target, closeTarget, err := openStore(*to, *casStore, true)
		if err != nil {
			return err
		}
		defer closeTarget()
		opts := publish.Options{Profile: p.Name, Report: rep, Judges: split(*judges), Unjudged: *unjudged}
		res, err := publish.Publish(ctx, st, target, opts)
		if res != nil {
			for _, s := range res.Published {
				fmt.Fprintf(out, "published %s head %s\n", s.Session, s.Head)
			}
			for _, h := range res.Held {
				fmt.Fprintf(out, "held %s: %s\n", h.Session, h.Reason)
			}
			if *manifestF != "" {
				data, merr := json.MarshalIndent(publish.NewManifest(res, opts), "", "  ")
				if merr == nil {
					merr = os.WriteFile(*manifestF, append(data, '\n'), 0o644)
				}
				err = errors.Join(err, merr)
			}
		}
		return err
	}
	return errors.New(usage)
}

// builtIn is the command's profile under name.
func builtIn(name, home, rulesFile string) (agentredact.Profile, error) {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	strs := []agentredact.StringRedactor{agentredact.HomePaths(home), agentredact.DefaultPatterns()}
	if rulesFile != "" {
		f, err := os.Open(rulesFile)
		if err != nil {
			return agentredact.Profile{}, err
		}
		defer f.Close()
		r, err := agentredact.ParseRules(f)
		if err != nil {
			return agentredact.Profile{}, err
		}
		strs = append(strs, r)
	}
	p := agentredact.Profile{
		Name:     name,
		Strings:  strs,
		Entries:  []agentredact.EntryRedactor{agentredact.Environment(), agentredact.Images(agentredact.DefaultImagePlaceholder)},
		Identity: agentredact.ClaudeCodeIdentity(),
	}
	return p, p.Validate()
}

// openStore opens a jsonl or cas store at dir, holding only redacted
// entries when redactedOnly is set.
func openStore(dir string, isCAS, redactedOnly bool) (agentsession.Store, func(), error) {
	if isCAS {
		var opts []cas.Option
		if redactedOnly {
			opts = append(opts, cas.WithRedactedOnly())
		}
		st, err := cas.Open(dir, opts...)
		if err != nil {
			return nil, nil, err
		}
		return st, func() { st.Close() }, nil
	}
	var opts []jsonl.Option
	if redactedOnly {
		opts = append(opts, jsonl.WithRedactedOnly())
	}
	st, err := jsonl.Open(dir, opts...)
	if err != nil {
		return nil, nil, err
	}
	return st, func() { st.Close() }, nil
}

func read(ctx context.Context, st agentsession.Store, id string) (*agentsession.Session, error) {
	if r, ok := st.(agentsession.Reader); ok {
		return r.Read(ctx, id)
	}
	return nil, errors.New("the store cannot be read without a hold")
}

func importSession(ctx context.Context, st agentsession.Store, s *agentsession.Session) error {
	im, ok := st.(agentsession.Importer)
	if !ok {
		return errors.New("the store cannot import a session")
	}
	var buf strings.Builder
	if err := agentsession.Write(&buf, s); err != nil {
		return err
	}
	_, err := im.Import(ctx, strings.NewReader(buf.String()), true)
	return err
}

func split(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
