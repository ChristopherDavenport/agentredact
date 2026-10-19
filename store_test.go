package agentredact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"slices"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/agentsession/cas"
	"github.com/ChristopherDavenport/agentsession/jsonl"
	"github.com/ChristopherDavenport/openresponses"
)

// Every store here is a fresh one, in memory or in a temporary
// directory, holding only the synthetic sessions the test builds.

// storeKind opens a store of one kind.
type storeKind struct {
	name string
	open func(t *testing.T) agentsession.Store
	// blobs says the store takes blobs.
	blobs bool
}

var storeKinds = []storeKind{
	{name: "memory", open: func(*testing.T) agentsession.Store { return agentsession.NewMemoryStore() }},
	{name: "jsonl", open: func(t *testing.T) agentsession.Store {
		st, err := jsonl.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	}},
	{name: "cas", blobs: true, open: func(t *testing.T) agentsession.Store {
		st, err := cas.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	}},
}

func storeProfile() Profile {
	return structProfile("test.store@1", []EntryRedactor{BlockOut(userWith("secret-block"))})
}

// load imports each session into st, as its record.
func load(t *testing.T, st agentsession.Store, sessions ...*agentsession.Session) {
	t.Helper()
	for _, s := range sessions {
		if _, err := st.(agentsession.Importer).Import(context.Background(), bytes.NewReader(fileOf(t, s)), true); err != nil {
			t.Fatalf("import %s: %v", s.ID(), err)
		}
		if rl, ok := st.(interface{ Release(string) error }); ok {
			if err := rl.Release(s.ID()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// grow appends to the session s in st the entries s holds past the
// first n in file order, as its writer appended them.
func grow(t *testing.T, st agentsession.Store, s *agentsession.Session, n int) {
	t.Helper()
	for _, e := range agentsession.FileOrder(s)[n:] {
		own, err := clone(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Append(context.Background(), s.ID(), own); err != nil {
			t.Fatalf("grow %s: %v", s.ID(), err)
		}
	}
	if rl, ok := st.(interface{ Release(string) error }); ok {
		if err := rl.Release(s.ID()); err != nil {
			t.Fatal(err)
		}
	}
}

func read(t *testing.T, st agentsession.Store, id string) *agentsession.Session {
	t.Helper()
	s, err := readHeld(context.Background(), st, id)
	if err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return s
}

// held returns the bytes of every session st holds, by ID.
func held(t *testing.T, st agentsession.Store) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for sum, err := range st.List(context.Background(), agentsession.ListFilter{}) {
		if err != nil {
			t.Fatal(err)
		}
		out[sum.Header.ID] = fileOf(t, read(t, st, sum.Header.ID))
	}
	return out
}

func redactStore(t *testing.T, st agentsession.Store, p Profile, opts StoreOptions) *StoreReport {
	t.Helper()
	rep, err := RedactStore(context.Background(), st, p, opts)
	if err != nil {
		t.Fatalf("RedactStore: %v", err)
	}
	return rep
}

// bySession indexes a report by original.
func bySession(rep *StoreReport) map[string]SessionReport {
	out := map[string]SessionReport{}
	for _, s := range rep.Sessions {
		out[s.Original] = s
	}
	return out
}

func redID(id string) string { return agentsession.RedactedSessionID(id, storeProfile().Name) }

// richOriginal holds a planted value in every place an entry and a
// header can hold one: the header's cwd, harness and a member the
// format does not define; an env entry's paths, revision, tool and
// workspace; user and assistant text, a call's arguments and output, an
// inline image, a custom entry's data, a label, a compaction's summary;
// and blocks a profile folds. base is a response a fork can start from.
func richOriginal(t *testing.T, c *clock, id string) (s *agentsession.Session, base string) {
	t.Helper()
	s = newOriginal(id)
	env := agentsession.NewEnvEntry(fakeHome + "/project")
	env.VCS = &agentsession.VCS{System: "git", Revision: fakeRevision, Dirty: true}
	env.AddRead(fakeHome+"/project/main.go", agentsession.HashText("fake file"))
	env.AddTool("go", fakeTool)
	ws := env.SetWorkspace(agentsession.WorkspaceContainer, "registry.example.invalid/fake@sha256:00")
	if err := ws.SetMember("host", fakeHost); err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, env)
	appendAt(t, s, c, user("my password is "+fakePassword+" and my key is "+fakeKey))
	base = turn(t, s, c, "resp-1", "noted, "+fakeKey+" from "+fakeHome+"/project")
	appendAt(t, s, c, user("secret-block: a private aside"))
	appendAt(t, s, c, user("read the file"))
	respond(t, s, c, "resp-2", call("call-r"))
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-r", "contents with "+fakePassword)))
	msg := openresponses.UserMessage(&openresponses.InputText{Text: "look"}, &openresponses.InputImage{ImageURL: fakeImage})
	appendAt(t, s, c, agentsession.NewItemEntry(msg))
	kept := turn(t, s, c, "resp-3", "I see it, "+fakeHome)
	appendAt(t, s, c, &agentsession.CustomEntry{NS: "fake.notes", Data: json.RawMessage(`{"note":"` + fakeKey + `"}`)})
	appendAt(t, s, c, agentsession.NewLabelEntry(kept, "kept "+fakePassword))
	comp, err := s.Compact(kept, openresponses.UserText("summary: the password was "+fakePassword))
	if err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, comp)
	appendAt(t, s, c, user("after the compaction, "+fakeKey))
	turn(t, s, c, "resp-4", "fine")
	return s, base
}

// checkClean holds every redaction in st to having no planted value,
// and every response in it to verifying, read from the store; and every
// finding to quoting none.
func checkClean(t *testing.T, st agentsession.Store, rep *StoreReport) {
	t.Helper()
	n := 0
	for id, file := range held(t, st) {
		s := read(t, st, id)
		if !s.Header().Redacted {
			continue
		}
		n++
		for _, v := range planted {
			if bytes.Contains(file, []byte(v)) {
				t.Errorf("redaction %s kept %q", id, v)
			}
		}
		for _, e := range s.Entries() {
			if r, ok := e.(*agentsession.ResponseEntry); ok && r.RequestHash != "" {
				if err := s.Verify(r.ID); err != nil {
					t.Errorf("redaction %s: response %s does not verify: %v", id, r.ResponseID, err)
				}
			}
		}
	}
	if n == 0 {
		t.Error("no redaction in the store")
	}
	for _, s := range rep.Sessions {
		for _, f := range s.Findings {
			for _, v := range planted {
				if strings.Contains(f.Message+f.At, v) {
					t.Errorf("finding %+v quotes %q", f, v)
				}
			}
		}
	}
	checkErrors(t, rep)
}

// checkErrors holds every error and warning in the report to naming no
// hash and quoting no planted value.
func checkErrors(t *testing.T, rep *StoreReport) {
	t.Helper()
	for _, s := range rep.Sessions {
		texts := slices.Clone(s.Warnings)
		if s.Err != nil {
			texts = append(texts, s.Err.Error())
		}
		for _, text := range texts {
			if hashRef.MatchString(text) {
				t.Errorf("%s: %q names a hash", s.Original, text)
			}
			for _, v := range planted {
				if strings.Contains(text, v) {
					t.Errorf("%s: %q quotes %q", s.Original, text, v)
				}
			}
		}
	}
}

// TestRedactStoreForkAndGrowth: an original and its fork, redacted into
// each store kind: the fork's redaction is a fork of the original's,
// their shared prefix the same entries, every response verifying. Both
// grow; a rerun appends exactly what a fresh pass into an empty copy
// writes beyond the first run, and equals it byte for byte; a third run
// writes nothing.
func TestRedactStoreForkAndGrowth(t *testing.T) {
	for _, kind := range storeKinds {
		t.Run(kind.name, func(t *testing.T) {
			c := &clock{}
			p := storeProfile()
			o, base := richOriginal(t, c, "orig-o")
			f := fork(t, o, base, "orig-f")
			appendAt(t, f, c, user("on the fork, "+fakeKey))
			turn(t, f, c, "resp-f", "forked in "+fakeHome)
			st := kind.open(t)
			load(t, st, o, f)

			rep := redactStore(t, st, p, StoreOptions{})
			got := bySession(rep)
			if len(rep.Sessions) != 2 || rep.Sessions[0].Original != o.ID() || rep.Sessions[1].Original != f.ID() {
				t.Fatalf("report %+v: want the origin, then the fork", rep.Sessions)
			}
			// The compaction's summary restates the block left out before
			// it: reported, and so not publishable unless accepted.
			if r := got[o.ID()]; !r.Created || r.Fork || r.Written == 0 || r.Publishable() || len(r.Findings) != 1 || r.Findings[0].Kind != FindingRestates {
				t.Errorf("origin %+v", r)
			}
			if r := got[f.ID()]; !r.Created || !r.Fork || r.Written != 3 || !r.Publishable() {
				t.Errorf("fork %+v: want created as a fork with its three own entries", r)
			}
			ro, rf := read(t, st, redID(o.ID())), read(t, st, redID(f.ID()))
			h := rf.Header()
			if h.ParentSession != ro.ID() || h.Base == "" {
				t.Fatalf("the fork's redaction: parent_session %q base %q, not a fork of %s", h.ParentSession, h.Base, ro.ID())
			}
			var prefix, path []string
			for _, e := range agentsession.FileOrder(rf) {
				if rf.Prefix(e.Base().ID) {
					prefix = append(prefix, e.Base().ID)
				}
			}
			for _, e := range ro.Path(h.Base) {
				path = append(path, e.Base().ID)
			}
			if len(prefix) == 0 || !slices.Equal(prefix, path) {
				t.Errorf("the shared prefix is not the origin's redaction's entries:\n%v\n%v", prefix, path)
			}
			checkClean(t, st, rep)

			nO, nF := len(agentsession.FileOrder(o)), len(agentsession.FileOrder(f))
			appendAt(t, o, c, user("secret-block: later aside"))
			appendAt(t, o, c, user("origin later, "+fakePassword))
			turn(t, o, c, "resp-5", "five")
			appendAt(t, f, c, user("fork later"))
			turn(t, f, c, "resp-g", "six")
			grow(t, st, o, nO)
			grow(t, st, f, nF)
			rep2 := redactStore(t, st, p, StoreOptions{})

			fresh := kind.open(t)
			load(t, fresh, o, f)
			frep := bySession(redactStore(t, fresh, p, StoreOptions{}))
			for _, id := range []string{o.ID(), f.ID()} {
				r2 := bySession(rep2)[id]
				if r2.Created || r2.Written != frep[id].Written-got[id].Written {
					t.Errorf("%s: the rerun wrote %d entries, a fresh pass %d beyond the first run's %d", id, r2.Written, frep[id].Written, got[id].Written)
				}
				if a, b := fileOf(t, read(t, st, redID(id))), fileOf(t, read(t, fresh, redID(id))); !bytes.Equal(a, b) {
					t.Errorf("%s: the grown redaction differs from a fresh pass:\n%s\n---\n%s", id, a, b)
				}
			}
			if bySession(rep2)[o.ID()].Written != 4 {
				t.Errorf("the origin grew by a placeholder and three entries; the rerun wrote %d", bySession(rep2)[o.ID()].Written)
			}
			checkClean(t, st, rep2)

			before := held(t, st)
			rep3 := redactStore(t, st, p, StoreOptions{AcceptFindings: []FindingKind{FindingRestates}})
			for _, r := range rep3.Sessions {
				if !r.UpToDate || r.Written != 0 || r.Created || r.Blobs != 0 || !r.Publishable() {
					t.Errorf("a rerun with nothing new, its findings accepted: %+v", r)
				}
			}
			if r := bySession(rep3)[o.ID()]; len(r.Findings) != 1 {
				t.Errorf("an up-to-date rerun reports %d findings, want the redaction's one", len(r.Findings))
			}
			after := held(t, st)
			if len(after) != len(before) {
				t.Errorf("a rerun changed the sessions held: %d, then %d", len(before), len(after))
			}
			for id, b := range before {
				if !bytes.Equal(after[id], b) {
					t.Errorf("a rerun changed %s", id)
				}
			}
		})
	}
}

// TestRedactStoreReferences: references into sessions the store holds
// point at their redactions: a parents element into another session, a
// subsession link, and the child's parent_session. A link to a session
// the store does not hold names its derived redaction too; a parents
// element naming an entry of one waits for it, on every run.
func TestRedactStoreReferences(t *testing.T) {
	for _, kind := range storeKinds {
		t.Run(kind.name, func(t *testing.T) {
			c := &clock{}
			p := storeProfile()
			parent := newOriginal("orig-parent")
			appendAt(t, parent, c, user("spawn a worker, "+fakeKey))
			respond(t, parent, c, "resp-1", call("call-sub"))
			childID := agentsession.SubsessionID(parent.ID(), "call-sub")
			appendAt(t, parent, c, agentsession.NewSubsessionLink(childID, "call-sub"))
			appendAt(t, parent, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-sub", "the worker said "+fakePassword)))
			answer := turn(t, parent, c, "resp-2", "done")

			child := agentsession.New(agentsession.Header{ID: childID, CreatedAt: t0, ParentSession: parent.ID(), SpawnedBy: "call-sub", CWD: fakeHome})
			appendAt(t, child, c, user("work in "+fakeHome))
			turn(t, child, c, "resp-c", "worked")

			merger := newOriginal("orig-merger")
			appendAt(t, merger, c, user("start"))
			conv := user("merged the parent's answer")
			conv.Parents = []agentsession.EntryRef{{Session: parent.ID(), Entry: answer}}
			appendAt(t, merger, c, conv)
			turn(t, merger, c, "resp-m", "merged")

			outside := newOriginal("orig-outside")
			appendAt(t, outside, c, user("first"))
			appendAt(t, outside, c, &agentsession.LinkEntry{Rel: agentsession.RelContinuedIn, Session: "fake-outside-session"})
			turn(t, outside, c, "resp-o", "ok")

			stranger := newOriginal("orig-stranger")
			stray := user("merged a stranger")
			stray.Parents = []agentsession.EntryRef{{Session: "fake-outside-session", Entry: agentsession.HashText("fake entry")}}
			appendAt(t, stranger, c, stray)

			st := kind.open(t)
			load(t, st, parent, child, merger, outside, stranger)
			rep := redactStore(t, st, p, StoreOptions{})
			got := bySession(rep)
			for _, r := range rep.Sessions {
				if r.Original == stranger.ID() {
					continue
				}
				if r.Err != nil || !r.Created || !r.Publishable() {
					t.Errorf("%s: %+v", r.Original, r)
				}
			}
			for run := range 2 {
				if r := got[stranger.ID()]; r.WaitingOn != "fake-outside-session" || r.Err != nil || r.Created || r.Publishable() {
					t.Errorf("run %d: the session naming an entry outside the store %+v, want it waiting", run, r)
				}
				if _, err := readHeld(context.Background(), st, redID(stranger.ID())); !errors.Is(err, agentsession.ErrNoSession) {
					t.Errorf("run %d: a waiting session's redaction was written: %v", run, err)
				}
				got = bySession(redactStore(t, st, p, StoreOptions{}))
			}
			var order []string
			for _, r := range rep.Sessions {
				order = append(order, r.Original)
			}
			if slices.Index(order, parent.ID()) > slices.Index(order, merger.ID()) {
				t.Errorf("order %v: the merger before the session it merges from", order)
			}

			rp, rc, rm, ro := read(t, st, redID(parent.ID())), read(t, st, redID(childID)), read(t, st, redID(merger.ID())), read(t, st, redID(outside.ID()))
			var link *agentsession.LinkEntry
			for _, e := range rp.Entries() {
				if l, ok := e.(*agentsession.LinkEntry); ok {
					link = l
				}
			}
			if link == nil || link.Session != rc.ID() || link.CallID != "call-sub" {
				t.Errorf("the subsession link %+v, want the child's redaction %s", link, rc.ID())
			}
			if h := rc.Header(); h.ParentSession != rp.ID() || h.SpawnedBy != "call-sub" {
				t.Errorf("the child's redaction: parent_session %q spawned_by %q, want %s", h.ParentSession, h.SpawnedBy, rp.ID())
			}
			pos := slices.IndexFunc(agentsession.FileOrder(parent), func(e agentsession.Entry) bool { return e.Base().ID == answer }) + 1
			var answerRed string
			for _, e := range rp.Entries() {
				if spans, _ := agentsession.RedactedOf(e); markKey(spans) == markKey(markOf(pos, false)) {
					answerRed = e.Base().ID
				}
			}
			var merged []agentsession.EntryRef
			for _, e := range rm.Entries() {
				if len(e.Base().Parents) > 0 {
					merged = e.Base().Parents
				}
			}
			if len(merged) != 1 || merged[0].Session != rp.ID() || merged[0].Entry != answerRed || answerRed == "" {
				t.Errorf("the merger's parents %+v, want {%s %s}", merged, rp.ID(), answerRed)
			}
			for redaction, others := range map[*agentsession.Session][]string{
				rp: {childID, merger.ID()}, rc: {parent.ID()}, rm: {parent.ID(), answer},
			} {
				file := fileOf(t, redaction)
				for _, o := range others {
					if bytes.Contains(file, []byte(o)) {
						t.Errorf("%s names the original %s", redaction.ID(), o)
					}
				}
			}
			if file := fileOf(t, ro); bytes.Contains(file, []byte("fake-outside-session")) || !bytes.Contains(file, []byte(redID("fake-outside-session"))) {
				t.Error("the link outside the store does not name the derived redaction alone")
			}
			for _, id := range []string{parent.ID(), childID, merger.ID(), outside.ID()} {
				if len(got[id].Findings) != 0 {
					t.Errorf("%s: findings %+v", id, got[id].Findings)
				}
			}
			checkClean(t, st, rep)
		})
	}
}

// TestRedactStoreSkipsAndNative: the redactions a store holds, under
// any profile, are never redacted; a redaction someone resumed natively
// is reported as not publishable, and still grows with its original.
func TestRedactStoreSkipsAndNative(t *testing.T) {
	for _, kind := range storeKinds {
		t.Run(kind.name, func(t *testing.T) {
			ctx := context.Background()
			c := &clock{}
			p := storeProfile()
			o, _ := richOriginal(t, c, "orig-o")
			other := redact(t, testProfile(), o, nil).Session
			st := kind.open(t)
			load(t, st, o, other)

			rep := redactStore(t, st, p, StoreOptions{})
			if rep.Skipped != 1 || len(rep.Sessions) != 1 || rep.Sessions[0].Original != o.ID() {
				t.Fatalf("report %+v: want the original alone, the other profile's redaction skipped", rep)
			}
			if _, err := st.Append(ctx, redID(o.ID()), user("a native note")); err != nil {
				t.Fatal(err)
			}
			if rl, ok := st.(interface{ Release(string) error }); ok {
				if err := rl.Release(redID(o.ID())); err != nil {
					t.Fatal(err)
				}
			}
			n := len(agentsession.FileOrder(o))
			appendAt(t, o, c, user("later"))
			turn(t, o, c, "resp-9", "nine")
			grow(t, st, o, n)

			rep = redactStore(t, st, p, StoreOptions{})
			if rep.Skipped != 2 || len(rep.Sessions) != 1 {
				t.Fatalf("report %+v: want both redactions skipped", rep)
			}
			r := rep.Sessions[0]
			if r.Err != nil || r.Native != 1 || r.Publishable() || r.Written != 3 {
				t.Errorf("a natively resumed redaction: %+v, want 3 written, 1 native, not publishable", r)
			}
			for id, file := range held(t, st) {
				s := read(t, st, id)
				if from := s.Header().RedactedFrom; from != nil && (from.Session == other.ID() || from.Session == redID(o.ID())) {
					t.Errorf("%s is a redaction of a redaction", id)
				}
				if id == other.ID() && !bytes.Equal(file, fileOf(t, other)) {
					t.Error("the other profile's redaction changed")
				}
			}
		})
	}
}

// TestRedactStoreBlobs: a sidecar image's replacement is written as a
// blob where the store takes blobs; where it takes none the redaction
// is not written, its fork is stopped, and an unrelated session is
// redacted.
func TestRedactStoreBlobs(t *testing.T) {
	for _, kind := range storeKinds {
		t.Run(kind.name, func(t *testing.T) {
			ctx := context.Background()
			c := &clock{}
			p := storeProfile()
			s := agentsession.New(agentsession.Header{ID: "orig-sidecar", CreatedAt: t0, Media: agentsession.MediaSidecar})
			appendAt(t, s, c, user("first"))
			base := turn(t, s, c, "resp-1", "one")
			appendAt(t, s, c, agentsession.NewItemEntry(openresponses.UserMessage(
				&openresponses.InputImage{ImageURL: "sidecar:" + agentsession.HashText("FAKE-IMAGE-BLOB-0003")})))
			turn(t, s, c, "resp-2", "an image")
			f := fork(t, s, base, "orig-sidecar-fork")
			appendAt(t, f, c, user("on the fork"))
			u, _ := richOriginal(t, c, "orig-unrelated")
			st := kind.open(t)
			load(t, st, s, f, u)

			rep, err := RedactStore(ctx, st, p, StoreOptions{})
			got := bySession(rep)
			placeholder, _ := placeholderBytes(DefaultImagePlaceholder)
			hash := agentsession.HashBytes(placeholder)
			if kind.blobs {
				if err != nil {
					t.Fatalf("RedactStore: %v", err)
				}
				if r := got[s.ID()]; r.Blobs != 1 || !r.Created {
					t.Errorf("the sidecar session %+v, want one blob", r)
				}
				blob, err := st.(BlobWriter).(interface {
					Blob(context.Context, string) ([]byte, error)
				}).Blob(ctx, hash)
				if err != nil || !bytes.Equal(blob, placeholder) {
					t.Errorf("the blob %s: %v", hash, err)
				}
				if !bytes.Contains(fileOf(t, read(t, st, redID(s.ID()))), []byte("sidecar:"+hash)) {
					t.Error("the redaction does not name the replacement")
				}
				if r := got[f.ID()]; r.Err != nil || !r.Fork {
					t.Errorf("the fork %+v", r)
				}
				if r := bySession(redactStore(t, st, p, StoreOptions{}))[s.ID()]; r.Blobs != 0 || !r.UpToDate {
					t.Errorf("a rerun of the sidecar session %+v, want no blob written", r)
				}
				return
			}
			if !errors.Is(err, ErrNoBlobWriter) {
				t.Errorf("RedactStore: %v, want ErrNoBlobWriter", err)
			}
			if r := got[s.ID()]; !errors.Is(r.Err, ErrNoBlobWriter) || r.Created {
				t.Errorf("the sidecar session %+v, want ErrNoBlobWriter", r)
			}
			if _, err := readHeld(ctx, st, redID(s.ID())); !errors.Is(err, agentsession.ErrNoSession) {
				t.Errorf("the redaction naming a blob the store lacks was written: %v", err)
			}
			if r := got[f.ID()]; !errors.Is(r.Err, ErrDependency) {
				t.Errorf("the fork %+v, want ErrDependency", r)
			}
			if r := got[u.ID()]; r.Err != nil || !r.Created {
				t.Errorf("the unrelated session %+v", r)
			}
		})
	}
}

// TestRedactStoreFailures: a session that fails stops the sessions that
// depend on it, its fork and one merging from it, and sessions in a
// cycle are refused with what depends on them; every other session is
// redacted.
func TestRedactStoreFailures(t *testing.T) {
	c := &clock{}
	p := storeProfile()
	bad := newOriginal("orig-bad")
	early := appendAt(t, bad, c, user("first"))
	appendAt(t, bad, c, &agentsession.CustomEntry{NS: "fake.notes", Data: json.RawMessage(`{"` + fakePassword + `":1}`)})
	badFork := fork(t, bad, early, "orig-bad-fork")
	onFork := appendAt(t, badFork, c, user("on the fork"))
	chained := newOriginal("orig-chained") // merges from the fork: stopped two steps away
	via := user("merged from the fork")
	via.Parents = []agentsession.EntryRef{{Session: badFork.ID(), Entry: onFork}}
	appendAt(t, chained, c, via)
	merger := newOriginal("orig-merger")
	conv := user("merged")
	conv.Parents = []agentsession.EntryRef{{Session: bad.ID(), Entry: early}}
	appendAt(t, merger, c, conv)
	cycle := func(id, other string) *agentsession.Session {
		s := newOriginal(id)
		e := user("names " + other)
		e.Parents = []agentsession.EntryRef{{Session: other, Entry: agentsession.HashText("fake " + other)}}
		appendAt(t, s, c, e)
		return s
	}
	a, b, d := cycle("orig-cycle-a", "orig-cycle-b"), cycle("orig-cycle-b", "orig-cycle-a"), cycle("orig-cycle-d", "orig-cycle-a")
	good, _ := richOriginal(t, c, "orig-good")
	st := agentsession.NewMemoryStore()
	load(t, st, bad, badFork, chained, merger, a, b, d, good)

	rep, err := RedactStore(context.Background(), st, p, StoreOptions{})
	if err == nil {
		t.Error("no error for the sessions that failed")
	}
	got := bySession(rep)
	if len(rep.Sessions) != 8 {
		t.Errorf("%d sessions reported, want 8", len(rep.Sessions))
	}
	if r := got[chained.ID()]; !errors.Is(r.Err, ErrDependency) || !strings.Contains(r.Err.Error(), badFork.ID()) {
		t.Errorf("a session merging from a stopped fork: %+v, want ErrDependency naming the fork", r)
	}
	for id, want := range map[string]error{
		bad.ID(): ErrKeyNotRedacted, badFork.ID(): ErrDependency, merger.ID(): ErrDependency,
		a.ID(): ErrCycle, b.ID(): ErrCycle, d.ID(): ErrCycle,
	} {
		if r := got[id]; !errors.Is(r.Err, want) || r.Created {
			t.Errorf("%s: %+v, want %v", id, r, want)
		}
		if !errors.Is(err, want) {
			t.Errorf("the error returned does not wrap %v", want)
		}
		if _, err := st.Read(context.Background(), redID(id)); !errors.Is(err, agentsession.ErrNoSession) {
			t.Errorf("%s: a redaction was written", id)
		}
	}
	if r := got[good.ID()]; r.Err != nil || !r.Created {
		t.Errorf("the unrelated session %+v", r)
	}
	checkErrors(t, rep)
}

// TestRedactStoreSelect: a selection takes the sessions it depends on
// with it.
func TestRedactStoreSelect(t *testing.T) {
	c := &clock{}
	p := storeProfile()
	o, base := richOriginal(t, c, "orig-o")
	f := fork(t, o, base, "orig-f")
	appendAt(t, f, c, user("on the fork"))
	u, _ := richOriginal(t, c, "orig-u")
	st := agentsession.NewMemoryStore()
	load(t, st, o, f, u)
	rep := redactStore(t, st, p, StoreOptions{Select: func(h agentsession.Header) bool { return h.ID == f.ID() }})
	var ids []string
	for _, r := range rep.Sessions {
		ids = append(ids, r.Original)
	}
	if strings.Join(ids, " ") != o.ID()+" "+f.ID() {
		t.Errorf("redacted %v, want the fork's origin, then the fork", ids)
	}
	if r := bySession(rep)[f.ID()]; !r.Fork {
		t.Errorf("the fork %+v, want a fork of its origin's redaction", r)
	}
}

// TestRedactStoreBaseLeftOut: a fork whose base the origin's redaction
// dropped is redacted without a base, and resumes so.
func TestRedactStoreBaseLeftOut(t *testing.T) {
	c := &clock{}
	p := structProfile("test.leaf@1", nil, KeepLeafPath())
	o := newOriginal("orig-o")
	root := userAt(t, o, c, "", "first")
	base := turn(t, o, c, "resp-1", "one")
	if err := o.Branch(userAt(t, o, c, root, "the leaf's branch")); err != nil {
		t.Fatal(err)
	}
	turn(t, o, c, "resp-2", "two")
	f := fork(t, o, base, "orig-f")
	appendAt(t, f, c, user("on the fork"))
	st := agentsession.NewMemoryStore()
	load(t, st, o, f)
	for run := range 2 {
		rep := redactStore(t, st, p, StoreOptions{})
		r := bySession(rep)[f.ID()]
		if r.Err != nil || r.Fork || r.Created != (run == 0) {
			t.Errorf("run %d: the fork %+v, want it redacted without a base", run, r)
		}
		if h := read(t, st, agentsession.RedactedSessionID(f.ID(), p.Name)).Header(); h.Base != "" || h.ParentSession != agentsession.RedactedSessionID(o.ID(), p.Name) {
			t.Errorf("run %d: header base %q parent_session %q", run, h.Base, h.ParentSession)
		}
	}
}

// TestRedactStoreFindingsEveryRun: a finding is reported on every run,
// an up-to-date one included, and keeps the redaction from being
// publishable unless its kind is accepted.
func TestRedactStoreFindingsEveryRun(t *testing.T) {
	c := &clock{}
	p := storeProfile()
	s := agentsession.New(agentsession.Header{ID: "orig-pdf", CreatedAt: t0, Media: agentsession.MediaSidecar})
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.UserMessage(
		&openresponses.InputText{Text: "read this"},
		&openresponses.InputFile{Filename: "fake.pdf", FileData: "sidecar:" + agentsession.HashText("FAKE-PDF-BLOB-0004")})))
	turn(t, s, c, "resp-1", "read")
	st := agentsession.NewMemoryStore()
	load(t, st, s)
	for run := range 2 {
		r := bySession(redactStore(t, st, p, StoreOptions{}))[s.ID()]
		if len(r.Findings) != 1 || r.Findings[0].Kind != FindingSidecarMedia || r.Publishable() || r.UpToDate != (run == 1) {
			t.Errorf("run %d: %+v, want the sidecar PDF reported and not publishable", run, r)
		}
	}
	if r := bySession(redactStore(t, st, p, StoreOptions{AcceptFindings: []FindingKind{FindingSidecarMedia}}))[s.ID()]; !r.Publishable() {
		t.Errorf("with the kind accepted: %+v, want publishable", r)
	}
}

// TestRedactStoreArrivalOrder: what is written does not depend on the
// order sessions arrived in. A session naming an entry of one the store
// does not hold yet waits, with nothing written, and is redacted once
// it arrives; a subsession child redacted before its parent arrives
// names the parent's redaction from the first. Each ends equal to a
// fresh pass over the final store.
func TestRedactStoreArrivalOrder(t *testing.T) {
	c := &clock{}
	p := storeProfile()
	target := newOriginal("orig-target")
	appendAt(t, target, c, user("the answer is "+fakeKey))
	answer := turn(t, target, c, "resp-t", "forty-two")
	merger := newOriginal("orig-merger")
	conv := user("merged the answer")
	conv.Parents = []agentsession.EntryRef{{Session: target.ID(), Entry: answer}}
	appendAt(t, merger, c, conv)
	turn(t, merger, c, "resp-m", "merged")
	mergerFork := fork(t, merger, conv.ID, "orig-merger-fork")
	appendAt(t, mergerFork, c, user("on the merger's fork"))

	parent := newOriginal("orig-parent")
	appendAt(t, parent, c, user("spawn"))
	respond(t, parent, c, "resp-1", call("call-sub"))
	childID := agentsession.SubsessionID(parent.ID(), "call-sub")
	appendAt(t, parent, c, agentsession.NewSubsessionLink(childID, "call-sub"))
	appendAt(t, parent, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-sub", "done")))
	turn(t, parent, c, "resp-2", "done")
	child := agentsession.New(agentsession.Header{ID: childID, CreatedAt: t0, ParentSession: parent.ID(), SpawnedBy: "call-sub"})
	appendAt(t, child, c, user("work"))
	turn(t, child, c, "resp-c", "worked")

	for _, kind := range storeKinds {
		t.Run(kind.name, func(t *testing.T) {
			st := kind.open(t)
			load(t, st, merger, mergerFork, child)
			rep := redactStore(t, st, p, StoreOptions{})
			got := bySession(rep)
			if r := got[merger.ID()]; r.WaitingOn != target.ID() || r.Created {
				t.Errorf("the merger before its target arrived: %+v, want waiting on it", r)
			}
			if r := got[mergerFork.ID()]; r.WaitingOn != merger.ID() || r.Err != nil {
				t.Errorf("the merger's fork: %+v, want waiting on the merger", r)
			}
			if r := got[childID]; !r.Created {
				t.Errorf("the child before its parent arrived: %+v", r)
			}
			if h := read(t, st, redID(childID)).Header(); h.ParentSession != redID(parent.ID()) {
				t.Errorf("the child's parent_session %q, want the parent's redaction", h.ParentSession)
			}
			checkErrors(t, rep)

			load(t, st, target, parent)
			rep = redactStore(t, st, p, StoreOptions{})
			for _, r := range rep.Sessions {
				if r.Err != nil || r.WaitingOn != "" {
					t.Errorf("after the arrivals: %+v", r)
				}
			}
			if r := bySession(rep)[childID]; !r.UpToDate {
				t.Errorf("the child, its parent arrived: %+v, want up to date", r)
			}
			fresh := kind.open(t)
			load(t, fresh, target, merger, mergerFork, parent, child)
			redactStore(t, fresh, p, StoreOptions{})
			for _, id := range []string{target.ID(), merger.ID(), mergerFork.ID(), parent.ID(), childID} {
				if a, b := fileOf(t, read(t, st, redID(id))), fileOf(t, read(t, fresh, redID(id))); !bytes.Equal(a, b) {
					t.Errorf("%s: arrival order changed the redaction:\n%s\n---\n%s", id, a, b)
				}
			}
		})
	}
}

// TestRedactStoreRootAppend: a redaction that grew a new root is
// refused before anything is written, on every run.
func TestRedactStoreRootAppend(t *testing.T) {
	c := &clock{}
	p := structProfile("test.root@1", []EntryRedactor{LeaveOut(userWith("omit me"))})
	o := newOriginal("orig-root")
	first := appendAt(t, o, c, user("omit me"))
	appendAt(t, o, c, user("kept"))
	turn(t, o, c, "resp-1", "one")
	st := agentsession.NewMemoryStore()
	load(t, st, o)
	redactStore(t, st, p, StoreOptions{})
	before := fileOf(t, read(t, st, agentsession.RedactedSessionID(o.ID(), p.Name)))
	n := len(agentsession.FileOrder(o))
	userAt(t, o, c, first, "an edited prompt")
	grow(t, st, o, n)
	for run := range 2 {
		rep, err := RedactStore(context.Background(), st, p, StoreOptions{})
		if r := bySession(rep)[o.ID()]; !errors.Is(r.Err, ErrRootAppend) || !errors.Is(err, ErrRootAppend) || r.Written != 0 {
			t.Errorf("run %d: %+v, want ErrRootAppend", run, r)
		}
	}
	if after := fileOf(t, read(t, st, agentsession.RedactedSessionID(o.ID(), p.Name))); !bytes.Equal(after, before) {
		t.Error("something was written for a redaction that grew a root")
	}
}

// TestRedactStoreForkBaseNotYet: a fork whose base the origin's snapshot
// does not hold yet waits, and is redacted as a fork once it does; it is
// never created without a base.
func TestRedactStoreForkBaseNotYet(t *testing.T) {
	c := &clock{}
	p := storeProfile()
	o := newOriginal("orig-o")
	appendAt(t, o, c, user("first"))
	turn(t, o, c, "resp-1", "one")
	early, err := agentsession.Read(bytes.NewReader(fileOf(t, o)))
	if err != nil {
		t.Fatal(err)
	}
	n := len(agentsession.FileOrder(o))
	appendAt(t, o, c, user("second"))
	base := turn(t, o, c, "resp-2", "two")
	f := fork(t, o, base, "orig-f")
	appendAt(t, f, c, user("on the fork"))
	st := agentsession.NewMemoryStore()
	load(t, st, early, f)
	if r := bySession(redactStore(t, st, p, StoreOptions{}))[f.ID()]; r.WaitingOn != o.ID() || r.Created {
		t.Errorf("a fork whose base the origin does not hold yet: %+v, want waiting", r)
	}
	if _, err := st.Read(context.Background(), redID(f.ID())); !errors.Is(err, agentsession.ErrNoSession) {
		t.Errorf("the fork's redaction was written: %v", err)
	}
	grow(t, st, o, n)
	if r := bySession(redactStore(t, st, p, StoreOptions{}))[f.ID()]; !r.Created || !r.Fork {
		t.Errorf("the fork once its base arrived: %+v, want created as a fork", r)
	}
}

// TestRedactStoreLineOfForks: O, F a fork of O and G a fork of F, each
// redacted as a fork of its origin's redaction, grown and rerun equal
// to a fresh pass.
func TestRedactStoreLineOfForks(t *testing.T) {
	c := &clock{}
	p := storeProfile()
	o := newOriginal("orig-o")
	appendAt(t, o, c, user("first "+fakeKey))
	baseF := turn(t, o, c, "resp-1", "one")
	f := fork(t, o, baseF, "orig-f")
	appendAt(t, f, c, user("on f"))
	baseG := turn(t, f, c, "resp-f", "f")
	g := fork(t, f, baseG, "orig-g")
	appendAt(t, g, c, user("on g, "+fakePassword))
	turn(t, g, c, "resp-g", "g")
	for _, kind := range storeKinds {
		t.Run(kind.name, func(t *testing.T) {
			st := kind.open(t)
			load(t, st, g, f, o)
			rep := redactStore(t, st, p, StoreOptions{})
			var order []string
			for _, r := range rep.Sessions {
				order = append(order, r.Original)
				if !r.Created || r.Fork != (r.Original != o.ID()) {
					t.Errorf("%s: %+v", r.Original, r)
				}
			}
			if strings.Join(order, " ") != "orig-o orig-f orig-g" {
				t.Errorf("order %v", order)
			}
			rf, rg := read(t, st, redID(f.ID())), read(t, st, redID(g.ID()))
			if h := rg.Header(); h.ParentSession != rf.ID() || h.Base == "" {
				t.Errorf("G's redaction: parent_session %q base %q, want a fork of %s", h.ParentSession, h.Base, rf.ID())
			} else if _, ok := rf.Entry(h.Base); !ok {
				t.Error("G's base is not an entry of F's redaction")
			}
			if h := rf.Header(); h.ParentSession != redID(o.ID()) || h.Base == "" {
				t.Errorf("F's redaction: parent_session %q base %q", h.ParentSession, h.Base)
			}
			checkClean(t, st, rep)
		})
	}
}

// releaseCounter is a memory store that counts each Release and can
// refuse an append.
type releaseCounter struct {
	*agentsession.MemoryStore
	released  map[string]int
	appends   int
	failAfter int // refuse the append numbered this; 0 refuses none
}

func (s *releaseCounter) Release(id string) error {
	s.released[id]++
	return nil
}

func (s *releaseCounter) Append(ctx context.Context, id string, e agentsession.Entry) (string, error) {
	s.appends++
	if s.appends == s.failAfter {
		return "", errors.New("fake: the disk is full")
	}
	return s.MemoryStore.Append(ctx, id, e)
}

// TestRedactStoreReleases: the pass lets each redaction it wrote go,
// after an import, after appends, and after an append that failed part
// way; the next run resumes and equals a fresh pass.
func TestRedactStoreReleases(t *testing.T) {
	c := &clock{}
	p := storeProfile()
	o, _ := richOriginal(t, c, "orig-o")
	st := &releaseCounter{MemoryStore: agentsession.NewMemoryStore(), released: map[string]int{}}
	load(t, st, o)
	red := redID(o.ID())
	redactStore(t, st, p, StoreOptions{})
	if st.released[red] != 1 {
		t.Errorf("released %d times after the import, want 1", st.released[red])
	}
	n := len(agentsession.FileOrder(o))
	appendAt(t, o, c, user("later"))
	turn(t, o, c, "resp-9", "nine")
	grow(t, st, o, n)
	st.failAfter = st.appends + 2
	rep, err := RedactStore(context.Background(), st, p, StoreOptions{})
	if r := bySession(rep)[o.ID()]; err == nil || r.Err == nil || r.Written != 1 {
		t.Errorf("an append refused part way: %+v", r)
	}
	if st.released[red] != 2 {
		t.Errorf("released %d times after a failed append, want 2", st.released[red])
	}
	checkErrors(t, rep)
	st.failAfter = 0
	if r := bySession(redactStore(t, st, p, StoreOptions{}))[o.ID()]; r.Err != nil || r.Written != 2 {
		t.Errorf("the run after: %+v, want the two entries left", r)
	}
	if st.released[red] != 3 {
		t.Errorf("released %d times, want 3", st.released[red])
	}
	fresh := agentsession.NewMemoryStore()
	load(t, fresh, o)
	redactStore(t, fresh, p, StoreOptions{})
	if !bytes.Equal(fileOf(t, read(t, st, red)), fileOf(t, read(t, fresh, red))) {
		t.Error("the redaction resumed after a failed append differs from a fresh pass")
	}
}

// TestRedactStoreHead: a redaction grown on a branch has the head an
// import of the same file gives, as a fresh pass's has.
func TestRedactStoreHead(t *testing.T) {
	for _, kind := range storeKinds {
		t.Run(kind.name, func(t *testing.T) {
			c := &clock{}
			p := storeProfile()
			o := newOriginal("orig-o")
			first := appendAt(t, o, c, user("first"))
			turn(t, o, c, "resp-1", "one")
			st := kind.open(t)
			load(t, st, o)
			redactStore(t, st, p, StoreOptions{})
			n := len(agentsession.FileOrder(o))
			userAt(t, o, c, first, "a branch")
			grow(t, st, o, n)
			rep := redactStore(t, st, p, StoreOptions{})
			if r := bySession(rep)[o.ID()]; r.Written != 1 || len(r.Warnings) != 0 {
				t.Errorf("%+v", r)
			}
			fresh := kind.open(t)
			load(t, fresh, o)
			redactStore(t, fresh, p, StoreOptions{})
			if a, b := read(t, st, redID(o.ID())).Leaf(), read(t, fresh, redID(o.ID())).Leaf(); a != b || a == "" {
				t.Errorf("the grown redaction's head %s, a fresh one's %s", a, b)
			}
		})
	}
}

// openOnly is a store with no Reader: the pass opens what it reads.
type openOnly struct {
	m        *agentsession.MemoryStore
	released map[string]int
}

func (s *openOnly) Create(ctx context.Context, h agentsession.Header) (*agentsession.Session, error) {
	return s.m.Create(ctx, h)
}
func (s *openOnly) Open(ctx context.Context, id string) (*agentsession.Session, error) {
	return s.m.Open(ctx, id)
}
func (s *openOnly) Append(ctx context.Context, id string, e agentsession.Entry) (string, error) {
	return s.m.Append(ctx, id, e)
}
func (s *openOnly) List(ctx context.Context, f agentsession.ListFilter) iter.Seq2[agentsession.Summary, error] {
	return s.m.List(ctx, f)
}
func (s *openOnly) Delete(ctx context.Context, id string) error { return s.m.Delete(ctx, id) }
func (s *openOnly) Import(ctx context.Context, r io.Reader, asRecord bool) (*agentsession.Session, error) {
	return s.m.Import(ctx, r, asRecord)
}
func (s *openOnly) Release(id string) error {
	s.released[id]++
	return nil
}

// TestRedactStoreOpenOnly: over a store with no Reader, the pass lets
// go of the sessions it opened to read, and still grows a redaction
// equal to a fresh pass.
func TestRedactStoreOpenOnly(t *testing.T) {
	c := &clock{}
	p := storeProfile()
	o, _ := richOriginal(t, c, "orig-o")
	st := &openOnly{m: agentsession.NewMemoryStore(), released: map[string]int{}}
	load(t, st, o)
	redactStore(t, st, p, StoreOptions{})
	if st.released[o.ID()] == 0 {
		t.Error("the original opened to read was not let go")
	}
	n := len(agentsession.FileOrder(o))
	appendAt(t, o, c, user("later"))
	turn(t, o, c, "resp-9", "nine")
	grow(t, st, o, n)
	if r := bySession(redactStore(t, st, p, StoreOptions{}))[o.ID()]; r.Written != 3 {
		t.Errorf("%+v, want three entries appended", r)
	}
	fresh := agentsession.NewMemoryStore()
	load(t, fresh, o)
	redactStore(t, fresh, p, StoreOptions{})
	got, _ := st.m.Read(context.Background(), redID(o.ID()))
	if !bytes.Equal(fileOf(t, got), fileOf(t, read(t, fresh, redID(o.ID())))) {
		t.Error("the redaction the store holds differs from a fresh pass")
	}
}
