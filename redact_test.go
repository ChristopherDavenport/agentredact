package agentredact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image/png"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// Every value planted here is synthetic: obviously fake keys and
// passwords, the home of a user called example, and an image whose
// bytes are a marker.
const (
	fakePassword = "hunter2-fake-password"
	fakeKey      = "sk-test-0000000000000000000000000000"
	fakeHome     = "/home/example"
	fakeRevision = "0000000000000000000000000000000000fake01"
	fakeHost     = "build-host.example.invalid"
	fakeTool     = "9.9.9-fake"
)

// fakeImage is a data URL whose payload decodes to a marker.
var fakeImage = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("FAKE-IMAGE-BYTES-0001"))

// planted are the strings no redaction may keep.
var planted = []string{fakePassword, fakeKey, fakeHome, "example/", fakeRevision, fakeHost, fakeTool, fakeImage[len("data:image/png;base64,"):]}

func testProfile() Profile {
	return Profile{
		Name:    "test.default@1",
		Strings: []StringRedactor{Secrets(fakePassword), HomePaths(fakeHome), DefaultPatterns()},
		Entries: []EntryRedactor{Environment(), Images(DefaultImagePlaceholder)},
	}
}

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// clock gives each entry its own timestamp, a second apart, so a case
// is the same on every run.
type clock struct{ n int }

func (c *clock) next() time.Time { c.n++; return t0.Add(time.Duration(c.n) * time.Second) }

func appendAt(t *testing.T, s *agentsession.Session, c *clock, e agentsession.Entry) string {
	t.Helper()
	e.Base().Timestamp = c.next()
	id, err := s.Append(e)
	if err != nil {
		t.Fatalf("append %s: %v", e.EntryType(), err)
	}
	return id
}

func user(text string) *agentsession.ItemEntry {
	return agentsession.NewItemEntry(openresponses.UserText(text))
}

// turn appends an assistant reply and its response, with a request
// hash that verifies in the original.
func turn(t *testing.T, s *agentsession.Session, c *clock, respID, text string) string {
	t.Helper()
	reply := agentsession.NewItemEntry(openresponses.AssistantText(text))
	reply.ResponseID = respID
	appendAt(t, s, c, reply)
	resp := &agentsession.ResponseEntry{ResponseID: respID, Status: openresponses.ResponseStatusCompleted, RequestHash: "sha256:to-compute"}
	if err := s.SetRequestHash(resp); err != nil {
		t.Fatal(err)
	}
	id := appendAt(t, s, c, resp)
	if err := s.Verify(id); err != nil {
		t.Fatalf("the original's response does not verify: %v", err)
	}
	return id
}

func newOriginal(id string) *agentsession.Session {
	return agentsession.New(agentsession.Header{
		ID:        id,
		CreatedAt: t0,
		CWD:       fakeHome + "/project",
		Harness:   &agentsession.Harness{Name: "fake-harness", Version: "1.0"},
		Extra:     map[string]json.RawMessage{"fake:note": json.RawMessage(`{"where":"` + fakeHome + `/notes","n":1}`)},
	})
}

// plainOriginal is a session holding the secrets on two branches, an
// env entry, a label naming an entry, and responses that verify.
func plainOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := newOriginal("orig-plain")
	env := agentsession.NewEnvEntry(fakeHome + "/project")
	env.VCS = &agentsession.VCS{System: "git", Revision: fakeRevision, Dirty: true}
	env.AddRead(fakeHome+"/project/main.go", agentsession.HashText("fake file"))
	env.AddTool("go", fakeTool)
	ws := env.SetWorkspace(agentsession.WorkspaceContainer, "registry.example.invalid/fake@sha256:00")
	if err := ws.SetMember("host", fakeHost); err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, env)
	root := appendAt(t, s, c, user("my password is "+fakePassword+" and my key is "+fakeKey))
	turn(t, s, c, "resp-1", "noted, I will not repeat "+fakeKey+" from "+fakeHome+"/project")
	appendAt(t, s, c, user("read "+fakeHome+"/project/main.go"))
	turn(t, s, c, "resp-2", "done")
	other := user("forget " + fakePassword)
	other.Parent = root
	b := appendAt(t, s, c, other)
	appendAt(t, s, c, agentsession.NewLabelEntry(b, "kept "+fakePassword))
	return s
}

// compactionOriginal is plainOriginal folded by a compaction whose
// summary holds a secret, with a turn after it.
func compactionOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := newOriginal("orig-compaction")
	appendAt(t, s, c, user("first "+fakePassword))
	turn(t, s, c, "resp-1", "ok "+fakeKey)
	kept := appendAt(t, s, c, user("second, in "+fakeHome))
	turn(t, s, c, "resp-2", "ok")
	comp, err := s.Compact(kept, openresponses.UserText("summary: the password was "+fakePassword))
	if err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, comp)
	appendAt(t, s, c, user("after the fold, "+fakeKey))
	turn(t, s, c, "resp-3", "fine")
	return s
}

// partsOriginal sets instructions from parts holding secrets, then a
// delta that names unchanged parts by hash, with a turn under each.
func partsOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := newOriginal("orig-parts")
	parts := []agentsession.InstructionPart{
		{ID: "base", Text: "You work in " + fakeHome + "/project."},
		{ID: "keys", Text: "Never print " + fakeKey + "."},
	}
	cfg := agentsession.Settings{}.InstructionsDelta(parts)
	cfg.Model = "fake-model"
	appendAt(t, s, c, cfg)
	appendAt(t, s, c, user("hello"))
	turn(t, s, c, "resp-1", "hi")
	ctx, err := s.Context()
	if err != nil {
		t.Fatal(err)
	}
	// Reordered, so the unchanged parts are named by the hash of their
	// text, which the first config entry holds.
	parts = []agentsession.InstructionPart{parts[1], {ID: "extra", Text: "The password is " + fakePassword + "."}, parts[0]}
	delta := ctx.Settings.InstructionsDelta(parts)
	if delta == nil || delta.InstructionsParts[0].Hash == "" || delta.InstructionsParts[2].Hash == "" {
		t.Fatalf("the delta does not name parts by hash: %+v", delta)
	}
	appendAt(t, s, c, delta)
	appendAt(t, s, c, user("again"))
	turn(t, s, c, "resp-2", "hi again")
	return s
}

// wantInstructions checks that the redacted session's instructions at
// its leaf resolve, every part, to the rewritten texts.
func wantInstructions(t *testing.T, red *agentsession.Session, want string) {
	t.Helper()
	ctx, err := red.Context()
	if err != nil {
		t.Fatal(err)
	}
	if got := ctx.Settings.Instructions; got != want {
		t.Errorf("instructions %q, want %q", got, want)
	}
}

const partsRedacted = "Never print [REDACTED openai_key].\n\nThe password is [REDACTED].\n\nYou work in ~/project."

// TestRedactPartsByHash: parts named by hash resolve to the rewritten
// texts, in a fresh redaction and in one resumed past the entry that
// holds them, which only works when the Rewriter met that entry again.
func TestRedactPartsByHash(t *testing.T) {
	want := partsRedacted
	c := &clock{}
	orig := partsOriginal(t, c)
	p := testProfile()
	wantInstructions(t, redact(t, p, orig, nil).Session, want)

	// Redact only up to the first config entry's turn, then resume past
	// the delta that names its parts by hash.
	s := newOriginal("orig-parts")
	parts := []agentsession.InstructionPart{
		{ID: "base", Text: "You work in " + fakeHome + "/project."},
		{ID: "keys", Text: "Never print " + fakeKey + "."},
	}
	cfg := agentsession.Settings{}.InstructionsDelta(parts)
	c = &clock{}
	appendAt(t, s, c, cfg)
	appendAt(t, s, c, user("hello"))
	turn(t, s, c, "resp-1", "hi")
	first := redact(t, p, s, nil)
	ctx, err := s.Context()
	if err != nil {
		t.Fatal(err)
	}
	parts = []agentsession.InstructionPart{parts[1], {ID: "extra", Text: "The password is " + fakePassword + "."}, parts[0]}
	appendAt(t, s, c, ctx.Settings.InstructionsDelta(parts))
	appendAt(t, s, c, user("again"))
	turn(t, s, c, "resp-2", "hi again")
	resumed := redact(t, p, s, first.Session)
	wantInstructions(t, resumed.Session, want)
	if a, b := fileOf(t, resumed.Session), fileOf(t, redact(t, p, s, nil).Session); !bytes.Equal(a, b) {
		t.Errorf("the resumed redaction differs from a fresh one:\n%s\n---\n%s", a, b)
	}
}

// imageOriginal holds an inline image beside text holding a secret.
func imageOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := newOriginal("orig-image")
	msg := openresponses.UserMessage(
		&openresponses.InputText{Text: "look at this, " + fakePassword},
		&openresponses.InputImage{ImageURL: fakeImage, Detail: openresponses.ImageDetailHigh},
	)
	appendAt(t, s, c, agentsession.NewItemEntry(msg))
	turn(t, s, c, "resp-1", "I see an image")
	return s
}

// forkOriginal is a fork of plainOriginal at its first response, grown
// with a turn of its own.
func forkOriginal(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	origin := plainOriginal(t, c)
	var at string
	for _, e := range origin.Entries() {
		if r, ok := e.(*agentsession.ResponseEntry); ok && r.ResponseID == "resp-1" {
			at = r.ID
		}
	}
	f, err := agentsession.Fork(origin, at, agentsession.Header{ID: "orig-fork", CreatedAt: t0, CWD: fakeHome})
	if err != nil {
		t.Fatal(err)
	}
	appendAt(t, f, c, user("on the fork, "+fakeKey))
	turn(t, f, c, "resp-f", "forked")
	return f
}

func fileOf(t *testing.T, s *agentsession.Session) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := agentsession.Write(&buf, s); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func redact(t *testing.T, p Profile, orig, existing *agentsession.Session) *Result {
	t.Helper()
	res, err := Redact(p, orig, existing)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	return res
}

// checkRedaction holds a fresh redaction of orig to every rule: no
// planted value in its bytes, each entry redacted [n] in file order,
// every response verifying, the header linked, the file reading back,
// and a second run writing the same bytes.
func checkRedaction(t *testing.T, p Profile, orig *agentsession.Session, res *Result) {
	t.Helper()
	red := res.Session
	file := fileOf(t, red)
	for _, v := range planted {
		if bytes.Contains(file, []byte(v)) {
			t.Errorf("the redaction kept %q:\n%s", v, file)
		}
	}
	h := red.Header()
	oh := orig.Header()
	if !h.Redacted || h.RedactedFrom == nil || h.RedactedFrom.Session != oh.ID || h.RedactedFrom.Profile != p.Name {
		t.Errorf("header redacted %v, redacted_from %+v", h.Redacted, h.RedactedFrom)
	}
	if want := agentsession.RedactedSessionID(oh.ID, p.Name); h.ID != want {
		t.Errorf("ID %s, want %s", h.ID, want)
	}
	if h.Base != "" {
		t.Errorf("base %s, want none", h.Base)
	}
	order := agentsession.FileOrder(red)
	if len(order) != len(agentsession.FileOrder(orig)) {
		t.Errorf("%d entries, the original %d", len(order), len(agentsession.FileOrder(orig)))
	}
	if len(res.Entries) != len(order) {
		t.Errorf("Result.Entries holds %d, the session %d", len(res.Entries), len(order))
	}
	for i, e := range order {
		spans, ok := agentsession.RedactedOf(e)
		if want := []agentsession.Span{{From: i + 1, To: i + 1}}; !ok || !reflect.DeepEqual(spans, want) {
			t.Errorf("entry %d (%s) redacted %v %v, want %v", i+1, e.EntryType(), spans, ok, want)
		}
	}
	back, err := agentsession.Read(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("the redacted file does not read: %v\n%s", err, file)
	}
	verified := 0
	for _, e := range back.Entries() {
		r, ok := e.(*agentsession.ResponseEntry)
		if !ok || r.RequestHash == "" {
			continue
		}
		verified++
		if err := back.Verify(r.ID); err != nil {
			t.Errorf("response %s does not verify: %v", r.ResponseID, err)
		}
	}
	if verified == 0 {
		t.Error("no response with a request_hash; the case proves nothing")
	}
	again := redact(t, p, orig, nil)
	if !bytes.Equal(fileOf(t, again.Session), file) {
		t.Errorf("a second run wrote other bytes:\n%s\n---\n%s", file, fileOf(t, again.Session))
	}
}

func TestRedact(t *testing.T) {
	for _, tt := range []struct {
		name  string
		build func(*testing.T, *clock) *agentsession.Session
	}{
		{"plain", plainOriginal},
		{"compaction", compactionOriginal},
		{"instruction parts", partsOriginal},
		{"inline image", imageOriginal},
		{"fork", forkOriginal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			orig := tt.build(t, &clock{})
			p := testProfile()
			res := redact(t, p, orig, nil)
			checkRedaction(t, p, orig, res)
			if len(res.Findings) != 0 {
				t.Errorf("findings %+v", res.Findings)
			}
		})
	}
}

// TestRedactResume grows each original after it was redacted: the
// resumed redaction appends only the new entries and equals a fresh
// redaction of the grown original byte for byte.
func TestRedactResume(t *testing.T) {
	for _, tt := range []struct {
		name  string
		build func(*testing.T, *clock) *agentsession.Session
	}{
		{"plain", plainOriginal},
		{"compaction", compactionOriginal},
		{"instruction parts", partsOriginal},
		{"fork", forkOriginal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &clock{}
			orig := tt.build(t, c)
			p := testProfile()
			first := redact(t, p, orig, nil)
			before := first.Session.Len()

			// Nothing new: nothing written.
			if again := redact(t, p, orig, first.Session); len(again.Entries) != 0 {
				t.Fatalf("resuming an up-to-date redaction wrote %d entries", len(again.Entries))
			}

			appendAt(t, orig, c, user("later, "+fakePassword+" in "+fakeHome))
			turn(t, orig, c, "resp-later", "later reply "+fakeKey)
			grown := redact(t, p, orig, first.Session)
			if len(grown.Entries) != 3 || grown.Session.Len() != before+3 {
				t.Errorf("resume wrote %d entries, the session went %d -> %d; want 3 new", len(grown.Entries), before, grown.Session.Len())
			}
			if grown.Session != first.Session {
				t.Error("resume did not grow the existing session")
			}
			fresh := redact(t, p, orig, nil)
			if a, b := fileOf(t, grown.Session), fileOf(t, fresh.Session); !bytes.Equal(a, b) {
				t.Errorf("the resumed redaction differs from a fresh one:\n%s\n---\n%s", a, b)
			}
			checkRedaction(t, p, orig, fresh)
		})
	}
}

// TestRedactResumeAfterNative: entries appended natively to a redacted
// session stay, and the redaction resumes past them.
func TestRedactResumeAfterNative(t *testing.T) {
	c := &clock{}
	orig := plainOriginal(t, c)
	p := testProfile()
	red := redact(t, p, orig, nil).Session
	appendAt(t, red, c, user("a native note"))
	appendAt(t, orig, c, user("more "+fakeKey))
	res := redact(t, p, orig, red)
	if len(res.Entries) != 1 {
		t.Fatalf("wrote %d entries, want 1", len(res.Entries))
	}
	spans, _ := agentsession.RedactedOf(res.Entries[0])
	if want := len(agentsession.FileOrder(orig)); len(spans) != 1 || spans[0].From != want {
		t.Errorf("redacted %v, want [%d]", spans, want)
	}
}

func TestRedactRefusesAnotherRedaction(t *testing.T) {
	c := &clock{}
	orig := plainOriginal(t, c)
	p := testProfile()
	red := redact(t, p, orig, nil).Session

	other := testProfile()
	other.Name = "test.default@2"
	if _, err := Redact(other, orig, red); !errors.Is(err, ErrNotThisRedaction) {
		t.Errorf("another profile: %v, want ErrNotThisRedaction", err)
	}
	otherOrig := compactionOriginal(t, &clock{})
	if _, err := Redact(p, otherOrig, red); !errors.Is(err, ErrNotThisRedaction) {
		t.Errorf("another original: %v, want ErrNotThisRedaction", err)
	}
	if _, err := Redact(p, orig, orig); !errors.Is(err, ErrNotThisRedaction) {
		t.Errorf("a session that is not redacted: %v, want ErrNotThisRedaction", err)
	}
	// A redaction naming more of the original than it holds.
	short := newOriginal("orig-plain")
	appendAt(t, short, &clock{}, user("x"))
	if _, err := Redact(p, short, red); !errors.Is(err, agentsession.ErrStaleOriginal) {
		t.Errorf("a shorter original: %v, want ErrStaleOriginal", err)
	}
	if _, err := Redact(Profile{Name: "no version"}, orig, nil); !errors.Is(err, ErrProfileName) {
		t.Errorf("a bad profile name: %v, want ErrProfileName", err)
	}
}

// TestRedactUnverifiedHash: a response whose request_hash did not
// verify in the original gets none in the redaction, and one whose
// original had none gets none.
func TestRedactUnverifiedHash(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-unverified")
	appendAt(t, s, c, user("hello "+fakePassword))
	reply := agentsession.NewItemEntry(openresponses.AssistantText("hi"))
	reply.ResponseID = "resp-bad"
	appendAt(t, s, c, reply)
	bad := &agentsession.ResponseEntry{ResponseID: "resp-bad", Status: openresponses.ResponseStatusCompleted, RequestHash: agentsession.HashText("not the request")}
	badID := appendAt(t, s, c, bad)
	if err := s.Verify(badID); !errors.Is(err, agentsession.ErrHashMismatch) {
		t.Fatalf("the planted hash verifies: %v", err)
	}
	reply2 := agentsession.NewItemEntry(openresponses.AssistantText("again"))
	reply2.ResponseID = "resp-none"
	appendAt(t, s, c, reply2)
	appendAt(t, s, c, &agentsession.ResponseEntry{ResponseID: "resp-none", Status: openresponses.ResponseStatusCompleted})
	turn(t, s, c, "resp-good", "good")

	res := redact(t, testProfile(), s, nil)
	for _, e := range res.Session.Entries() {
		r, ok := e.(*agentsession.ResponseEntry)
		if !ok {
			continue
		}
		switch r.ResponseID {
		case "resp-bad", "resp-none":
			if r.RequestHash != "" {
				t.Errorf("%s has request_hash %s, want none", r.ResponseID, r.RequestHash)
			}
		case "resp-good":
			if err := res.Session.Verify(r.ID); err != nil {
				t.Errorf("resp-good does not verify: %v", err)
			}
		}
	}
}

// TestRedactSidecarImage: a sidecar image is left as it is and
// reported, never passed silently.
func TestRedactSidecarImage(t *testing.T) {
	c := &clock{}
	s := agentsession.New(agentsession.Header{ID: "orig-sidecar", CreatedAt: t0, Media: agentsession.MediaSidecar})
	url := "sidecar:" + agentsession.HashText("fake blob")
	msg := openresponses.UserMessage(&openresponses.InputImage{ImageURL: url})
	appendAt(t, s, c, agentsession.NewItemEntry(msg))
	res := redact(t, testProfile(), s, nil)
	if len(res.Findings) != 1 {
		t.Fatalf("findings %+v, want one", res.Findings)
	}
	f := res.Findings[0]
	if f.Position != 1 || f.Redactor != "images" || !strings.Contains(f.At, "image_url") || strings.Contains(f.Message, url) {
		t.Errorf("finding %+v", f)
	}
	if !bytes.Contains(fileOf(t, res.Session), []byte(url)) {
		t.Error("the sidecar reference was not kept as it was")
	}
	if res.Session.Header().Media != agentsession.MediaSidecar {
		t.Error("the redaction changed the media form")
	}
}

func TestEnvironment(t *testing.T) {
	c := &clock{}
	s := agentsession.New(agentsession.Header{ID: "orig-env", CreatedAt: t0, CWD: fakeHome})
	ws := func(ref string) *agentsession.EnvEntry {
		e := agentsession.NewEnvEntry(fakeHome)
		e.SetWorkspace(agentsession.WorkspaceContainer, ref)
		e.Unknown = map[string]json.RawMessage{"fake:tree": json.RawMessage(`"` + fakeRevision + `"`)}
		return e
	}
	appendAt(t, s, c, ws("image-a"))
	appendAt(t, s, c, user("one"))
	appendAt(t, s, c, ws("image-b"))
	appendAt(t, s, c, ws("image-a"))
	appendAt(t, s, c, agentsession.NewEnvEntry(fakeHome))
	p := Profile{Name: "env@1", Entries: []EntryRedactor{Environment()}}
	res := redact(t, p, s, nil)
	if cwd := res.Session.Header().CWD; cwd != "" {
		t.Errorf("header cwd %q", cwd)
	}
	var refs []string
	for _, e := range agentsession.FileOrder(res.Session) {
		env, ok := e.(*agentsession.EnvEntry)
		if !ok {
			continue
		}
		if env.CWD != "" || env.VCS != nil || env.Files != nil || env.Tools != nil || len(env.Unknown) != 0 {
			t.Errorf("env entry kept %+v", env)
		}
		if env.Workspace == nil {
			refs = append(refs, "")
			continue
		}
		if env.Workspace.Kind != agentsession.WorkspaceContainer || len(env.Workspace.Unknown) != 0 {
			t.Errorf("workspace %+v", env.Workspace)
		}
		refs = append(refs, env.Workspace.Ref)
	}
	want := []string{"[REDACTED workspace 1]", "[REDACTED workspace 2]", "[REDACTED workspace 1]", ""}
	if !reflect.DeepEqual(refs, want) {
		t.Errorf("workspace refs %q, want %q", refs, want)
	}
	file := fileOf(t, res.Session)
	for _, v := range []string{fakeHome, fakeRevision, "image-a", "image-b"} {
		if bytes.Contains(file, []byte(v)) {
			t.Errorf("kept %q:\n%s", v, file)
		}
	}
}

func TestImagesPlaceholder(t *testing.T) {
	data := DefaultImagePlaceholder[len("data:image/png;base64,"):]
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := png.Decode(bytes.NewReader(raw)); err != nil {
		t.Errorf("DefaultImagePlaceholder is not a PNG: %v", err)
	}
	orig := imageOriginal(t, &clock{})
	res := redact(t, testProfile(), orig, nil)
	found := false
	for _, e := range res.Session.Entries() {
		it, ok := e.(*agentsession.ItemEntry)
		if !ok {
			continue
		}
		if m, ok := it.Item.(*openresponses.Message); ok {
			for _, part := range m.Content {
				if img, ok := part.(*openresponses.InputImage); ok {
					found = true
					if img.ImageURL != DefaultImagePlaceholder || img.Detail != openresponses.ImageDetailHigh {
						t.Errorf("image part %+v", img)
					}
				}
			}
		}
	}
	if !found {
		t.Error("the image part is gone")
	}
	bad := Profile{Name: "bad@1", Entries: []EntryRedactor{Images("not a data url")}}
	if _, err := Redact(bad, orig, nil); err == nil {
		t.Error("a bad placeholder was accepted")
	}
}

// TestRedactWrapsAgentsessionErrors: a refusal from agentsession names
// the entry that failed and is found by errors.Is.
func TestRedactWrapsAgentsessionErrors(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-collide")
	env := agentsession.NewEnvEntry("")
	env.AddRead("/a/one", agentsession.HashText("1"))
	env.AddRead("/a/two", agentsession.HashText("2"))
	appendAt(t, s, c, user("first"))
	id := appendAt(t, s, c, env)
	p := Profile{Name: "collide@1", Strings: []StringRedactor{func(s string) string {
		return strings.NewReplacer("one", "x", "two", "x").Replace(s)
	}}}
	_, err := Redact(p, s, nil)
	if !errors.Is(err, agentsession.ErrKeyCollision) {
		t.Fatalf("err %v, want ErrKeyCollision", err)
	}
	if !strings.Contains(err.Error(), "entry 2") || !strings.Contains(err.Error(), id) {
		t.Errorf("%v does not name entry 2 (%s)", err, id)
	}
}
