package agentredact

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// homeProfile redacts the fake home alone, so a case shows what one
// redactor does and does not reach.
func homeProfile() Profile {
	return Profile{Name: "test.home@1", Strings: []StringRedactor{HomePaths(fakeHome)}}
}

// TestHeaderExtraKeys: the header's members the format does not define
// have their names renamed at any depth, and the header holds no
// planted path.
func TestHeaderExtraKeys(t *testing.T) {
	s := agentsession.New(agentsession.Header{ID: "orig-header-keys", CreatedAt: t0, Extra: map[string]json.RawMessage{
		"x.harness/projects":  json.RawMessage(`{"` + fakeHome + `/proj":{"trusted":true,"list":[{"` + fakeHome + `/deep":1}]}}`),
		fakeHome + "/top-key": json.RawMessage(`"value"`),
	}})
	appendAt(t, s, &clock{}, user("hello"))
	res := redact(t, homeProfile(), s, nil)
	file := fileOf(t, res.Session)
	if bytes.Contains(file, []byte(fakeHome)) {
		t.Errorf("the header kept the home:\n%s", file)
	}
	h := res.Session.Header()
	if _, ok := h.Extra["~/top-key"]; !ok {
		t.Errorf("Extra %v, want ~/top-key", h.Extra)
	}
	if got := string(h.Extra["x.harness/projects"]); got != `{"~/proj":{"list":[{"~/deep":1}],"trusted":true}}` {
		t.Errorf("nested member %s", got)
	}
}

func TestHeaderExtraKeyCollisions(t *testing.T) {
	for _, tt := range []struct {
		name  string
		extra map[string]json.RawMessage
		f     StringRedactor
	}{
		{"top level", map[string]json.RawMessage{fakeHome + "/a": json.RawMessage(`1`), "~/a": json.RawMessage(`2`)}, HomePaths(fakeHome)},
		{"nested", map[string]json.RawMessage{"x.fake": json.RawMessage(`{"` + fakeHome + `/a":1,"~/a":2}`)}, HomePaths(fakeHome)},
		{"to a defined member", map[string]json.RawMessage{"x-cwd": json.RawMessage(`"v"`)}, func(s string) string { return strings.ReplaceAll(s, "x-cwd", "cwd") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := agentsession.New(agentsession.Header{ID: "orig-collide", CreatedAt: t0, Extra: tt.extra})
			appendAt(t, s, &clock{}, user("hello"))
			_, err := Redact(Profile{Name: "collide@1", Strings: []StringRedactor{tt.f}}, s, nil)
			if !errors.Is(err, agentsession.ErrKeyCollision) {
				t.Fatalf("err %v, want ErrKeyCollision", err)
			}
			if strings.Contains(err.Error(), fakeHome) {
				t.Errorf("the error quotes the home: %v", err)
			}
		})
	}
}

// unknownExtension is an extension entry holding a planted key.
func unknownExtension(t *testing.T) agentsession.Entry {
	t.Helper()
	e, err := agentsession.UnmarshalEntry([]byte(`{"type":"x.fake:note","id":"x","parent":null,"ts":"2026-01-02T03:04:05Z","index":{"` + fakeHome + `/c":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	e.Base().ID = ""
	return e
}

// TestEntryKeysRefused: an entry holding a member name the string
// redactors would change is refused, by position and a pointer built
// from rewritten names, never naming the key.
func TestEntryKeysRefused(t *testing.T) {
	for _, tt := range []struct {
		name  string
		entry func(t *testing.T, s *agentsession.Session) agentsession.Entry
		at    string
	}{
		{"custom data", func(t *testing.T, s *agentsession.Session) agentsession.Entry {
			return &agentsession.CustomEntry{NS: "x.fake", Data: json.RawMessage(`{"` + fakeHome + `/a.go":"x"}`)}
		}, "/data/~0~1a.go"},
		{"outcome details", func(t *testing.T, s *agentsession.Session) agentsession.Entry {
			o := agentsession.NewOutcomeEntry("fake", s.Leaf())
			o.Details = json.RawMessage(`{"tests":{"` + fakeHome + `/t":1}}`)
			return o
		}, "/details/tests/~0~1t"},
		{"nested unknown member", func(t *testing.T, s *agentsession.Session) agentsession.Entry {
			e := user("hello")
			e.Unknown = map[string]json.RawMessage{"x.fake:meta": json.RawMessage(`{"files":{"` + fakeHome + `/b":"1"}}`)}
			return e
		}, "/x.fake:meta/files/~0~1b"},
		{"extension entry", func(t *testing.T, s *agentsession.Session) agentsession.Entry {
			return unknownExtension(t)
		}, "/index/~0~1c"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &clock{}
			s := newOriginal("orig-keys")
			appendAt(t, s, c, user("first"))
			appendAt(t, s, c, tt.entry(t, s))
			_, err := Redact(homeProfile(), s, nil)
			if !errors.Is(err, ErrKeyNotRedacted) {
				t.Fatalf("err %v, want ErrKeyNotRedacted", err)
			}
			msg := err.Error()
			if strings.Contains(msg, fakeHome) || strings.Contains(msg, "~1home~1example") {
				t.Errorf("the error names the key: %v", err)
			}
			if !strings.Contains(msg, "entry 2 ") || !strings.Contains(msg, "at "+tt.at) {
				t.Errorf("the error %q does not name entry 2 at %s", msg, tt.at)
			}
		})
	}
}

// TestEnvFileKeysRenamed: an env entry's file paths, which the Rewriter
// renames, pass the key check without Environment.
func TestEnvFileKeysRenamed(t *testing.T) {
	s := newOriginal("orig-env-files")
	env := agentsession.NewEnvEntry("")
	env.AddRead(fakeHome+"/a.go", agentsession.HashText("fake"))
	appendAt(t, s, &clock{}, env)
	res := redact(t, homeProfile(), s, nil)
	if bytes.Contains(fileOf(t, res.Session), []byte(fakeHome)) {
		t.Error("the env file path kept the home")
	}
}

// TestDataURLMeta: a base64 data URL's media type and parameters go
// through the string redactors; its payload is kept.
func TestDataURLMeta(t *testing.T) {
	payload := "AAA+AKIAFAKE0000EXAMPLE0+AAA"
	url := "data:image/png;name=" + fakeHome + "/shot.png;base64," + payload
	s := newOriginal("orig-meta")
	appendAt(t, s, &clock{}, agentsession.NewItemEntry(openresponses.UserMessage(&openresponses.InputImage{ImageURL: url})))
	p := Profile{Name: "meta@1", Strings: []StringRedactor{HomePaths(fakeHome), DefaultPatterns()}}
	res := redact(t, p, s, nil)
	m := res.Session.Entries()[0].(*agentsession.ItemEntry).Item.(*openresponses.Message)
	if got, want := m.Content[0].(*openresponses.InputImage).ImageURL, "data:image/png;name=~/shot.png;base64,"+payload; got != want {
		t.Errorf("image_url %q, want %q", got, want)
	}
}

// TestMediaFindings: inline media that is not an image, and an image
// data URL inside a longer string, are kept and reported.
func TestMediaFindings(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-media")
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.UserMessage(&openresponses.InputFile{Filename: "fake.pdf", FileData: "data:application/pdf;base64,JVBERi0xLjQK"})))
	appendAt(t, s, c, user("see ![shot](data:image/png;base64,iVBORw0K) and DATA:image/gif;base64,R0lG"))
	res := redact(t, testProfile(), s, nil)
	var got []string
	for _, f := range res.Findings {
		got = append(got, f.At)
		if f.Redactor != "redact" {
			t.Errorf("finding %+v", f)
		}
	}
	want := []string{"/item/content/0/file_data", "/item/content/0/text", "/item/content/0/text"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("findings at %v, want %v", got, want)
	}
	if res.Findings[0].Position != 1 || res.Findings[1].Position != 2 {
		t.Errorf("positions %+v", res.Findings)
	}
}

// TestImagesUppercaseScheme: an image whose scheme is written in upper
// case, with no lower-case "data:" in the entry, is replaced.
func TestImagesUppercaseScheme(t *testing.T) {
	s := newOriginal("orig-upper")
	url := "DATA:image/png;base64,RkFLRS1JTUFHRQ=="
	appendAt(t, s, &clock{}, agentsession.NewItemEntry(openresponses.UserMessage(&openresponses.InputImage{ImageURL: url})))
	res := redact(t, testProfile(), s, nil)
	m := res.Session.Entries()[0].(*agentsession.ItemEntry).Item.(*openresponses.Message)
	if got := m.Content[0].(*openresponses.InputImage).ImageURL; got != DefaultImagePlaceholder {
		t.Errorf("image_url %q, want the placeholder", got)
	}
}

// TestWorkspaceKindRedacted: the workspace kind Environment keeps is the
// one the string redactors left.
func TestWorkspaceKindRedacted(t *testing.T) {
	s := newOriginal("orig-kind")
	env := agentsession.NewEnvEntry("")
	env.SetWorkspace("corp-buildfarm-7", "ref")
	appendAt(t, s, &clock{}, env)
	p := Profile{Name: "kind@1", Strings: []StringRedactor{Secrets("corp-buildfarm-7")}, Entries: []EntryRedactor{Environment()}}
	res := redact(t, p, s, nil)
	if bytes.Contains(fileOf(t, res.Session), []byte("corp-buildfarm-7")) {
		t.Errorf("the kind was kept:\n%s", fileOf(t, res.Session))
	}
	if got := res.Session.Entries()[0].(*agentsession.EnvEntry).Workspace; got == nil || got.Kind != SecretReplacement {
		t.Errorf("workspace %+v", got)
	}
}

// TestCrossSessionReferences: a reference to another session names its
// derived redaction; an entry of another session whose counterparts are
// not given stays as written and is reported.
func TestCrossSessionReferences(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-cross")
	appendAt(t, s, c, user("first"))
	appendAt(t, s, c, &agentsession.LinkEntry{Rel: agentsession.RelContinuedIn, Session: "fake-other-session"})
	conv := user("merged")
	conv.Parents = []agentsession.EntryRef{{Session: "fake-other-session", Entry: agentsession.HashText("fake entry")}}
	appendAt(t, s, c, conv)
	res := redact(t, testProfile(), s, nil)
	var got []string
	for _, f := range res.Findings {
		got = append(got, f.At)
		if f.Kind != FindingForeignReference {
			t.Errorf("finding %+v, want a foreign reference", f)
		}
		if strings.Contains(f.Message, "fake-other-session") || strings.Contains(f.Message, "sha256:") {
			t.Errorf("finding quotes a reference: %+v", f)
		}
	}
	want := []string{"/parents/0/entry"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("findings at %v, want %v", got, want)
	}
	file := fileOf(t, res.Session)
	if bytes.Contains(file, []byte("fake-other-session")) {
		t.Error("the other session's original ID was kept")
	}
	if !bytes.Contains(file, []byte(agentsession.RedactedSessionID("fake-other-session", testProfile().Name))) {
		t.Error("the other session's derived redaction is not named")
	}
}

// TestRedactReadBackResume: a redaction written and read back, as a
// store hands it over, resumes into one equal to a fresh redaction.
func TestRedactReadBackResume(t *testing.T) {
	for _, tt := range []struct {
		name  string
		build func(*testing.T, *clock) *agentsession.Session
	}{
		{"plain", plainOriginal},
		{"instruction parts", partsOriginal},
		{"two roots", twoRootsOriginal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &clock{}
			orig := tt.build(t, c)
			p := testProfile()
			first := redact(t, p, orig, nil)
			back, err := agentsession.Read(bytes.NewReader(fileOf(t, first.Session)))
			if err != nil {
				t.Fatal(err)
			}
			appendAt(t, orig, c, user("later, "+fakeKey))
			turn(t, orig, c, "resp-later", "later")
			grown := redact(t, p, orig, back)
			if len(grown.Entries) != 3 {
				t.Errorf("wrote %d entries, want 3", len(grown.Entries))
			}
			if a, b := fileOf(t, grown.Session), fileOf(t, redact(t, p, orig, nil).Session); !bytes.Equal(a, b) {
				t.Errorf("the resumed redaction differs from a fresh one:\n%s\n---\n%s", a, b)
			}
		})
	}
}

func TestRedactRefusesWrongExisting(t *testing.T) {
	c := &clock{}
	orig := plainOriginal(t, c)
	p := testProfile()
	red := redact(t, p, orig, nil).Session
	redID := red.ID()

	wrongID := agentsession.New(agentsession.Header{ID: "fake-wrong-id", CreatedAt: t0, Redacted: true,
		RedactedFrom: &agentsession.RedactedFrom{Session: orig.ID(), Profile: p.Name}})
	if _, err := Redact(p, orig, wrongID); !errors.Is(err, ErrNotThisRedaction) {
		t.Errorf("a wrong ID: %v, want ErrNotThisRedaction", err)
	}

	based, err := agentsession.Fork(red, red.Entries()[2].Base().ID, agentsession.Header{ID: redID, CreatedAt: t0, Redacted: true,
		RedactedFrom: &agentsession.RedactedFrom{Session: orig.ID(), Profile: p.Name}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Redact(p, orig, based); !errors.Is(err, ErrNotThisRedaction) {
		t.Errorf("a base: %v, want ErrNotThisRedaction", err)
	}

	// An original of the same ID whose entries are of other types.
	other := newOriginal("orig-plain")
	for range agentsession.FileOrder(orig) {
		appendAt(t, other, &clock{}, user("x"))
	}
	if _, err := Redact(p, other, red); !errors.Is(err, ErrNotThisRedaction) {
		t.Errorf("entries of other types: %v, want ErrNotThisRedaction", err)
	}
}

// TestWorkspaceNumberingAlongPath: workspaces are numbered along each
// entry's path, so a fork numbers its prefix as its origin does, and
// numbers that differ only in spelling are one workspace.
func TestWorkspaceNumberingAlongPath(t *testing.T) {
	c := &clock{}
	envAt := func(s *agentsession.Session, parent, ref string, n json.RawMessage) string {
		e := agentsession.NewEnvEntry("")
		ws := e.SetWorkspace(agentsession.WorkspaceContainer, ref)
		if n != nil {
			if err := ws.SetMember("x.fake:n", n); err != nil {
				t.Fatal(err)
			}
		}
		e.Parent = parent
		return appendAt(t, s, c, e)
	}
	s := newOriginal("orig-ws")
	root := envAt(s, "", "ws-a", nil)
	envAt(s, root, "ws-b", nil)       // branch 1
	c2 := envAt(s, root, "ws-c", nil) // branch 2
	one := envAt(s, c2, "ws-d", json.RawMessage(`1`))
	envAt(s, one, "ws-d", json.RawMessage(`1.0`)) // the same workspace
	p := Profile{Name: "ws@1", Entries: []EntryRedactor{Environment()}}
	refs := func(red *agentsession.Session) []string {
		var out []string
		for _, e := range agentsession.FileOrder(red) {
			if env, ok := e.(*agentsession.EnvEntry); ok && env.Workspace != nil {
				out = append(out, env.Workspace.Ref)
			}
		}
		return out
	}
	got := refs(redact(t, p, s, nil).Session)
	want := []string{"[REDACTED workspace 1]", "[REDACTED workspace 2]", "[REDACTED workspace 2]", "[REDACTED workspace 3]", "[REDACTED workspace 3]"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("origin refs %q, want %q", got, want)
	}
	f, err := agentsession.Fork(s, c2, agentsession.Header{ID: "orig-ws-fork", CreatedAt: t0})
	if err != nil {
		t.Fatal(err)
	}
	if got := refs(redact(t, p, f, nil).Session); strings.Join(got, ",") != "[REDACTED workspace 1],[REDACTED workspace 2]" {
		t.Errorf("fork refs %q, want the origin's numbering of its prefix", got)
	}
}
