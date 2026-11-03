package agentredact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentsession"
	"github.com/ChristopherDavenport/openresponses"
)

// The rules agentsession's formats 0.14 to 0.19 gave redactors, each
// held by a synthetic case.

// TestCustomEntryLeavesWithCall: a custom entry carrying a call's
// call_id leaves with the call, as its dispatches and outputs do (RFC
// 0001 0.15, Leaving entries out).
//
//	1 user  2 call c (resp-1)  3 resp-1  4 custom call_id c  5 output
//	6 msg (resp-2)  7 resp-2
func TestCustomEntryLeavesWithCall(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-custom-call")
	appendAt(t, s, c, user("run the tool"))
	respond(t, s, c, "resp-1", call("call-nested"))
	appendAt(t, s, c, &agentsession.CustomEntry{NS: "fake:nested_call", CallID: "call-nested", Data: json.RawMessage(`{"note":"nested-call-record"}`)})
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-nested", "done")))
	respond(t, s, c, "resp-2", agentsession.NewItemEntry(openresponses.AssistantText("ok")))
	p := structProfile("test.custom-call@1", []EntryRedactor{LeaveOut(ofType(openresponses.ItemTypeFunctionCall))})
	res := redact(t, p, s, nil)
	checkStructural(t, p, s, res, []string{"1", "6", "7"})
	absent(t, res, "call-nested", "nested-call-record")
}

// TestCompactionKeepsTrust: a compaction whose entries before first_kept
// are left out keeps its trust as written, never narrowed to what the
// kept entries carry (RFC 0001 0.15, Every redacted entry).
func TestCompactionKeepsTrust(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-trust")
	appendAt(t, s, c, user("secret-block: what an untrusted page said"))
	turn(t, s, c, "resp-1", "read it")
	kept := appendAt(t, s, c, user("second"))
	turn(t, s, c, "resp-2", "ok")
	comp, err := s.Compact(kept, openresponses.UserText("summary of an untrusted page"))
	if err != nil {
		t.Fatal(err)
	}
	comp.Trust = &agentsession.Trust{Reads: []string{agentsession.TrustUntrusted}}
	appendAt(t, s, c, comp)
	appendAt(t, s, c, user("after the fold"))
	turn(t, s, c, "resp-3", "fine")
	p := structProfile("test.trust@1", []EntryRedactor{BlockOut(userWith("secret-block"))})
	res := redact(t, p, s, nil)
	var got *agentsession.CompactionEntry
	for _, e := range readBack(t, res.Session).Entries() {
		if v, ok := e.(*agentsession.CompactionEntry); ok {
			got = v
		}
	}
	if got == nil || got.Trust == nil || !reflect.DeepEqual(got.Trust.Reads, []string{agentsession.TrustUntrusted}) {
		t.Fatalf("the compaction's trust %+v, want untrusted as written", got)
	}
	if !hasKind(res, FindingRestates) {
		t.Errorf("findings %+v, want the compaction restating what was left out", res.Findings)
	}
}

func hasKind(res *Result, kind FindingKind) bool {
	return slices.ContainsFunc(res.Findings, func(f Finding) bool { return f.Kind == kind })
}

// promisedFork is a fork whose header promises dispatch records, whose
// own entry answers a call of its prefix the origin never dispatched,
// which a fork may do: its promise covers its own entries alone.
//
//	origin: 1 user  2 call c (resp-1)  3 resp-1
//	fork:   4 answer c  5 output  6 msg (resp-2)  7 resp-2
func promisedFork(t *testing.T, c *clock) (origin, f *agentsession.Session) {
	t.Helper()
	origin = newOriginal("orig-unpromised")
	appendAt(t, origin, c, user("run it"))
	ids := respond(t, origin, c, "resp-1", call("call-prefix"))
	f, err := agentsession.Fork(origin, ids[1], agentsession.Header{ID: "orig-promised-fork", CreatedAt: t0, Records: []string{agentsession.TypeDispatch, agentsession.TypeDecision}})
	if err != nil {
		t.Fatal(err)
	}
	appendAt(t, f, c, agentsession.NewDecision("call-prefix", ids[0], agentsession.VerdictAnswer, agentsession.ByPolicy).WithReason("answered on the fork"))
	appendAt(t, f, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-prefix", "answered")))
	respond(t, f, c, "resp-2", agentsession.NewItemEntry(openresponses.AssistantText("ok")))
	if err := f.VerifyRecords(f.Leaf()); err != nil {
		t.Fatalf("the original fork does not verify its records: %v", err)
	}
	return origin, f
}

// TestForkPrefixAnswered: a fork redacted without a base holds its
// prefix as entries of its own, which the original's promise of records
// never covered, so the redaction does not carry that promise and an
// answer to a prefix call the origin never dispatched is written; as a
// fork of the origin's redaction, it keeps the base and the promise.
func TestForkPrefixAnswered(t *testing.T) {
	c := &clock{}
	origin, f := promisedFork(t, c)
	p := testProfile()
	alone, err := Redact(p, testKey, f, nil)
	if err != nil {
		t.Fatalf("redacted without a base: %v", err)
	}
	back := readBack(t, alone.Session)
	if err := back.VerifyRecords(back.Leaf()); err != nil {
		t.Errorf("redacted without a base, the records do not verify: %v", err)
	}
	ro := redact(t, p, origin, nil)
	asFork := redactFork(t, p, f, nil, &Origin{Original: origin, Redaction: ro.Session})
	if h := asFork.Session.Header(); h.Base == "" || !slices.Equal(h.Records, f.Header().Records) {
		t.Errorf("as a fork: base %q, records %v, want the base and %v", h.Base, h.Records, f.Header().Records)
	}
}

// TestKeyRequired: there is no default key, so Redact and RedactStore
// refuse the zero Key and a short one.
func TestKeyRequired(t *testing.T) {
	orig := plainOriginal(t, &clock{})
	if _, err := Redact(testProfile(), Key{}, orig, nil); !errors.Is(err, agentsession.ErrRedactionKey) {
		t.Errorf("Redact with no key: %v, want ErrRedactionKey", err)
	}
	if _, err := NewKey([]byte("short")); !errors.Is(err, agentsession.ErrRedactionKey) {
		t.Errorf("NewKey of 5 bytes: %v, want ErrRedactionKey", err)
	}
	if _, err := RedactStore(context.Background(), agentsession.NewMemoryStore(), testProfile(), Key{}, StoreOptions{}); !errors.Is(err, agentsession.ErrRedactionKey) {
		t.Errorf("RedactStore with no key: %v, want ErrRedactionKey", err)
	}
}

// TestPseudonymNames: a redaction names its original by the keyed
// pseudonym (RFC 0001 0.19, The redacted session): its ID is the one
// RedactedID derives, which a reader recomputes from its own header and
// a holder of the original's ID cannot, since it is not the unkeyed
// derivation over that ID; another key gives another session; and the
// key is in no byte of the output and in no printing of it.
func TestPseudonymNames(t *testing.T) {
	orig := plainOriginal(t, &clock{})
	p := testProfile()
	res := redact(t, p, orig, nil)
	h := res.Session.Header()
	if h.ID != RedactedID(testKey, orig.ID(), p.Name) || h.RedactedFrom.Session != pseudonymOf(orig.ID(), p.Name) {
		t.Errorf("id %s, redacted_from %+v", h.ID, h.RedactedFrom)
	}
	if err := agentsession.CheckRedactedID(h); err != nil {
		t.Errorf("CheckRedactedID: %v", err)
	}
	if !agentsession.VerifiesAsRedacted(h) {
		t.Error("the header does not verify as a redacted session's")
	}
	file := fileOf(t, res.Session)
	if unkeyed := agentsession.RedactedSessionID(orig.ID(), p.Name); bytes.Contains(file, []byte(unkeyed)) || h.ID == unkeyed {
		t.Error("the redaction holds the unkeyed derivation over the original's ID")
	}
	if bytes.Contains(file, []byte(orig.ID())) || bytes.Contains(file, keyBytes(testKey)) || bytes.Contains(file, []byte(fmt.Sprintf("%x", keyBytes(testKey)))) {
		t.Error("the redaction holds the original's ID or the key")
	}
	other := redact(t, p, orig, nil)
	k2 := mustKey("agentredact-another-test-key-not-secret")
	again, err := Redact(p, k2, orig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Session.ID() == other.Session.ID() {
		t.Error("two keys derive one ID")
	}
	if _, err := Redact(p, k2, orig, res.Session); !errors.Is(err, ErrNotThisRedaction) {
		t.Errorf("resuming under another key: %v, want ErrNotThisRedaction", err)
	}
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("redacting", "key", testKey)
	for _, out := range []string{fmt.Sprint(testKey), fmt.Sprintf("%v %+v %#v %s %q %x", testKey, testKey, testKey, testKey, testKey, testKey), logged.String()} {
		if strings.Contains(out, string(keyBytes(testKey))) || strings.Contains(out, fmt.Sprintf("%x", keyBytes(testKey))) {
			t.Errorf("a printed key shows its bytes: %s", out)
		}
	}
	if data, err := json.Marshal(struct{ K Key }{testKey}); err == nil {
		t.Errorf("a key marshalled: %s", data)
	}
}

// TestKeyFile: a key file is written once, owner-only, read back to the
// same names, and refused when it is missing, open to others, or holds
// no key.
func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.key")
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(path, k); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(path, testKey); !errors.Is(err, ErrKeyFile) {
		t.Errorf("overwriting a key file: %v, want ErrKeyFile", err)
	}
	back, err := ReadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if RedactedID(back, "orig", "p@1") != RedactedID(k, "orig", "p@1") {
		t.Error("the key read back derives other names")
	}
	if _, err := ReadKeyFile(filepath.Join(dir, "missing.key")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing key file: %v, want ErrNotExist", err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("the key file's mode %v, %v; want 0600", info.Mode().Perm(), err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadKeyFile(path); !errors.Is(err, ErrKeyFile) {
			t.Errorf("a key file others may read: %v, want ErrKeyFile", err)
		}
	}
	bad := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(bad, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(bad); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a file holding no key: %v, want ErrKeyFile", err)
	}
}

// TestLayersStayDistinct: two instruction layer ids of one message that
// one pattern matches are written as two placeholders, so the layers
// stay distinct and the session writes (RFC 0001 0.18, #20), however
// many entries apart the values are met.
func TestLayersStayDistinct(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-layers")
	one, two := "sk-test-1111111111111111111111111111", "sk-test-2222222222222222222222222222"
	appendAt(t, s, c, user("the second key is "+two))
	layered := user("two layers")
	layered.InstructionsLayers = []agentsession.LayerRef{
		{ID: "/fake/" + one + "/AGENTS.md", Source: agentsession.LayerAgentsMD},
		{ID: "/fake/" + two + "/AGENTS.md", Source: agentsession.LayerAgentsMD},
	}
	appendAt(t, s, c, layered)
	turn(t, s, c, "resp-1", "ok")
	res := redact(t, testProfile(), s, nil)
	it := agentsession.FileOrder(readBack(t, res.Session))[1].(*agentsession.ItemEntry)
	want := []agentsession.LayerRef{
		{ID: "/fake/[REDACTED openai_key#2]/AGENTS.md", Source: agentsession.LayerAgentsMD},
		{ID: "/fake/[REDACTED openai_key#1]/AGENTS.md", Source: agentsession.LayerAgentsMD},
	}
	if !reflect.DeepEqual(it.InstructionsLayers, want) {
		t.Errorf("layers %+v, want %+v", it.InstructionsLayers, want)
	}
	first := agentsession.FileOrder(res.Session)[0].(*agentsession.ItemEntry)
	if text := first.Item.(*openresponses.Message).Content[0].(*openresponses.InputText).Text; text != "the second key is [REDACTED openai_key#1]" {
		t.Errorf("first text %q", text)
	}
	// Resumed after the first entry, the numbering is the fresh one's.
	lines := bytes.SplitAfter(fileOf(t, s), []byte("\n"))
	early, err := agentsession.Read(bytes.NewReader(bytes.Join(lines[:2], nil)))
	if err != nil {
		t.Fatal(err)
	}
	grown := redact(t, testProfile(), s, redact(t, testProfile(), early, nil).Session)
	if a, b := fileOf(t, grown.Session), fileOf(t, res.Session); !bytes.Equal(a, b) {
		t.Errorf("the resumed redaction differs from a fresh one:\n%s\n---\n%s", a, b)
	}
}

// TestForkContinuesNumbering: a fork redacted as a fork of its origin's
// redaction names a value its shared prefix holds by the prefix's
// placeholder, though the origin met another value first on a branch
// off the fork's path.
func TestForkContinuesNumbering(t *testing.T) {
	c := &clock{}
	one, two := "sk-test-1111111111111111111111111111", "sk-test-2222222222222222222222222222"
	o := newOriginal("orig-numbered")
	userAt(t, o, c, "", "an abandoned branch holding "+one)
	o.ResetLeaf()
	userAt(t, o, c, "", "a branch holding "+two) // a second first entry
	base := turn(t, o, c, "resp-1", "ok")
	f := fork(t, o, base, "orig-numbered-fork")
	appendAt(t, f, c, user("on the fork, "+two))
	turn(t, f, c, "resp-f", "forked")
	p := testProfile()
	ro := redact(t, p, o, nil)
	if !bytes.Contains(fileOf(t, ro.Session), []byte("a branch holding [REDACTED openai_key#2]")) {
		t.Fatalf("the origin's redaction does not number the second key 2:\n%s", fileOf(t, ro.Session))
	}
	rf := redactFork(t, p, f, nil, &Origin{Original: o, Redaction: ro.Session})
	if file := fileOf(t, rf.Session); !bytes.Contains(file, []byte("on the fork, [REDACTED openai_key#2]")) {
		t.Errorf("the fork names the prefix's key otherwise:\n%s", file)
	}
}

// TestKeptImageFinding: a profile with no Images keeps every image and
// reports each, inline, sidecar under an image_url, and a sidecar blob
// of an image type under any item, as an image finding with no value
// (#17); a profile with Images reports none.
func TestKeptImageFinding(t *testing.T) {
	c := &clock{}
	s := agentsession.New(agentsession.Header{ID: "orig-images", CreatedAt: t0, Media: agentsession.MediaSidecar})
	shot := "sidecar:" + agentsession.HashText("FAKE-SCREENSHOT-0001")
	file := "sidecar:" + agentsession.HashText("FAKE-PNG-AS-FILE-0002")
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.UserMessage(
		&openresponses.InputText{Text: "three pictures"},
		&openresponses.InputImage{ImageURL: fakeImage},
		&openresponses.InputImage{ImageURL: shot},
		&openresponses.InputFile{Filename: "fake.png", FileData: file},
	)))
	turn(t, s, c, "resp-1", "seen")
	types := func(hash string) string {
		if "sidecar:"+hash == file {
			return "image/png"
		}
		return ""
	}
	plain := Profile{Name: "test.no-images@1", Strings: []StringRedactor{Secrets(fakePassword)}}
	res, err := Redact(plain, testKey, s, nil, WithMediaTypes(types))
	if err != nil {
		t.Fatal(err)
	}
	var at []string
	for _, f := range res.Findings {
		if f.Kind == FindingImage {
			at = append(at, f.At)
			if f.Position != 1 || strings.Contains(f.Message, "sha256:") || strings.Contains(f.Message, "FAKE") {
				t.Errorf("finding %+v", f)
			}
		}
	}
	want := []string{"/item/content/1/image_url", "/item/content/2/image_url", "/item/content/3/file_data"}
	if !slices.Equal(at, want) {
		t.Errorf("image findings at %v, want %v", at, want)
	}
	rep := SessionReport{Findings: res.Findings, accept: map[FindingKind]bool{}}
	if rep.Publishable() {
		t.Error("a session keeping images is publishable")
	}
	rep.accept[FindingImage] = true
	if !rep.Publishable() {
		t.Errorf("a session keeping images is not publishable when images are accepted: %+v", res.Findings)
	}
	with, err := Redact(testProfile(), testKey, s, nil, WithMediaTypes(types))
	if err != nil {
		t.Fatal(err)
	}
	if hasKind(with, FindingImage) {
		t.Errorf("a profile with Images reports %+v", with.Findings)
	}
}

// TestSessionIDsInText: text quoting the original's own ID, or a
// child's it links to, names their redactions instead, wherever the
// string redactors reach, as references do (RFC 0001 0.19, #11).
func TestSessionIDsInText(t *testing.T) {
	c := &clock{}
	const own = "11111111-1111-4111-8111-00000000f00d" // synthetic
	s := newOriginal(own)
	appendAt(t, s, c, user("work in /tmp/claude-1000/-home-example-proj/"+own+"/scratchpad"))
	respond(t, s, c, "resp-1", call("call-sub"))
	child := agentsession.SubsessionID(own, "call-sub")
	appendAt(t, s, c, agentsession.NewSubsessionLink(child, "call-sub"))
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-sub", "child "+child+" wrote "+own+".txt")))
	respond(t, s, c, "resp-2", agentsession.NewItemEntry(openresponses.AssistantText("ok")))
	p := testProfile()
	res := redact(t, p, s, nil)
	file := fileOf(t, res.Session)
	if bytes.Contains(file, []byte(own)) || bytes.Contains(file, []byte(child)) {
		t.Errorf("the redaction quotes an original session ID:\n%s", file)
	}
	redChild := RedactedID(testKey, child, p.Name)
	for _, want := range []string{"-~-proj/" + res.Session.ID() + "/scratchpad", "child " + redChild + " wrote " + res.Session.ID() + ".txt", `"session":"` + redChild + `"`} {
		if !bytes.Contains(file, []byte(want)) {
			t.Errorf("the redaction lacks %s:\n%s", want, file)
		}
	}
}

// claudeCodeShaped is a synthetic session shaped as agentimport writes a
// Claude Code import, holding identity members and text quoting their
// values in other spellings.
//
//	1 custom credential_org  2 item with a session_context attachment
//	3 custom api-request  4 user quoting the values  5 msg  6 resp-1
func claudeCodeShaped(t *testing.T, c *clock) *agentsession.Session {
	t.Helper()
	s := newOriginal("orig-identity")
	appendAt(t, s, c, &agentsession.CustomEntry{NS: "claudecode", Data: json.RawMessage(`{"attachment":{"organizationUuid":"0a000000-0000-4000-8000-00000000a001","type":"credential_org"},"cwd":"` + fakeHome + `/project"}`)})
	ctx := user("hello")
	ctx.Unknown = map[string]json.RawMessage{"claudecode:attachment": json.RawMessage(`{"context":{"userEmail":"The user's email address is fake.user@example.test."},"type":"session_context"}`)}
	appendAt(t, s, c, ctx)
	appendAt(t, s, c, &agentsession.CustomEntry{NS: "claudecode", Data: json.RawMessage(`{"params":{"safeguards":[{"classifier_context":{"home_dir":"` + fakeHome + `","user_identity":"ExampleLogin"}}]},"type":"api-request"}`)})
	appendAt(t, s, c, user("mail FAKE.USER@example.test or fake.user%40example.test, org 0a000000-0000-4000-8000-00000000a001, cache github.com/!example!login/tool, ExampleLogin wrote it"))
	turn(t, s, c, "resp-1", "noted")
	return s
}

// TestIdentityValues: a profile's identity members harvest the user's
// values from the original, and every spelling of each, as written, in
// another case, URL-encoded or Go-module-escaped, is replaced; nothing
// is left for the check to find (#13).
func TestIdentityValues(t *testing.T) {
	s := claudeCodeShaped(t, &clock{})
	p := testProfile()
	p.Name = "test.identity@1"
	p.Identity = ClaudeCodeIdentity()
	res := redact(t, p, s, nil)
	file := strings.ToLower(string(fileOf(t, res.Session)))
	for _, v := range []string{"fake.user@example.test", "fake.user%40example.test", "0a000000-0000-4000-8000-00000000a001", "examplelogin", "!example!login"} {
		if strings.Contains(file, v) {
			t.Errorf("the redaction keeps %q:\n%s", v, file)
		}
	}
	if hasKind(res, FindingIdentity) {
		t.Errorf("findings %+v, want no identity value left", res.Findings)
	}
	if !strings.Contains(file, "[redacted identity#") {
		t.Errorf("no identity placeholder:\n%s", file)
	}
}

// TestIdentityNamedLate: a value the original names only after the
// entry quoting it is not replaced there, since what a redaction writes
// at a position rests on the entries up to it, but the check finds it,
// by its pointer and with no value, and the session is not publishable.
func TestIdentityNamedLate(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-identity-late")
	appendAt(t, s, c, user("signed, LateLoginName"))
	appendAt(t, s, c, &agentsession.CustomEntry{NS: "claudecode", Data: json.RawMessage(`{"params":{"safeguards":[{"classifier_context":{"user_identity":"LateLoginName"}}]}}`)})
	turn(t, s, c, "resp-1", "ok")
	p := testProfile()
	p.Name = "test.identity@1"
	p.Identity = ClaudeCodeIdentity()
	res := redact(t, p, s, nil)
	var got []string
	for _, f := range res.Findings {
		if f.Kind == FindingIdentity {
			got = append(got, fmt.Sprintf("%d %s", f.Position, f.At))
			if strings.Contains(f.Message, "LateLoginName") {
				t.Errorf("a finding quotes the value: %+v", f)
			}
		}
	}
	if want := []string{"1 /item/content/0/text"}; !slices.Equal(got, want) {
		t.Errorf("identity findings %v, want %v", got, want)
	}
	if bytes.Contains(fileOf(t, res.Session), []byte(`"user_identity":"LateLoginName"`)) {
		t.Error("the declaring member kept the value")
	}
}

// TestReplacementCounts: a redaction counts what each kind of string
// redactor replaced in what it wrote, a count and never a value, and a
// store pass reports the counts on every run; private addresses are
// kept (#18).
func TestReplacementCounts(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-counts")
	appendAt(t, s, c, user("in "+fakeHome+"/project, my password is "+fakePassword))
	out := "mail fake.person@example.test, fetch https://fakeuser:fakepass@host.example.invalid/x with Authorization: Bearer fake-bearer-0000, private 10.0.0.8 and 127.0.0.1, key " + fakeKey + " and " + fakeKey
	respond(t, s, c, "resp-1", call("call-1"))
	appendAt(t, s, c, agentsession.NewItemEntry(openresponses.NewFunctionCallOutput("call-1", out)))
	turn(t, s, c, "resp-2", "done")
	p := testProfile()
	p.Name = "test.counts@1"
	p.Strings = append(p.Strings, PII())
	res := redact(t, p, s, nil)
	// The header's cwd and note, the user's path, and the call's argument
	// hold the home.
	// The default patterns take the URL's password and the Bearer token.
	want := map[string]int{"secret": 1, "home": 4, "openai_key": 2, "email": 1, "bearer_token": 1, "url_password": 1}
	if !reflect.DeepEqual(res.Counts, want) {
		t.Errorf("counts %v, want %v", res.Counts, want)
	}
	file := fileOf(t, res.Session)
	for _, kept := range []string{"10.0.0.8", "127.0.0.1"} {
		if !bytes.Contains(file, []byte(kept)) {
			t.Errorf("%s was replaced", kept)
		}
	}
	st := agentsession.NewMemoryStore()
	load(t, st, s)
	for run := range 2 {
		if r := bySession(redactStore(t, st, p, StoreOptions{}))[s.ID()]; !reflect.DeepEqual(r.Counts, want) {
			t.Errorf("run %d: counts %v, want %v", run, r.Counts, want)
		}
	}
}

// TestIdentityFromText: the host and login names a shell prompt, an
// ls -l listing and an env entry's workspace name are harvested and
// replaced, with no api-request record (review finding 5).
func TestIdentityFromText(t *testing.T) {
	c := &clock{}
	s := newOriginal("orig-identity-text")
	env := agentsession.NewEnvEntry("")
	ws := env.SetWorkspace(agentsession.WorkspaceLocal, "")
	if err := ws.SetMember("host", "fakehost-ws-01"); err != nil {
		t.Fatal(err)
	}
	appendAt(t, s, c, env)
	appendAt(t, s, c, user("fakelogin@FAKEHOST-01:~$ ls -l\n-rw-r--r-- 1 fakeowner fakegroup 12 Jan  1 00:00 f.txt\ndrwxr-xr-x 2 root root 4096 Jan  1 00:00 d"))
	turn(t, s, c, "resp-1", "fakelogin owns it on FAKEHOST-01 and fakehost-ws-01; fakeowner too")
	p := Profile{Name: "test.identity-text@1", Identity: ClaudeCodeIdentity()}
	res := redact(t, p, s, nil)
	file := strings.ToLower(string(fileOf(t, res.Session)))
	for _, v := range []string{"fakelogin", "fakehost-01", "fakeowner", "fakegroup", "fakehost-ws-01"} {
		if strings.Contains(file, v) {
			t.Errorf("the redaction keeps %q", v)
		}
	}
	if !strings.Contains(file, "root root") {
		t.Error("a system account's name was replaced")
	}
}

// TestKeyInsideAStruct: a Key in a caller's unexported field prints no
// byte of itself, by %+v, %#v or slog (review finding 6).
func TestKeyInsideAStruct(t *testing.T) {
	type config struct {
		name string
		key  Key
	}
	c := config{name: "x", key: testKey}
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("cfg", "c", c)
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("cfg", "c", c)
	raw := string(keyBytes(testKey))
	for _, out := range []string{fmt.Sprintf("%v %+v %#v", c, c, c), logged.String()} {
		if strings.Contains(out, raw) || strings.Contains(out, fmt.Sprint([]byte(raw))) || strings.Contains(out, fmt.Sprintf("%x", raw)) {
			t.Errorf("the key's bytes are printed: %s", out)
		}
	}
}

// keyBytes are k's bytes, for tests that look for them in output.
func keyBytes(k Key) []byte { return k.bytes() }
