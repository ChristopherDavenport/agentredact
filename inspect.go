package agentredact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ChristopherDavenport/agentsession"
)

// ErrKeyNotRedacted is returned by [Redact] for an entry holding a
// member name, at any depth, that the profile's string redactors would
// change: a path keying a map in a custom entry's data, an outcome's
// details, a member the format does not define or an extension entry's
// own members. agentsession's Rewriter gives a redactor no member name
// but an env entry's file paths, so such a name would be written as the
// original had it; a profile that would leave a matched name in place
// does not produce a redaction. The error names the entry's position and
// a pointer to the member built from rewritten names, never the name.
var ErrKeyNotRedacted = errors.New("agentredact: a member name the string redactors would change is kept as written")

// inspect checks the entry e, as the entry redactors left it, for what
// the redaction must not write or must report: a member name f would
// change is ErrKeyNotRedacted; inline media that is not an image, and an
// image data URL inside a longer string, are kept and reported. pos is
// its position in the original.
func inspect(e agentsession.Entry, f StringRedactor, pos int, findings *[]Finding) error {
	data, err := agentsession.MarshalEntry(e)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return err
	}
	_, env := e.(*agentsession.EnvEntry)
	report := func(kind FindingKind, at, message string) {
		*findings = append(*findings, Finding{Kind: kind, Position: pos, At: at, Redactor: "redact", Message: message})
	}
	var walk func(v any, at string) error
	walk = func(v any, at string) error {
		switch x := v.(type) {
		case string:
			switch {
			case isBase64DataURL(x) && !isImageDataURL(x):
				report(FindingInlineMedia, at, "inline media that is not an image kept as it is: no redactor replaces it, and text in it is not found")
			case !isImageDataURL(x):
				for range strings.Count(strings.ToLower(x), "data:image/") {
					report(FindingEmbeddedImage, at, "an image data URL inside a longer string kept as it is: Images replaces whole-string data URLs only")
				}
			}
		case []any:
			for i, el := range x {
				if err := walk(el, fmt.Sprintf("%s/%d", at, i)); err != nil {
					return err
				}
			}
		case map[string]any:
			// An env entry's file paths are the one place the Rewriter
			// renames member names; they are what f made of them.
			renamed := env && (at == "/files/read" || at == "/files/written")
			for _, k := range sortedMembers(x) {
				if !renamed {
					if now := f(k); now != k {
						return fmt.Errorf("%w: at %s", ErrKeyNotRedacted, at+"/"+pointerToken(now))
					}
				}
				if err := walk(x[k], at+"/"+pointerToken(k)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(tree, "")
}
