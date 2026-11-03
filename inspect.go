package agentredact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ChristopherDavenport/agentsession"
)

// inspect checks the entry e, as the entry redactors left it, for what
// the redaction must report: inline media that is not an image, and an
// image data URL inside a longer string, are kept and reported. pos is
// its position in the original.
func inspect(e agentsession.Entry, pos int, findings *[]Finding) error {
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
			for _, k := range sortedMembers(x) {
				if err := walk(x[k], at+"/"+pointerToken(k)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(tree, "")
}
