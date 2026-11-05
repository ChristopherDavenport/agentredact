package agentredact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ChristopherDavenport/agentsession"
)

// inspect checks the entry e, as the entry redactors left it, for what
// the redaction must report: inline media that is not an image, and an
// image data URL inside a longer string, are kept and reported; and,
// when the profile replaces no image (images false), every inline image
// kept whole. A sidecar reference is the blob step's to report, by the
// blob's bytes ([redaction.sidecars]). pos is its position in the
// original.
//
// A string or a member name holding a spelling of a value ids holds is
// reported as an identity value, by its pointer, never the value.
func inspect(e agentsession.Entry, pos int, findings *[]Finding, images bool, ids *identities) error {
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
	var walk func(v any, at, member string) error
	walk = func(v any, at, member string) error {
		switch x := v.(type) {
		case string:
			if ids.found(x) {
				report(FindingIdentity, at, "a value an identity member of the original names, in one of its spellings")
			}
			if !images && isImageDataURL(x) {
				report(FindingImage, at, "an image kept: the profile replaces no image, and no string redactor reads the text in its pixels")
			}
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
				if err := walk(el, fmt.Sprintf("%s/%d", at, i), ""); err != nil {
					return err
				}
			}
		case map[string]any:
			for _, k := range sortedMembers(x) {
				if ids.found(k) {
					report(FindingIdentity, at, "a member name holding a value an identity member of the original names")
				}
				if err := walk(x[k], at+"/"+pointerToken(k), k); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(tree, "", "")
}

// memberNames reports each name the format keeps as written that f
// would change: of a member of e the format does not define, and of a
// member of an item entry's item, whose names the payload profile
// defines. The Rewriter leaves both, so a matched name would be written
// as the original had it; the finding names neither the member nor the
// match.
func memberNames(e agentsession.Entry, pos int, f func(string) string) []Finding {
	var out []Finding
	report := func(at string) {
		out = append(out, Finding{Kind: FindingMemberName, Position: pos, At: at, Redactor: "redact",
			Message: "a member's name holds what the string redactors replace, and the format keeps it as written"})
	}
	for _, k := range slices.Sorted(maps.Keys(e.Base().Unknown)) {
		if f(k) != k {
			report("")
			break
		}
	}
	if it, ok := e.(*agentsession.ItemEntry); ok && it.Item != nil {
		data, err := json.Marshal(it.Item)
		var m map[string]json.RawMessage
		if err == nil && json.Unmarshal(data, &m) == nil {
			for _, k := range slices.Sorted(maps.Keys(m)) {
				if f(k) != k {
					report("/item")
					break
				}
			}
		}
	}
	return out
}
