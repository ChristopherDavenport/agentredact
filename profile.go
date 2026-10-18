package agentredact

import (
	"errors"
	"fmt"
	"strings"
)

// StringRedactor rewrites one string. A profile joins its string
// redactors, in order, into the one function an
// [agentsession.Rewriter] applies to every string the format lets a
// redactor change. It must be deterministic: one input gives one
// output, on every call and every run, with no clock, no randomness
// and no dependence on map order, since a response ID and an
// instruction part's text are named across entries by their value, and
// a rerun must write what it wrote before.
type StringRedactor func(string) string

// Profile is a named, versioned set of redactors. Its name is written
// to a redacted session's redacted_from.profile and goes into the
// session's ID ([agentsession.RedactedSessionID]), so one original
// under one profile has one redacted session, which the profile
// resumes. A profile names one set of rules: changing what a profile's
// redactors write mixes two redactions in one session, so a changed
// rule set takes a new version.
type Profile struct {
	// Name is the profile's name and version, <name>@<version>, such as
	// "default@1": see [ValidateProfileName].
	Name string
	// Strings are applied in order to every string the Rewriter reaches,
	// the header's free-text members included.
	Strings []StringRedactor
	// Entries are applied in order to each entry after its strings are
	// rewritten, and, those that are [HeaderRedactor]s, to the header.
	Entries []EntryRedactor
}

// ErrProfileName is returned for a profile name [ValidateProfileName]
// refuses.
var ErrProfileName = errors.New("agentredact: invalid profile name")

// maxProfileName bounds a profile name, in bytes.
const maxProfileName = 128

// ValidateProfileName reports whether name is a profile name:
// <name>@<version>, at most 128 bytes, where name is one or more ASCII
// letters, digits, '.', '_' or '-', starting with a letter or a digit,
// and version is a decimal integer of at least 1 with no leading zero.
// "default@1" and "example.redact-home@2" are names; "default",
// "default@", "default@01" and "my profile@1" are not.
//
// The version is required because a profile names one set of rules and
// a changed set takes a new one; the character set keeps the name safe
// in a file name, a command line and a log, where it is shown beside
// session IDs.
func ValidateProfileName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty", ErrProfileName)
	}
	if len(name) > maxProfileName {
		return fmt.Errorf("%w: %d bytes, more than %d", ErrProfileName, len(name), maxProfileName)
	}
	base, version, ok := strings.Cut(name, "@")
	if !ok {
		return fmt.Errorf("%w: %q has no @<version>", ErrProfileName, name)
	}
	if base == "" || !isAlnum(base[0]) {
		return fmt.Errorf("%w: %q does not start with a letter or a digit", ErrProfileName, name)
	}
	for i := 0; i < len(base); i++ {
		if c := base[i]; !isAlnum(c) && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("%w: %q holds %q", ErrProfileName, name, c)
		}
	}
	if version == "" || version[0] == '0' {
		return fmt.Errorf("%w: %q: the version is a decimal integer from 1, with no leading zero", ErrProfileName, name)
	}
	for i := 0; i < len(version); i++ {
		if c := version[i]; c < '0' || c > '9' {
			return fmt.Errorf("%w: %q: the version is a decimal integer from 1, with no leading zero", ErrProfileName, name)
		}
	}
	return nil
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// Validate reports whether p can redact: its name valid, and no nil
// redactor among its own.
func (p Profile) Validate() error {
	if err := ValidateProfileName(p.Name); err != nil {
		return err
	}
	for i, s := range p.Strings {
		if s == nil {
			return fmt.Errorf("agentredact: profile %s: string redactor %d is nil", p.Name, i)
		}
	}
	for i, e := range p.Entries {
		if e == nil {
			return fmt.Errorf("agentredact: profile %s: entry redactor %d is nil", p.Name, i)
		}
	}
	return nil
}

// StringFunc returns the profile's string redactors joined in order,
// the function a Rewriter applies. Like [Chain], it keeps a base64 data
// URL's payload as it is.
func (p Profile) StringFunc() StringRedactor {
	return Chain(p.Strings...)
}

// Chain joins string redactors into one that applies each in order,
// except to the payload of a string that is wholly a base64 data URL:
// data:, an optional media type and parameters with no whitespace,
// ";base64,", and a payload of the base64 alphabet alone (standard or
// URL-safe, padding included), as an inline image is held. Of such a
// string the redactors are given the media type and parameters, which
// can hold a file name or a token as written, and the payload is kept
// as it is. A redactor matches text as written and does not decode
// base64, so in the payload it could find nothing but a pattern
// matching by chance, and replacing that would corrupt the media while
// hiding nothing; but a token written as the payload itself, made only
// of base64 characters, is kept too. Text inside a payload is not
// found: see the README. A data URL that is not base64 holds its text
// as written, which a redactor can find, so it is redacted like any
// other string, as is a line that merely starts "data:", such as a
// server-sent event.
func Chain(rs ...StringRedactor) StringRedactor {
	rs = append([]StringRedactor(nil), rs...)
	apply := func(s string) string {
		for _, r := range rs {
			s = r(s)
		}
		return s
	}
	return func(s string) string {
		if meta, payload, ok := splitBase64DataURL(s); ok {
			return s[:len("data:")] + apply(meta) + "," + payload
		}
		return apply(s)
	}
}

// isBase64DataURL reports whether s is wholly a base64 data URL.
func isBase64DataURL(s string) bool {
	_, _, ok := splitBase64DataURL(s)
	return ok
}

// splitBase64DataURL splits s, when it is wholly a base64 data URL
// (RFC 2397), into its media type and parameters, ";base64" included,
// and its payload. The scheme and the base64 marker are matched without
// regard to case.
func splitBase64DataURL(s string) (meta, payload string, ok bool) {
	if len(s) < len("data:") || !strings.EqualFold(s[:len("data:")], "data:") {
		return "", "", false
	}
	meta, payload, ok = strings.Cut(s[len("data:"):], ",")
	if !ok || payload == "" {
		return "", "", false
	}
	const marker = ";base64"
	if len(meta) < len(marker) || !strings.EqualFold(meta[len(meta)-len(marker):], marker) {
		return "", "", false
	}
	for i := 0; i < len(meta); i++ {
		if c := meta[i]; c <= ' ' || c >= 0x7f || c == '"' || c == '\\' {
			return "", "", false
		}
	}
	for i := 0; i < len(payload); i++ {
		if c := payload[i]; !isAlnum(c) && c != '+' && c != '/' && c != '=' && c != '-' && c != '_' {
			return "", "", false
		}
	}
	return meta, payload, true
}
