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
// the function a Rewriter applies. Like [Chain], it leaves a base64
// data URL as it is.
func (p Profile) StringFunc() StringRedactor {
	return Chain(p.Strings...)
}

// Chain joins string redactors into one that applies each in order,
// except to a string that is wholly a base64 data URL, which it returns
// as it is without calling any of them: data:, an optional media type
// and parameters with no whitespace, ";base64,", and a payload of the
// base64 alphabet alone (standard or URL-safe, padding included), as
// an inline image is held. A redactor matches text as written and does
// not decode base64, so it could find nothing there but a pattern
// matching the payload by chance, and replacing that would corrupt the
// media while hiding nothing. Text inside such a payload is not found:
// see the README. A data URL that is not base64 holds its text as
// written, which a redactor can find, so it is redacted like any other
// string, as is a line that merely starts "data:", such as a
// server-sent event.
func Chain(rs ...StringRedactor) StringRedactor {
	rs = append([]StringRedactor(nil), rs...)
	return func(s string) string {
		if isBase64DataURL(s) {
			return s
		}
		for _, r := range rs {
			s = r(s)
		}
		return s
	}
}

// isBase64DataURL reports whether s is wholly a base64 data URL
// (RFC 2397), its scheme and base64 marker matched without regard to
// case.
func isBase64DataURL(s string) bool {
	if len(s) < len("data:") || !strings.EqualFold(s[:len("data:")], "data:") {
		return false
	}
	meta, payload, ok := strings.Cut(s[len("data:"):], ",")
	if !ok || payload == "" {
		return false
	}
	const marker = ";base64"
	if len(meta) < len(marker) || !strings.EqualFold(meta[len(meta)-len(marker):], marker) {
		return false
	}
	for i := 0; i < len(meta); i++ {
		if c := meta[i]; c <= ' ' || c >= 0x7f || c == '"' || c == '\\' {
			return false
		}
	}
	for i := 0; i < len(payload); i++ {
		if c := payload[i]; !isAlnum(c) && c != '+' && c != '/' && c != '=' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
