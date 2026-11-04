package agentredact

import (
	"net/netip"
	"regexp"
	"strings"
)

// PII replaces the personal data of third parties that text tends to
// carry, which [DefaultPatterns], a set of secret shapes, does not
// look for: email addresses, IPv4 and IPv6 addresses outside the
// loopback, private, link-local, unspecified, multicast and
// documentation ranges, and phone numbers written with separators, an
// international one with its "+" and a North American one as (555)
// 555-0100 or 555-555-0100. Each match is written "[REDACTED <name>]",
// or in a redaction "[REDACTED <name>#<n>]" ([Placeholders]), name being
// email, ipv4, ipv6 or phone, in that order, each applied to what the
// earlier ones left.
//
// It is opt-in: a profile that adds it writes something else than it
// did, so it takes a new version. The user's own addresses are better
// found from what the session declares ([Profile.Identity]); this set is
// for everyone else's. A number written without separators, an address
// spelled out ("name at host"), an IP inside a longer token such as a
// version string, and an IPv6 address of fewer than three groups are
// not found. A URL's credentials, user:password@host, read as an email
// address, which hides the password with the host.
func PII() StringRedactor {
	return func(s string, ph *Placeholders) string {
		s = emailAddress.ReplaceAllStringFunc(s, func(m string) string { return ph.For("email", m) })
		s = replaceIPs(s, ipv4Candidate, "ipv4", ph)
		s = replaceIPs(s, ipv6Candidate, "ipv6", ph)
		for _, re := range phoneNumbers {
			s = re.ReplaceAllStringFunc(s, func(m string) string { return ph.For("phone", m) })
		}
		return s
	}
}

var (
	emailAddress  = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\b`)
	ipv4Candidate = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ipv6Candidate = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
	phoneNumbers  = []*regexp.Regexp{
		regexp.MustCompile(`\+[1-9][0-9]{0,2}[ .-]?(?:\([0-9]{1,4}\)[ .-]?)?[0-9]{1,4}(?:[ .-][0-9]{2,5}){1,4}\b`),
		regexp.MustCompile(`(?:\([2-9][0-9]{2}\) ?|\b[2-9][0-9]{2}[.-])[2-9][0-9]{2}[.-][0-9]{4}\b`),
	}
	documentation = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
)

// replaceIPs replaces each candidate match of re in s that is an IP
// address standing on its own, outside the ranges that name no one.
func replaceIPs(s string, re *regexp.Regexp, name string, ph *Placeholders) string {
	matches := re.FindAllStringIndex(s, -1)
	if matches == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		if m[0] > 0 && ipPart(s[m[0]-1]) || m[1] < len(s) && ipPart(s[m[1]]) {
			continue // inside a longer token: a version, a hash, a time
		}
		cand := s[m[0]:m[1]]
		if name == "ipv6" && groups(cand) < 3 {
			continue // a::b, as code writes a scope, parses but names no host
		}
		addr, err := netip.ParseAddr(cand)
		if err != nil || !public(addr) {
			continue
		}
		b.WriteString(s[last:m[0]])
		b.WriteString(ph.For(name, s[m[0]:m[1]]))
		last = m[1]
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// groups counts the non-empty colon-separated groups of an IPv6
// candidate.
func groups(s string) int {
	n := 0
	for _, g := range strings.Split(s, ":") {
		if g != "" {
			n++
		}
	}
	return n
}

// ipPart reports whether c, beside an address, makes it part of a
// longer token.
func ipPart(c byte) bool {
	return isAlnum(c) || c == '.' || c == ':' || c == '_' || c == '-'
}

// public reports whether addr can name a host of someone's: not
// loopback, private, link-local, unspecified, multicast or reserved for
// documentation.
func public(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified() || addr.IsMulticast() || addr.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range documentation {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}
