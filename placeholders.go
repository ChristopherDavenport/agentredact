package agentredact

import "strconv"

// Placeholders writes the placeholders of one redacted session,
// numbering each distinct value a kind of placeholder replaces: the
// first value [Secrets] replaces is written "[REDACTED#1]", another
// "[REDACTED#2]", and the first an openai_key pattern matches "[REDACTED
// openai_key#1]", whichever entry holds them. Within a session, one value
// is always one placeholder and two values are two, so a reader can
// still tell that two redacted values were equal or not, and a rewrite
// never makes two names one: RFC 0001 has a redactor keep two layers of
// an instructions_part list distinct "as by numbering its replacements"
// (since 0.18), which agentsession refuses otherwise with
// [agentsession.ErrLayersMerged].
//
// [Redact] makes one per redaction and gives it to every
// [StringRedactor] it calls. A number depends on the order the values
// are met in, which is fixed: the header's strings first, then the
// original's entries in file order, prefix included, each walked in the
// same order, whether the redaction is fresh or resumed; and a fork
// redacted as a fork of its origin's redaction continues the numbering
// its origin's redaction had reached at the base, so the shared prefix
// and the fork's own entries name one value alike. A nil Placeholders,
// as a redactor called outside a redaction gets, writes unnumbered
// placeholders ("[REDACTED]", "[REDACTED openai_key]").
//
// A Placeholders is not safe for concurrent use; a redaction is one
// goroutine's.
type Placeholders struct {
	n map[string]map[string]int
}

// NewPlaceholders returns an empty numbering, for a [StringRedactor]
// used on its own over strings that belong together.
func NewPlaceholders() *Placeholders {
	return &Placeholders{n: map[string]map[string]int{}}
}

// For returns the placeholder of value as kind replaces it: "[REDACTED
// <kind>#<n>]", or "[REDACTED#<n>]" for an empty kind, n counting from
// 1 the distinct values kind has replaced, in the order met. On a nil
// Placeholders it returns the placeholder with no number.
func (p *Placeholders) For(kind, value string) string {
	label := "[REDACTED"
	if kind != "" {
		label += " " + kind
	}
	if p == nil {
		return label + "]"
	}
	byValue := p.n[kind]
	if byValue == nil {
		byValue = map[string]int{}
		p.n[kind] = byValue
	}
	n, ok := byValue[value]
	if !ok {
		n = len(byValue) + 1
		byValue[value] = n
	}
	return label + "#" + strconv.Itoa(n) + "]"
}

// clone is a copy of p, so a fork continues its origin's numbering
// without changing it.
func (p *Placeholders) clone() *Placeholders {
	c := NewPlaceholders()
	for kind, byValue := range p.n {
		m := make(map[string]int, len(byValue))
		for v, n := range byValue {
			m[v] = n
		}
		c.n[kind] = m
	}
	return c
}
