// Package idna centralizes host canonicalization so the idna policy lives in one
// owned place, independent of the public sanitize API. It builds on a vendored
// copy of golang.org/x/net/idna under internal/x, which freezes canonicalization
// against upstream and toolchain Unicode drift so stored A-labels stay a stable
// lookup key — see internal/x/README.md for the rationale.
package idna

import xidna "github.com/netstar-labs/sanitize/internal/x/net/idna"

// strict and loose are the shared idna profiles. Both use non-transitional
// (UTS-46) processing, so deviation characters resolve as browsers and
// registries now handle them (faß.de -> xn--fa-hia.de, not fass.de). strict
// enforces STD3 ASCII rules (letters, digits, hyphen); loose relaxes STD3 so
// underscore labels (_dmarc, _sip._tcp) validate. Both are immutable and safe
// for concurrent use, so a single instance of each serves every caller.
var (
	strict = xidna.New(xidna.MapForLookup(), xidna.Transitional(false))
	loose  = xidna.New(xidna.MapForLookup(), xidna.Transitional(false), xidna.StrictDomainName(false))
)

// ToASCII converts host to its canonical punycode A-label. When allowUnderscore
// is true, STD3 ASCII rules are relaxed so underscore (and other non-LDH ASCII
// that UTS-46 permits) validate. ok is false when the label is not a valid idna
// name, in which case the caller should treat host as malformed.
func ToASCII(host string, allowUnderscore bool) (ascii string, ok bool) {
	p := strict
	if allowUnderscore {
		p = loose
	}
	a, err := p.ToASCII(host)
	if err != nil {
		return "", false
	}
	return a, true
}
