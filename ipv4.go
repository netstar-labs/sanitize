package sanitize

import (
	"net/netip"
	"strings"
)

// parseIPv4Radix implements inet_aton semantics: one to four dot-separated
// parts, each independently radix-detected (0x hex, leading-0 octal, else
// decimal), with the final part absorbing all remaining octets. Browsers resolve
// "2130706433", "0x7f.0.0.1" and "127.1" to 127.0.0.1, while netip.ParseAddr
// accepts strict dotted-quad decimal only — so without this those forms fall
// through as hostnames and are never judged as addresses.
//
// It mirrors github.com/netstar-labs/normie.ParseIPv4; keep the two in step.
func parseIPv4Radix(s string) (netip.Addr, bool) {
	// Every part of an inet_aton address starts with a digit, so any other lead
	// byte is a hostname. This runs on every host, so it must not allocate.
	if s == "" || len(s) > 63 || s[0] < '0' || s[0] > '9' {
		return netip.Addr{}, false
	}
	var vals [4]uint64
	n := 0
	for {
		if n == len(vals) {
			return netip.Addr{}, false // more than four parts
		}
		part, rest, more := strings.Cut(s, ".")
		v, ok := parseIPv4Part(part)
		if !ok {
			return netip.Addr{}, false
		}
		vals[n] = v
		n++
		if !more {
			break
		}
		s = rest
	}
	for i := 0; i < n-1; i++ { // every part but the last is a single octet
		if vals[i] > 0xff {
			return netip.Addr{}, false
		}
	}
	if rem := uint(4 - (n - 1)); vals[n-1] >= uint64(1)<<(8*rem) {
		return netip.Addr{}, false // the last part must fit the octets left
	}
	var word uint32
	for i := 0; i < n-1; i++ {
		word |= uint32(vals[i]) << (8 * (3 - uint(i)))
	}
	word |= uint32(vals[n-1])
	return netip.AddrFrom4([4]byte{byte(word >> 24), byte(word >> 16), byte(word >> 8), byte(word)}), true
}

// parseIPv4Part decodes one component with C radix rules. An empty component is
// invalid, which rejects "1..2". 12 bytes is the longest meaningful part (a full
// 32-bit value in octal, "037777777777"), so v cannot overflow uint64. Parsed by
// hand: strconv.ParseUint heap-allocates its error on every non-numeric label.
func parseIPv4Part(p string) (uint64, bool) {
	if p == "" || len(p) > 12 {
		return 0, false
	}
	base := uint64(10)
	switch {
	case len(p) > 2 && p[0] == '0' && p[1]|0x20 == 'x':
		base, p = 16, p[2:]
	case len(p) > 1 && p[0] == '0':
		base, p = 8, p[1:]
	}
	var v uint64
	for i := 0; i < len(p); i++ {
		c := p[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c|0x20 >= 'a' && c|0x20 <= 'f':
			d = uint64(c|0x20-'a') + 10
		default:
			return 0, false
		}
		if d >= base {
			return 0, false
		}
		v = v*base + d
	}
	return v, true
}
