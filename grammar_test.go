package sanitize_test

import (
	"testing"

	"github.com/netstar-labs/sanitize"
)

// TestAuthorityGrammar locks in WHATWG authority parsing: the authority ends at
// the first '/', '?' or '#' (backslash folding to '/'), userinfo ends at the
// LAST '@' inside it, a scheme only counts at the very start of the input, and
// the special schemes tolerate missing or extra slashes. Every row where the
// naive byte-scan answer differs from the browser's is a host misattribution —
// either an innocent domain blamed for an attacker's host, or an attacker host
// hidden where the parser reads a path. Expected hosts match github.com/netstar-labs/normie.Split.
func TestAuthorityGrammar(t *testing.T) {
	var s sanitize.Sanitizer
	for _, tc := range []struct {
		in       string
		host     string
		okay, ip bool
		port     int
	}{
		// '#' and '?' end the authority; '@' after them is fragment/query, not userinfo
		{`http://example.com#@evil.com`, "example.com", true, false, 0},
		{`http://example.com?@evil.com`, "example.com", true, false, 0},
		{`http://example.com?x=a@evil.com/p`, "example.com", true, false, 0},
		{`http://example.com#frag/with/slash`, "example.com", true, false, 0},
		{`http://example.com:8080?x=1`, "example.com", true, false, 8080},
		{`http://example.com:8080#f`, "example.com", true, false, 8080},

		// "://" after the authority is query/fragment content, never a scheme
		{`http://example.com?x=http://evil.com/`, "example.com", true, false, 0},
		{`example.com?x=http://foo.com`, "example.com", true, false, 0},
		{`example.com#http://foo.com`, "example.com", true, false, 0},

		// backslash folds, userinfo ends at the last '@'
		{`http://example.com\@evil.com/`, "example.com", true, false, 0},
		{`http://a@b@evil.com/`, "evil.com", true, false, 0},
		{`http://example.com:80@evil.com/`, "evil.com", true, false, 0},

		// special schemes tolerate missing/extra slashes
		{`http:/example.com/`, "example.com", true, false, 0},
		{`http:example.com/`, "example.com", true, false, 0},
		{`http:///example.com/`, "example.com", true, false, 0},
		{`HTTP:\\example.com\x`, "example.com", true, false, 0},
		{`//example.com/x`, "example.com", true, false, 0},

		// file: has an empty host; it must not promote the first path segment
		{`file:///a.example.com/x`, "", false, false, 0},
	} {
		v := tc.in
		r := s.ToHost(&v)
		if v != tc.host || r.Okay != tc.okay || r.IP != tc.ip || r.Port != tc.port {
			t.Errorf("%q => host=%q %+v; want host=%q Okay=%v IP=%v Port=%d",
				tc.in, v, r, tc.host, tc.okay, tc.ip, tc.port)
		}
	}
}

// TestIPv4Radix locks in inet_aton parsing: browsers resolve decimal-dword, hex,
// octal and short dotted forms to the same address as the dotted quad, so a
// rectifier built on strict netip parsing lets them fall through as a hostname
// — an IP-literal indicator that is never matched against an IP blocklist.
func TestIPv4Radix(t *testing.T) {
	var s sanitize.Sanitizer
	for _, tc := range []struct {
		in       string
		host     string
		okay, ip bool
	}{
		{`http://134744072/`, "8.8.8.8", true, true},     // dword
		{`http://0x08.8.8.8/`, "8.8.8.8", true, true},    // hex part
		{`http://010.8.8.8/`, "8.8.8.8", true, true},     // octal part
		{`http://8.8.2056/`, "8.8.8.8", true, true},      // short form, last part absorbs 2 octets
		{`http://0x08080808/`, "8.8.8.8", true, true},    // hex dword
		{`http://8.8.8.8./`, "8.8.8.8", true, true},      // trailing root dot
		{`http://%38.8.8.8/`, "8.8.8.8", true, true},     // percent-escaped digit
		{`134744072:8443/x`, "8.8.8.8", true, true},      // schemeless, ported
		{`http://2130706433/`, "127.0.0.1", false, true}, // loopback via dword: IP, not usable
		{`http://127.1/`, "127.0.0.1", false, true},      // loopback via short form
		{`http://123/`, "0.0.0.123", false, true},        // 0.0.0.0/8 is never a public destination
		{`http://1.2.3.4.5/`, "1.2.3.4.5", true, false},  // five parts: not an address, stays a name
		{`http://256.1.1.1/`, "256.1.1.1", true, false},  // octet overflow: not an address
	} {
		v := tc.in
		r := s.ToHost(&v)
		if v != tc.host || r.Okay != tc.okay || r.IP != tc.ip {
			t.Errorf("%q => host=%q %+v; want host=%q Okay=%v IP=%v",
				tc.in, v, r, tc.host, tc.okay, tc.ip)
		}
	}
}

// TestIDNAProducedIPv4: UTS-46 mapping folds fullwidth digits and ideographic
// full stops to ASCII, so a host that is not an address before mapping can be one
// after it. A browser maps first, so "１２７.０.０.１" is 127.0.0.1; probing for an
// address only before mapping reports a loopback literal as an ordinary Okay host.
func TestIDNAProducedIPv4(t *testing.T) {
	var s sanitize.Sanitizer
	for _, tc := range []struct {
		in       string
		host     string
		okay, ip bool
		port     int
	}{
		{"http://１２７.０.０.１/", "127.0.0.1", false, true, 0},
		{"http://８.８.８.８/", "8.8.8.8", true, true, 0},
		{"http://８.８.８.８:8080/x", "8.8.8.8", true, true, 8080},
		{"http://0x7f。0。0。1/", "127.0.0.1", false, true, 0},
		{"http://８.８.２０５６/", "8.8.8.8", true, true, 0},
	} {
		v := tc.in
		r := s.ToHost(&v)
		if v != tc.host || r.Okay != tc.okay || r.IP != tc.ip || r.Port != tc.port || r.Display != "" {
			t.Errorf("%q => host=%q %+v; want host=%q Okay=%v IP=%v Port=%d",
				tc.in, v, r, tc.host, tc.okay, tc.ip, tc.port)
		}
	}
}

// TestIPv6Canonical: an address is one key however it is written. Uppercase,
// uncompressed, zoned and IPv4-mapped spellings must collapse to the form a
// lookup (and the IPv4 spelling of the same host) agrees on; otherwise listing
// 8.8.8.8 does not match [::ffff:8.8.8.8] and the spelling evades the list.
func TestIPv6Canonical(t *testing.T) {
	var s sanitize.Sanitizer
	for _, tc := range []struct {
		in       string
		host     string
		okay, ip bool
		port     int
	}{
		{"2606:4700:0:0:0:0:0:1111", "2606:4700::1111", true, true, 0},
		{"http://[2606:4700::ABCD]/", "2606:4700::abcd", true, true, 0},
		{"http://[2606:4700::ABCD]:8443/x", "2606:4700::abcd", true, true, 8443},
		{"::ffff:8.8.8.8", "8.8.8.8", true, true, 0},
		{"http://[::ffff:808:808]/", "8.8.8.8", true, true, 0},
		{"http://[::FFFF:8.8.8.8]:80/", "8.8.8.8", true, true, 80},
		{"http://[::ffff:127.0.0.1]/", "127.0.0.1", false, true, 0},
		{"http://[2606:4700::1111%25eth0]/", "2606:4700::1111", true, true, 0}, // zone is host-local
		{"2606:4700::1111%eth0", "2606:4700::1111", true, true, 0},
		{"http://[::1]/", "::1", false, true, 0},
		{"http://[0:0:0:0:0:0:0:1]/", "::1", false, true, 0},
	} {
		v := tc.in
		r := s.ToHost(&v)
		if v != tc.host || r.Okay != tc.okay || r.IP != tc.ip || r.Port != tc.port {
			t.Errorf("%q => host=%q %+v; want host=%q Okay=%v IP=%v Port=%d", tc.in, v, r, tc.host, tc.okay, tc.ip, tc.port)
		}
	}
}

// TestNonNavigableSchemes: a scheme that is not a special web scheme is not a
// navigable URL, so its "host" must not be attributed. "javascript://example.com/
// %0aalert(1)" is a script, not a visit to example.com; "mailto:a@example.com" is an
// address, not a URL. Both used to come back as example.com. The forms that merely
// look like a scheme (host:port, bare IPv6, host:junk) still parse as hosts.
func TestNonNavigableSchemes(t *testing.T) {
	var s sanitize.Sanitizer
	for _, tc := range []struct {
		in   string
		host string
		port int
	}{
		// rejected: non-special with "//"
		{`javascript://example.com/%0aalert(1)`, "", 0},
		{`custom://example.com/x`, "", 0},
		{`ssh://example.com/`, "", 0},
		{`git+https://example.com/r`, "", 0},
		// rejected: opaque (no authority)
		{`mailto:a@example.com`, "", 0},
		{`javascript:alert(1)`, "", 0},
		{`data:text/html,x.example.com`, "", 0},
		{`tel:+15551234567`, "", 0},
		{`data:a@b@example.com:80`, "", 0}, // an '@' and a later ':' do not make an opaque scheme a host
		{`user:pass@example.com`, "", 0},   // schemeless creds read as an opaque scheme, as in normie
		{`user:pass@example.com:8080/x`, "", 0},
		// still hosts
		{`file://example.com/x`, "example.com", 0},
		{`ftp://example.com/x`, "example.com", 0},
		{`ws://example.com:8080/x`, "example.com", 8080},
		{`example.com:8080/x`, "example.com", 8080},
		{`example.com:80a`, "example.com", 0}, // lenient junk port is preserved
		{`example.com:`, "example.com", 0},
		{`abcd:ef01:2345::1`, "abcd:ef01:2345::1", 0}, // bare IPv6 whose first group looks like a scheme
		{`fe80::1`, "", 0},                            // link-local: still an IP, but not Okay (host kept below)
	} {
		v := tc.in
		r := s.ToHost(&v)
		if tc.in == `fe80::1` {
			if !r.IP || r.Okay {
				t.Errorf("%q => %q %+v; want IP, not Okay", tc.in, v, r)
			}
			continue
		}
		if v != tc.host || r.Port != tc.port || (tc.host == "" && (r.Okay || r.IP)) {
			t.Errorf("%q => host=%q %+v; want host=%q Port=%d", tc.in, v, r, tc.host, tc.port)
		}
	}
}

// TestCollapseDots: empty labels are collapsed, not rejected, as the GSB
// canonicalization (and normie) do: leading dots dropped, runs of dots folded to
// one, trailing dots dropped. "evil..com" is the host a lookup would key as
// "evil.com"; rejecting it means it is never checked.
func TestCollapseDots(t *testing.T) {
	var s sanitize.Sanitizer
	for _, tc := range []struct {
		in   string
		host string
		okay bool
	}{
		{"http://.example.com/", "example.com", true},
		{"http://..example.com/", "example.com", true},
		{"http://example..com/", "example.com", true},
		{"http://a...b....example.com./x", "a.b.example.com", true},
		{"http://ex%2e%2eample.com/", "ex.ample.com", true}, // decoded dots collapse too
		{"http://example。。com/", "example.com", true},       // mapped by UTS-46, then collapsed
		{"a．．b.com", "a.b.com", true},
		{"http://./", "", false},
		{"http://.../", "", false},
		{"http://.com/", "com", false}, // nothing left to be a registrable host (no dot)
	} {
		v := tc.in
		r := s.ToHost(&v)
		if v != tc.host || r.Okay != tc.okay {
			t.Errorf("%q => host=%q %+v; want host=%q Okay=%v", tc.in, v, r, tc.host, tc.okay)
		}
	}
}
