package sanitize_test

import (
	"strings"
	"testing"

	"github.com/netstar-labs/sanitize"
)

// rectify runs ToHost in rectify-only mode and returns the rewritten host plus
// its status.
func rectify(raw string) (host string, okay, isIP bool) {
	u := raw
	r := sanitize.NewSanitizer().ToHost(&u)
	return u, r.Okay, r.IP
}

// TestRectifyEdgeCases is the regression suite for the URL host-extraction audit
// (findings F1, F2, F4–F7): backslash authority-confusion, empty labels, last-@
// userinfo, whitespace stripping, percent-decoding, and multi-trailing-dot.
func TestRectifyEdgeCases(t *testing.T) {
	for _, tc := range []struct {
		id, in, host string
		okay         bool
	}{
		// F1 — backslash is a slash for special schemes; it ends the authority, so
		// the host is the segment before it (not smuggled past via "\@").
		{"F1a", `http://evil.com\@good.com/`, "evil.com", true},
		{"F1b", `http://good.com\@evil.com/`, "good.com", true},
		{"F1c", `http://example.com\path`, "example.com", true},
		{"F1d", `https:\\example.com`, "example.com", true},
		// F2 — empty labels are not valid hosts.
		{"F2a", "http://example..com/", "", false},
		{"F2b", "http://.example.com/", "", false},
		// F4 — userinfo ends at the LAST '@'.
		{"F4a", "http://a@b.com@c.com/", "c.com", true},
		{"F4b", "http://a@b@c.com/", "c.com", true},
		// F5 — tab/LF/CR removed anywhere; leading/trailing space trimmed.
		{"F5a", "http://example.com ", "example.com", true},
		{"F5b", "http://exam\tple.com", "example.com", true},
		{"F5c", "http://example.com\n", "example.com", true},
		// F6 — percent-decode the host; reject an escape that decodes to a delimiter.
		{"F6a", "http://%65xample.com/", "example.com", true}, // %65 = 'e'
		{"F6b", "http://%2Fevil.com/", "", false},             // %2F = '/', forbidden
		// F7 — all trailing dots are stripped, not just one.
		{"F7a", "http://example.com../", "example.com", true},
	} {
		host, okay, _ := rectify(tc.in)
		if host != tc.host || okay != tc.okay {
			t.Errorf("%s: ToHost(%q) = host=%q okay=%v; want host=%q okay=%v",
				tc.id, tc.in, host, okay, tc.host, tc.okay)
		}
	}
}

// TestRectifyPostIDNAMappingEdgeCases is the regression suite for finding F9 (A1
// audit): idna's UTS-46 mapping folds "fullwidth" Unicode punctuation (U+FF00-
// FFEF, e.g. '．'->'.', '＠'->'@', '／'->'/') to its literal ASCII form AFTER
// prep's own delimiter/empty-label checks have already run — so a fullwidth
// delimiter sails through pre-mapping validation clean and then decodes into a
// real delimiter/empty label inside a host reported Okay=true. This is a
// regression of the F2 fix (06eeb92), which closed the identical hole for
// literal and percent-encoded input but not for Unicode mapping.
func TestRectifyPostIDNAMappingEdgeCases(t *testing.T) {
	// F9a — fullwidth dot; default (strict) profile, no special config needed.
	if host, okay, _ := rectify("a．．b.com"); okay {
		t.Errorf("F9a: ToHost(fullwidth dots) = host=%q okay=true, want okay=false (empty label smuggled through)", host)
	}

	// F9b/c — fullwidth '@'/'/' ; require AllowUnderscore(true) (the loose
	// profile), a documented, realistic config for _dmarc/_sip._tcp-style
	// DNS-record consumers.
	loose := sanitize.NewSanitizer().AllowUnderscore(true)
	rectifyLoose := func(raw string) (string, bool) {
		h := raw
		r := loose.ToHost(&h)
		return h, r.Okay
	}
	if host, okay := rectifyLoose("good.com＠evil.com"); okay {
		t.Errorf("F9b: ToHost(fullwidth @, loose) = host=%q okay=true, want okay=false (delimiter smuggled through)", host)
	}
	if host, okay := rectifyLoose("evil.com／path.example.com"); okay {
		t.Errorf("F9c: ToHost(fullwidth /, loose) = host=%q okay=true, want okay=false (delimiter smuggled through)", host)
	}
}

// TestRectifyOverlongLabel is the regression suite for finding F10 (A1 audit):
// neither idna profile enforces the RFC 1035 63-octet per-label limit, so a
// syntactically-invalid name would otherwise still report Okay=true.
func TestRectifyOverlongLabel(t *testing.T) {
	overlong := strings.Repeat("a", 64) + ".com"
	if host, okay, _ := rectify("http://" + overlong + "/"); okay {
		t.Errorf("F10: ToHost(64-byte label) = host=%q okay=true, want okay=false", host)
	}
	// boundary: exactly 63 bytes must still pass.
	boundary := strings.Repeat("a", 63) + ".com"
	if host, okay, _ := rectify("http://" + boundary + "/"); !okay || host != boundary {
		t.Errorf("F10 boundary: ToHost(63-byte label) = host=%q okay=%v, want host=%q okay=true", host, okay, boundary)
	}
}

// TestIPClassificationSpecials is the regression suite for finding F3 (link-
// local/multicast/broadcast/CGNAT/4-in-6) and F11 (A1 audit: the remaining
// IANA special-purpose ranges — documentation, benchmarking, deprecated 6to4
// relay anycast, and reserved Class E): a threat tool must not classify any of
// these as usable public hosts.
func TestIPClassificationSpecials(t *testing.T) {
	for _, tc := range []struct {
		in     string
		public bool
	}{
		{"http://169.254.169.254/", false},          // link-local (cloud metadata)
		{"http://fe80::1/", false},                  // v6 link-local
		{"http://224.0.0.1/", false},                // multicast
		{"http://255.255.255.255/", false},          // broadcast
		{"http://[::ffff:169.254.169.254]/", false}, // 4-in-6 link-local
		{"http://100.64.0.1/", false},               // CGNAT 100.64/10
		{"http://10.0.0.1/", false},                 // RFC1918 (already caught)
		{"http://192.0.2.1/", false},                // F11: TEST-NET-1
		{"http://198.51.100.1/", false},             // F11: TEST-NET-2
		{"http://203.0.113.1/", false},              // F11: TEST-NET-3
		{"http://198.18.0.1/", false},               // F11: benchmarking 198.18.0.0/15
		{"http://192.88.99.1/", false},              // F11: deprecated 6to4 relay anycast
		{"http://240.0.0.1/", false},                // F11: reserved (Class E)
		{"http://8.8.8.8/", true},                   // genuinely public
	} {
		_, okay, isIP := rectify(tc.in)
		if !isIP {
			t.Errorf("%q: not classified as IP", tc.in)
			continue
		}
		if okay != tc.public {
			t.Errorf("%q: public=%v; want %v", tc.in, okay, tc.public)
		}
	}
}

// TestICANNDomainsOnly is the regression for finding F8: the PSL private-domains
// section loads by default (so blogspot.com is a public suffix), and
// ICANNDomainsOnly stops at the marker (so only com is).
func TestICANNDomainsOnly(t *testing.T) {
	full := sanitize.NewSanitizer().Configure(&sanitize.Options{Source: []string{"testdata/psl_icann_fixture.dat"}})
	icann := sanitize.NewSanitizer().Configure(&sanitize.Options{Source: []string{"testdata/psl_icann_fixture.dat"}, ICANNDomainsOnly: true})

	apex := func(s *sanitize.Sanitizer, raw string) string {
		u := raw
		r := s.ToHost(&u)
		if !r.Okay {
			return "<reject>"
		}
		return u[r.Apex:]
	}
	if got := apex(full, "foo.blogspot.com"); got != "foo.blogspot.com" {
		t.Errorf("full PSL: apex(foo.blogspot.com) = %q, want foo.blogspot.com (private domain is a suffix)", got)
	}
	if got := apex(icann, "foo.blogspot.com"); got != "blogspot.com" {
		t.Errorf("ICANN-only: apex(foo.blogspot.com) = %q, want blogspot.com (private section skipped)", got)
	}
}
