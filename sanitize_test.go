package sanitize_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/netstar-labs/sanitize"
	"github.com/netstar-labs/sanitize/internal/idna"
)

// TestPublicSuffixRules exercises the three PSL rule kinds — normal, wildcard, and
// exception — plus IDN (U-label) rule matching, loaded hermetically from a local
// fixture (no network). It pins the eTLD (TLD) and apex (eTLD+1) localization that
// distinguishes, e.g., "example.ck" (a bare eTLD under the "*.ck" wildcard) from
// "sub.example.ck" (a registrable apex) and "www.ck" (registrable via the exception).
func TestPublicSuffixRules(t *testing.T) {
	var s sanitize.Sanitizer
	s.Configure(&sanitize.Options{Source: []string{"testdata/psl_fixture.dat"}})

	// Compute the IDN suffix rather than hard-code a punycode magic string.
	gongsi, ok := idna.ToASCII("公司.cn", false)
	if !ok {
		t.Fatal("idna.ToASCII(公司.cn) failed")
	}

	for _, tc := range []struct {
		in        string
		okay      bool
		apex, tld string
	}{
		// normal rules
		{"example.com", true, "example.com", "com"},
		{"blog.example.com", true, "example.com", "com"},
		{"example.co.uk", true, "example.co.uk", "co.uk"},
		{"deep.blog.example.co.uk", true, "example.co.uk", "co.uk"},
		{"co.uk", false, "co.uk", "co.uk"}, // bare public suffix, not a host

		// wildcard "*.ck": example.ck is an eTLD; the apex is one label deeper
		{"example.ck", false, "example.ck", "example.ck"},
		{"sub.example.ck", true, "sub.example.ck", "example.ck"},
		{"a.sub.example.ck", true, "sub.example.ck", "example.ck"},

		// wildcard + exception under kawasaki.jp. (The "!www.ck" exception is exercised
		// in the internal suffix() test — through ToHost it is unreachable because the
		// "www." label is stripped during rectification before tld detection.)
		{"foo.kawasaki.jp", false, "foo.kawasaki.jp", "foo.kawasaki.jp"}, // bare eTLD
		{"shop.foo.kawasaki.jp", true, "shop.foo.kawasaki.jp", "foo.kawasaki.jp"},
		{"city.kawasaki.jp", true, "city.kawasaki.jp", "kawasaki.jp"}, // exception -> registrable

		// IDN rule (公司.cn) must match the A-label host ToHost produces
		{"shop.公司.cn", true, "shop." + gongsi, gongsi},

		// unknown tld is still rejected (no implicit "*" default rule)
		{"foo.nonexistenttld", false, "nonexistenttld", "foo.nonexistenttld"},
	} {
		v := tc.in
		r := s.ToHost(&v)
		if r.Okay != tc.okay || v[r.Apex:] != tc.apex || v[r.TLD:] != tc.tld {
			t.Errorf("%q => host=%q %+v apex=%q tld=%q; want Okay=%v apex=%q tld=%q",
				tc.in, v, r, v[r.Apex:], v[r.TLD:], tc.okay, tc.apex, tc.tld)
		}
	}
}

func TestSanitize(t *testing.T) {

	/*
		=== RUN   TestSanitize
		example.com {true false true 0 0 1234 } ...
		xn--exmple-cua.com {true false true 0 0 1234 exämple.com} ...
		example.com {true false true 0 0 1234 } ...
		100.10.10.10 {true true false 0 0 1234 } ...
		10.10.10.10 {false true false 0 0 1234 } ...
		abcd::dbca {true true false 0 0 1234 } ...
		--- PASS: TestSanitize (0.00s)
	*/

	var s sanitize.Sanitizer
	for _, v := range []string{
		"https://www.example.com:1234/path",          // normal
		"https://www.exämple.com:1234/path",          // idan
		"http://user:pass@www.example.com:1234/path", // user:pass
		"100.10.10.10:1234",                          // ipv4 valid
		"10.10.10.10:1234",                           // ipv4 private
		"https://[abcd::dbca]:1234",                  // ipv6 ported
	} {
		t := time.Now()
		r := s.ToHost(&v)
		fmt.Println(v, r, time.Since(t))

	}
}

// TestSanitizeCases locks in the rectification and validation behavior, including
// the ipv6 bracket-unwrap and ipv4-mapped-ipv6 edge cases.
func TestSanitizeCases(t *testing.T) {
	var s sanitize.Sanitizer
	for _, tc := range []struct {
		in       string
		host     string
		okay, ip bool
		www      bool
	}{
		{"https://www.example.com:1234/path", "example.com", true, false, true},
		{"http://user:pass@www.example.com/x", "example.com", true, false, true},
		{"Example.COM.", "example.com", true, false, false},
		{"HTTP://www.example.com/x", "example.com", true, false, true},        // uppercase scheme
		{"HttpS://example.com", "example.com", true, false, false},            // mixed-case scheme
		{"ftp://example.com/x", "example.com", true, false, false},            // non-http scheme
		{"//www.example.com/x", "example.com", true, false, true},             // protocol-relative
		{"example.com/a?x=http://foo.com", "example.com", true, false, false}, // "://" in query is not a scheme
		{"100.10.10.10:1234", "100.10.10.10", true, true, false},
		{"10.10.10.10:1234", "10.10.10.10", false, true, false}, // rfc1918 private
		{"127.0.0.1", "127.0.0.1", false, true, false},          // loopback
		{"0.0.0.0", "0.0.0.0", false, true, false},              // unspecified
		{"https://[abcd::dbca]:1234", "abcd::dbca", true, true, false},
		{"[2001:db8::1]", "2001:db8::1", true, true, false},     // unported bracket unwrap
		{"::ffff:1.2.3.4", "::ffff:1.2.3.4", true, true, false}, // bare ipv4-mapped ipv6
		{"[::ffff:1.2.3.4]:80", "::ffff:1.2.3.4", true, true, false},
		{"xn--a.com", "", false, false, false}, // malformed punycode -> rejected
	} {
		v := tc.in
		r := s.ToHost(&v)
		if v != tc.host || r.Okay != tc.okay || r.IP != tc.ip || r.WWW != tc.www {
			t.Errorf("%q => host=%q %+v; want host=%q Okay=%v IP=%v WWW=%v",
				tc.in, v, r, tc.host, tc.okay, tc.ip, tc.www)
		}
	}
}

// TestPort locks in the Port contract: the port number removed during
// rectification is reported for host, ipv4, and bracketed ipv6 forms; invalid
// port text (non-numeric, empty, out of range) is still stripped but reports 0,
// and an unbracketed ipv6 literal never carries a port.
func TestPort(t *testing.T) {
	var s sanitize.Sanitizer
	for _, tc := range []struct {
		in   string
		host string
		port int
	}{
		{"example.com:8080", "example.com", 8080},
		{"https://www.example.com:1234/path", "example.com", 1234},
		{"http://user:pass@example.com:8443/x", "example.com", 8443}, // credentials stripped before port
		{"100.10.10.10:1234", "100.10.10.10", 1234},                  // ipv4
		{"https://[abcd::dbca]:443", "abcd::dbca", 443},              // bracketed ipv6
		{"[2001:db8::1]", "2001:db8::1", 0},                          // unported bracket unwrap
		{"abcd::dbca", "abcd::dbca", 0},                              // bare ipv6 cannot carry a port
		{"example.com", "example.com", 0},                            // no port
		{"example.com:", "example.com", 0},                           // empty port
		{"example.com:99999", "example.com", 0},                      // out of range
		{"example.com:0", "example.com", 0},                          // :0 reports as none
		{"example.com:80a", "example.com", 0},                        // non-numeric
	} {
		v := tc.in
		r := s.ToHost(&v)
		if v != tc.host || r.Port != tc.port {
			t.Errorf("%q => host=%q Port=%d; want host=%q Port=%d",
				tc.in, v, r.Port, tc.host, tc.port)
		}
	}
}

func TestTLDSanitize(t *testing.T) {

	/*
		=== RUN   TestTLDSanitize
		host example.com {true false true 0 8 1234 } example.com com ...
		host xn--exmple-cua.com {true false true 0 15 1234 exämple.com} xn--exmple-cua.com com ...
		host blog.example.com {true false false 5 13 1234 } example.com com ...
		host one.0x4433 {false false false 4 0 0 } 0x4433 one.0x4433 ...
		host co.uk {true false false 0 3 0 } co.uk uk ...
		host test.co.uk {true false false 5 8 0 } co.uk uk ...
		ip   100.10.10.10 {true true false 0 0 1234 } ...
		ip   10.10.10.10 {false true false 0 0 1234 } ...
		ip   abcd::dbca {true true false 0 0 1234 } ...
		--- PASS: TestTLDSanitize (0.00s)
	*/

	var s sanitize.Sanitizer
	t.Log(s.Configure(&sanitize.Options{Iana: true}).Len())
	for _, v := range []string{
		"https://www.example.com:1234/path",           // normal
		"https://www.exämple.com:1234/path",           // idan
		"http://user:pass@blog.example.com:1234/path", // user:pass
		"one.0x4433",                // invalid tld
		"co.uk",                     // public suffix
		"test.co.uk",                // public suffix
		"100.10.10.10:1234",         // ipv4 valid
		"10.10.10.10:1234",          // ipv4 private
		"https://[abcd::dbca]:1234", // ipv6 ported
	} {
		t := time.Now()
		r := s.ToHost(&v)
		if r.IP {
			fmt.Println("ip  ", v, r, time.Since(t))
		} else {
			fmt.Println("host", v, r, v[r.Apex:], v[r.TLD:], time.Since(t))
		}
	}
}

// TestTLDSanitizeCases locks in apex/tld indexing and the unrecognized-tld
// invalidation contract using the iana list only.
func TestTLDSanitizeCases(t *testing.T) {
	var s sanitize.Sanitizer
	s.Configure(&sanitize.Options{Iana: true})
	for _, tc := range []struct {
		in        string
		okay      bool
		apex, tld string
	}{
		{"https://www.example.com/x", true, "example.com", "com"},
		{"blog.example.com", true, "example.com", "com"},
		{"one.0x4433", false, "0x4433", "one.0x4433"}, // unregistered tld invalidates
		{"foo.invalidtldxyz", false, "invalidtldxyz", "foo.invalidtldxyz"},
		{"com", false, "com", "com"}, // bare tld is not a host
	} {
		v := tc.in
		r := s.ToHost(&v)
		if r.Okay != tc.okay || v[r.Apex:] != tc.apex || v[r.TLD:] != tc.tld {
			t.Errorf("%q => %+v apex=%q tld=%q; want Okay=%v apex=%q tld=%q",
				tc.in, r, v[r.Apex:], v[r.TLD:], tc.okay, tc.apex, tc.tld)
		}
	}
}

// TestNonTransitional pins non-transitional (UTS-46) idna processing: deviation
// characters are preserved rather than mapped (ß stays ß, not ss).
func TestNonTransitional(t *testing.T) {
	var s sanitize.Sanitizer
	for _, tc := range []struct{ in, host string }{
		{"faß.de", "xn--fa-hia.de"},       // transitional would give fass.de
		{"straße.de", "xn--strae-oqa.de"}, // transitional would give strasse.de
		{"www.exämple.com", "xn--exmple-cua.com"},
	} {
		v := tc.in
		s.ToHost(&v)
		if v != tc.host {
			t.Errorf("%q => %q; want %q", tc.in, v, tc.host)
		}
	}
}

// TestAllowUnderscore locks the STD3 underscore contract: rejected by default,
// accepted (and left intact) once AllowUnderscore is enabled.
func TestAllowUnderscore(t *testing.T) {
	strict := sanitize.NewSanitizer()
	loose := sanitize.NewSanitizer().AllowUnderscore(true)
	for _, in := range []string{
		"_dmarc.example.com",
		"selector._domainkey.example.com",
		"_acme-challenge.example.com",
	} {
		a := in
		if r := strict.ToHost(&a); r.Okay {
			t.Errorf("strict %q => host=%q Okay=true; want rejected", in, a)
		}
		b := in
		if r := loose.ToHost(&b); !r.Okay || b != in {
			t.Errorf("loose %q => host=%q %+v; want host=%q Okay=true", in, b, r, in)
		}
	}
}

// TestDisplay pins the Display contract: the unicode (U-label) form is returned
// only when the host was actually converted to punycode, so len(Display) > 0
// signals the caller to store it alongside the canonical host.
func TestDisplay(t *testing.T) {
	var s sanitize.Sanitizer
	for _, tc := range []struct {
		in      string
		host    string
		display string
	}{
		{"www.exämple.com", "xn--exmple-cua.com", "exämple.com"}, // converted -> display set
		{"faß.de", "xn--fa-hia.de", "faß.de"},                    // converted -> display set
		{"www.example.com", "example.com", ""},                   // ascii -> no display
		{"xn--exmple-cua.com", "xn--exmple-cua.com", ""},         // already punycode -> no display
		{"100.10.10.10", "100.10.10.10", ""},                     // ip -> no display
	} {
		v := tc.in
		r := s.ToHost(&v)
		if v != tc.host || r.Display != tc.display {
			t.Errorf("%q => host=%q Display=%q; want host=%q Display=%q",
				tc.in, v, r.Display, tc.host, tc.display)
		}
	}
}
