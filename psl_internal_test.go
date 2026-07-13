package sanitize

import "testing"

// TestSuffix white-box tests the public-suffix algorithm directly against
// hand-built rule sets, isolating it from url rectification. It covers the three
// rule kinds and their precedence — including the "!www.ck" exception that ToHost
// cannot reach (rectification strips the leading "www." label first).
func TestSuffix(t *testing.T) {
	s := &Sanitizer{
		tld:      set("com", "co.uk", "uk", "jp", "ck"),
		wildcard: set("ck", "kawasaki.jp"),
		except:   set("www.ck", "city.kawasaki.jp"),
	}
	for _, tc := range []struct {
		host    string
		tld     int  // byte index of the public suffix (eTLD) start
		matched bool // whether any rule matched
	}{
		{"example.com", 8, true},         // normal: eTLD "com"
		{"a.b.example.com", 12, true},    // normal, deep subdomain
		{"example.co.uk", 8, true},       // normal multi-label: eTLD "co.uk"
		{"co.uk", 0, true},               // bare public suffix
		{"com", 0, true},                 // bare tld
		{"example.ck", 0, true},          // wildcard "*.ck": example.ck is the eTLD
		{"sub.example.ck", 4, true},      // wildcard: eTLD "example.ck"
		{"www.ck", 4, true},              // exception "!www.ck": eTLD "ck" (not "www.ck")
		{"foo.kawasaki.jp", 0, true},     // wildcard "*.kawasaki.jp": foo.kawasaki.jp is the eTLD
		{"a.foo.kawasaki.jp", 2, true},   // wildcard: eTLD "foo.kawasaki.jp"
		{"city.kawasaki.jp", 5, true},    // exception beats wildcard: eTLD "kawasaki.jp"
		{"foo.nonexistenttld", 0, false}, // unknown tld: no rule matches
		{"localhost", 0, false},          // single label, unknown
	} {
		tld, matched := s.suffix(tc.host)
		if tld != tc.tld || matched != tc.matched {
			t.Errorf("suffix(%q) = (%d, %v); want (%d, %v)  [eTLD %q]",
				tc.host, tld, matched, tc.tld, tc.matched, tc.host[tld:])
		}
	}
}

func set(items ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}
