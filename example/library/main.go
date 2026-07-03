// Command library demonstrates in-process use of the sanitize package.
//
// A single Sanitizer type covers three modes, selected at construction:
//
//	NewSanitizer()       rectify + validate only (no tld list)
//	NewIANASanitizer()   + iana.org tld list
//	NewTLDSanitizer()    + iana.org and publicsuffix.org tld lists
//
//	go run ./example/library
package main

import (
	"fmt"

	"github.com/netstar-labs/sanitize"
)

func main() {

	inputs := []string{
		"https://www.example.com:1234/path",       // scheme, www, port, path
		"https://www.exämple.com/",                // idna -> punycode
		"http://user:pass@blog.example.com/index", // credentials + subdomain
		"co.uk",             // public suffix (not a host)
		"test.co.uk",        // eTLD+1 over a public suffix
		"one.0x4433",        // unknown tld
		"100.10.10.10:1234", // public ipv4
		"10.10.10.10",       // private ipv4
		"[abcd::dbca]:443",  // ported ipv6
	}

	// --- rectify only -------------------------------------------------------
	//
	// NewSanitizer loads no tld list: it rectifies and format-validates only,
	// so Apex/TLD stay 0 and Okay just means "looks like a host". A zero-value
	// Sanitizer behaves the same (it lazily initializes on first use).
	fmt.Println("== NewSanitizer — rectify only ==")
	report(sanitize.NewSanitizer(), inputs)

	// --- iana ---------------------------------------------------------------
	//
	// NewIANASanitizer loads the iana.org list, so a registered tld is required
	// for a domain to be Okay and Apex/TLD are reported. iana does not know
	// public suffixes, so test.co.uk resolves its apex as co.uk (tld=uk).
	fmt.Println("\n== NewIANASanitizer — iana.org ==")
	report(sanitize.NewIANASanitizer(), inputs)

	// --- iana + public suffix ----------------------------------------------
	//
	// NewTLDSanitizer adds the publicsuffix.org list, so co.uk is recognized as
	// a suffix and test.co.uk resolves its apex as test.co.uk (tld=co.uk). On
	// first run the lists are fetched and cached (72h) under ./.sanitize.
	fmt.Println("\n== NewTLDSanitizer — iana.org + publicsuffix.org ==")
	report(sanitize.NewTLDSanitizer(), inputs)
}

// report sanitizes each input and prints the host form and flags.
func report(s *sanitize.Sanitizer, inputs []string) {
	if n := s.Len(); n > 0 {
		fmt.Printf("(%d tld entries)\n", n)
	}
	for _, in := range inputs {
		host := in // copy: ToHost rewrites the string in place
		r := s.ToHost(&host)
		switch {
		case r.IP:
			fmt.Printf("%-42s -> %-22s ip   okay=%v\n", in, host, r.Okay)
		case r.TLD > 0:
			// A registered tld was found. Apex and TLD are byte offsets into
			// the rewritten host, so the apex (eTLD+1) and tld slice out
			// directly.
			fmt.Printf("%-42s -> %-22s host okay=%v apex=%s tld=%s\n",
				in, host, r.Okay, host[r.Apex:], host[r.TLD:])
		default:
			fmt.Printf("%-42s -> %-22s okay=%v\n", in, host, r.Okay)
		}
	}
}
