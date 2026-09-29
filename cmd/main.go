package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/netstar-labs/sanitize"
)

// Version and Revision are stamped by build/sanitize via -ldflags -X;
// an unstamped build (go run / plain go build) reports "dev unknown".
var Version, Revision string

func main() {

	var writer = os.Stdout
	var reader = os.Stdin
	var invalid = os.Stderr

	if len(os.Args) > 1 {
		switch strings.TrimLeft(os.Args[1], "-") {
		case "help":
			if len(Version) == 0 {
				Version = "dev"
			}
			if len(Revision) == 0 {
				Revision = "unknown"
			}
			fmt.Printf("\nsanitize %s %s - validate a list of urls (one per line) from stdin or a file arg\n", Version, Revision)
			fmt.Println("  valid domains -> stdout, rejected inputs -> stderr")
			fmt.Println("  IP=on  retain ip addresses on stdout")
			fmt.Println("  TLD=on retain hosts with an unregistered tld on stdout")
			return
		default:
			f, err := os.Open(os.Args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "sanitize:", err)
				os.Exit(1)
			}
			defer f.Close()
			reader = f
		}
	}

	// env toggles: retain ip addresses and/or unregistered-tld hosts on stdout
	// instead of routing them to stderr as rejects
	keepIP := envBool("IP")
	keepBadTLD := envBool("TLD")

	var host string
	var s = sanitize.NewTLDSanitizer()
	var scanner = bufio.NewScanner(reader)
	for scanner.Scan() {
		host = scanner.Text()
		r := s.ToHost(&host)
		if len(host) == 0 {
			continue // blank line or host that rectified to empty
		}
		route(decide(r, keepIP, keepBadTLD), writer, invalid, host)
	}

}

// decide reports whether host should be routed to stdout (true) or stderr
// (false), given r and the keepIP/keepBadTLD toggles. A tld match alone is not
// enough: r.TLD > 0 with r.Okay == false means the host matched a registered
// tld but failed a later check (e.g. the 254-byte length cap or the 63-byte
// per-label cap) — it must not be reported as a valid registrable domain.
func decide(r sanitize.Result, keepIP, keepBadTLD bool) bool {
	switch {
	case r.IP:
		return keepIP
	case r.TLD > 0 && r.Okay:
		return true // valid registrable domain
	default:
		// no registered tld (unknown tld or bare public suffix), or an
		// otherwise-invalid host that still happened to match a tld
		return keepBadTLD
	}
}

// envBool reports whether the environment variable name is set to one of the
// truthy strings this tool recognizes.
func envBool(name string) bool {
	switch os.Getenv(name) {
	case "on", "true", "1":
		return true
	}
	return false
}

// route writes host to w when ok, else to bad.
func route(ok bool, w, bad *os.File, host string) {
	if ok {
		fmt.Fprintln(w, host)
	} else {
		fmt.Fprintln(bad, host)
	}
}
