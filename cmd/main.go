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
			if err == nil {
				defer f.Close()
				reader = f
			}
		}
	}

	// env toggles: retain ip addresses and/or unregistered-tld hosts on stdout
	// instead of routing them to stderr as rejects
	var keepIP bool
	switch os.Getenv("IP") {
	case "on", "true", "1":
		keepIP = true
	}
	var keepBadTLD bool
	switch os.Getenv("TLD") {
	case "on", "true", "1":
		keepBadTLD = true
	}

	var host string
	var s = sanitize.NewTLDSanitizer()
	var scanner = bufio.NewScanner(reader)
	for scanner.Scan() {
		host = scanner.Text()
		r := s.ToHost(&host)
		if len(host) == 0 {
			continue // blank line or host that rectified to empty
		}
		switch {
		case r.IP:
			// ip address; retained on stdout only when IP mode is on
			if keepIP {
				fmt.Fprintln(writer, host)
			} else {
				fmt.Fprintln(invalid, host)
			}
		case r.TLD > 0:
			fmt.Fprintln(writer, host) // valid registrable domain
		default:
			// no registered tld (unknown tld or bare public suffix); retained
			// on stdout only when TLD mode is on
			if keepBadTLD {
				fmt.Fprintln(writer, host)
			} else {
				fmt.Fprintln(invalid, host)
			}
		}
	}

}
