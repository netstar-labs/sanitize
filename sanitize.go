package sanitize

import (
	"bufio"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/netstar-labs/sanitize/internal/idna"
)

// Sanitizer rectifies a raw url to its host form and validates the result. On
// its own it performs rectification and basic format validation only; once one
// or more tld lists are loaded via Configure it additionally reports the tld and
// apex (eTLD+1) index locations and rejects hosts with an unrecognized tld.
type Sanitizer struct {
	tld             map[string]struct{}
	allowUnderscore bool
}

// Result reports sanitizer status. Apex and TLD are byte offsets into the
// rewritten host and are non-zero only when a registered tld was matched, which
// requires a tld list to have been loaded (see Configure). Port is the port
// number removed during rectification (host, ipv4, or bracketed ipv6 forms);
// it is 0 when no valid port (1-65535) was present, so an explicit :0 is
// indistinguishable from no port.
type Result struct {
	Okay, IP, WWW bool   // status flags
	Apex, TLD     int    // index locations
	Port          int    // port detected during rectification (0 = none)
	Display       string // unicode (U-label) form, set only when converted to punycode
}

// Options selects which tld lists Configure loads. The boolean flags pull the
// standard iana.org and publicsuffix.org lists; Source adds arbitrary local
// paths or remote (http/https) lists.
type Options struct {
	Iana         bool
	PublicSuffix bool
	Source       []string
}

const (
	ianaSource = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	pslSource  = "https://publicsuffix.org/list/public_suffix_list.dat"
)

// NewSanitizer returns a rectify-only Sanitizer (no tld detection); call
// Configure to load tld lists for full control, or use NewIANASanitizer /
// NewTLDSanitizer for preconfigured variants. The zero value is equivalent and
// ready to use; a Sanitizer holds no per-instance idna state, so a rectify-only
// Sanitizer is safe to share across goroutines immediately.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{}
}

// NewIANASanitizer returns a Sanitizer preconfigured with the iana.org tld list;
// a thin wrapper over NewSanitizer().Configure(&Options{Iana: true}).
func NewIANASanitizer() *Sanitizer {
	return NewSanitizer().Configure(&Options{Iana: true})
}

// NewTLDSanitizer returns a Sanitizer preconfigured with the iana.org and
// publicsuffix.org tld lists; a thin wrapper over
// NewSanitizer().Configure(&Options{Iana: true, PublicSuffix: true}).
func NewTLDSanitizer() *Sanitizer {
	return NewSanitizer().Configure(&Options{Iana: true, PublicSuffix: true})
}

// Len is the number of registered tld items loaded (0 in rectify-only mode).
func (s *Sanitizer) Len() int { return len(s.tld) }

// AllowUnderscore relaxes STD3 ASCII rules so underscore labels (e.g. _dmarc,
// _sip._tcp, _acme-challenge) validate instead of being rejected as malformed.
// Chainable; call before ToHost. Note: relaxing STD3 also permits other non-LDH
// ASCII that UTS-46 allows — there is no underscore-only idna setting.
//
//	s := sanitize.NewTLDSanitizer().AllowUnderscore(true)
func (s *Sanitizer) AllowUnderscore(v bool) *Sanitizer {
	s.allowUnderscore = v
	return s
}

// prep strips the scheme, path, credentials, and port from *url and rectifies it
// to a bare host or ip in place. When isIP is true the value parsed as an ip and
// ok reports whether it is a usable public address, so the caller should stop.
// For hosts ok is false (the caller applies its own host validation) and www
// reports whether a leading www. label was removed. port is the port number
// removed, or 0 when none was present; invalid port text (non-numeric, out of
// range) is still stripped but reports 0.
func prep(url *string) (isIP, ok, www bool, port int) {

	// basic url assurances
	if strings.HasPrefix(*url, "//") { // strip protocol-relative prefix //example.com
		*url = (*url)[2:]
	} else if idx := strings.Index(*url, "://"); idx >= 0 && strings.IndexByte(*url, '/') == idx+1 {
		// the first '/' belongs to "://" so this is a scheme (any scheme, any
		// case), not a "://" embedded later in the path or query
		*url = (*url)[idx+3:] // strip scheme
	}
	if idx := strings.IndexByte(*url, '/'); idx >= 0 {
		*url = (*url)[:idx] // strip page
	}
	if idx := strings.IndexByte(*url, '@'); idx >= 0 {
		*url = (*url)[idx+1:] // strip user:pass
	}

	// port removal / ipv6 bracket unwrap
	if ci := strings.IndexByte(*url, ':'); ci >= 0 { // ported host|ipv4 or ipv6
		switch {
		case strings.HasPrefix(*url, "["):
			if idx := strings.Index(*url, "]:"); idx > 0 {
				port = portNumber((*url)[idx+2:])
				*url = (*url)[1:idx] // ipv6 with port [abcd::dcba]:1234
			} else {
				*url = strings.TrimSuffix((*url)[1:], "]") // unported ipv6 [abcd::dcba]
			}
		case strings.LastIndexByte(*url, ':') != ci:
			// more than one colon: bare ipv6 literal (abcd::dcba, ::ffff:1.2.3.4); keep intact
		default:
			port = portNumber((*url)[ci+1:])
			*url = (*url)[:ci] // ported host or ipv4 example.com:1234 or 100.100.100.100:1234
		}
	}

	// detect ipv4/6 and validate
	if ip, err := netip.ParseAddr(*url); err == nil {
		return true, !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate(), false, port
	}

	// host form rectification and type assurance
	*url = strings.ToLower(*url)         // standardize case
	*url = strings.TrimSuffix(*url, ".") // remove cannonical
	if www = strings.HasPrefix(*url, "www."); www {
		*url = (*url)[4:] // strip www label
	}
	return false, false, www, port
}

// portNumber parses s as a port number, reporting 0 unless s is all digits and
// in range 1-65535.
func portNumber(s string) int {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return int(n)
}

// fetch downloads url to target atomically via a temp file and rename; a partial
// or failed transfer leaves any existing target untouched. Errors are swallowed
// by design so a missing remote list degrades to whatever local cache exists.
func fetch(url, target string) {
	client := http.Client{Timeout: 30 * time.Second}
	r, err := client.Get(url)
	if err != nil {
		return
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return
	}

	tmp, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".tmp-*")
	if err != nil {
		return
	}
	_, cpErr := io.Copy(tmp, r.Body)
	clErr := tmp.Close()
	if cpErr != nil || clErr != nil {
		os.Remove(tmp.Name())
		return
	}
	os.Rename(tmp.Name(), target)
}

// Configure loads the requested tld lists into the Sanitizer. A nil or empty
// Options loads nothing and leaves the Sanitizer in rectify-only mode, giving
// the caller full control over which lists (if any) are used:
//
//	s := sanitize.NewSanitizer()                                // rectify only
//	s.Configure(&sanitize.Options{Iana: true})                  // iana.org
//	s.Configure(&sanitize.Options{PublicSuffix: true})          // publicsuffix.org
//	s.Configure(&sanitize.Options{Source: []string{"/custom"}}) // custom list
//
// iana.org and publicsuffix.org lists are fetched automatically and cached
// (72h); local paths and additional remote lists may be passed via Source. The
// tld set is loaded once; subsequent Configure calls with a loaded set are
// no-ops.
func (s *Sanitizer) Configure(opt *Options) *Sanitizer {

	// nil options => rectify only (full control, no tld loaded)
	if opt == nil {
		return s
	}

	// resolve requested sources without mutating the caller's Options
	var sources []string
	sources = append(sources, opt.Source...)
	if opt.Iana {
		sources = append(sources, ianaSource)
	}
	if opt.PublicSuffix {
		sources = append(sources, pslSource)
	}
	if len(sources) == 0 {
		return s // nothing requested; remain rectify only
	}

	if s.tld == nil {
		// tld are derived from iana.org and publicsuffix.org lists that are used to
		// detect and validate the host tld and for apex localization; 72h updates
		s.tld = make(map[string]struct{})

		var resource = ".sanitize"
		if runtime.GOOS == "linux" {
			resource = "/var/sanitize"
		}
		os.MkdirAll(resource, 0755)

		// remote,local combo resource loader
		for _, item := range sources {
			if strings.Contains(item, "://") {
				// fetch resource when not exist or over 72h aged
				var target = filepath.Join(resource, filepath.Base(item))
				if info, err := os.Stat(target); err != nil || info.ModTime().Before(time.Now().Add(-72*time.Hour)) {
					fetch(item, target)
				}
				item = target
			}

			f, err := os.Open(item)
			if err != nil {
				continue
			}
			var scanner = bufio.NewScanner(f)
			for scanner.Scan() {
				row := strings.ToLower(strings.TrimSpace(scanner.Text()))
				if len(row) == 0 || strings.HasPrefix(row, "//") || strings.HasPrefix(row, "#") {
					continue
				}
				row = strings.TrimPrefix(row, "*.") // ignore psl *. rules for simplicity
				if len(row) > 0 {
					s.tld[row] = struct{}{}
				}
			}
			f.Close()
		}
	}

	return s
}

// ToHost takes the raw url to host; reports status with ip conditional flag.
// When a tld list has been loaded it also sets the tld and apex form index
// locations for domains using the icann.org and publicsuffix.org private tld
// extensions, where the apex form is the effective tld+1 segment; an
// unrecognized tld reports Okay false. In rectify-only mode Apex and TLD stay 0
// and Okay reflects basic host validation only.
//
//	url := "blog.example.com"
//	r := s.ToHost(&url)
//	if r.Okay && !r.IP { // tld list loaded => registered tld guaranteed
//	 url[r.Apex:] = example.com
//	 url[r.TLD:] = com
//	}
//
//	handles canonical hosts as well as ipv4/6 and idna conversion to punycode
func (s *Sanitizer) ToHost(url *string) (result Result) {

	result.IP, result.Okay, result.WWW, result.Port = prep(url)
	if result.IP {
		return
	}

	// canonicalize idna labels to the punycode A-label; expose the unicode
	// display (U-label) form when a conversion actually occurred so the caller
	// knows to store it alongside the canonical host.
	display := *url
	if ascii, ok := idna.ToASCII(*url, s.allowUnderscore); ok {
		if ascii != display {
			result.Display = display
		}
		*url = ascii
	} else {
		*url = "" // unconvertible idna label; fail downstream validation
	}

	// without a tld map fall back to basic host validation
	if s.tld == nil {
		result.Okay = strings.Contains(*url, ".") && len(*url) < 254
		return
	}

	// detect tld and set the apex index
	idx := 0
	for {
		if _, ok := s.tld[(*url)[idx:]]; ok {
			result.TLD = idx
			if idx == result.Apex {
				return // item is a bare tld; not a usable host
			}
			break // tld found
		}
		result.Apex = idx
		next := strings.IndexByte((*url)[idx:], '.')
		if next < 0 {
			break // exhausted, no registered tld found
		}
		idx += next + 1
	}

	// a registered tld sits past the first label (TLD > 0); anything else is invalid
	result.Okay = result.TLD > 0 && len(*url) < 254
	return
}
