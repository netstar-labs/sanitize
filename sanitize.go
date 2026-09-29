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

	"github.com/netstar-labs/idna"
)

// Sanitizer rectifies a raw url to its host form and validates the result. On
// its own it performs rectification and basic format validation only; once one
// or more tld lists are loaded via Configure it additionally reports the tld and
// apex (eTLD+1) index locations and rejects hosts with an unrecognized tld.
//
// The Public Suffix List distinguishes three rule kinds (publicsuffix.org
// algorithm), all honoured here so the public suffix — and therefore the apex
// (eTLD+1) — is identified correctly:
//
//   - normal ("com", "co.uk"): the suffix itself is a public suffix. Held in tld.
//   - wildcard ("*.ck"): every single label under the parent is a public suffix,
//     so "example.ck" is an eTLD and "sub.example.ck" is the apex. The parent
//     ("ck") is held in wildcard.
//   - exception ("!www.ck"): carves a name back out of a wildcard, so "www.ck" is
//     the apex (its eTLD is "ck"). The carved name ("www.ck") is held in except and
//     wins over any wildcard.
type Sanitizer struct {
	tld             map[string]struct{} // normal exact suffixes (IANA tlds + PSL normal rules)
	wildcard        map[string]struct{} // PSL "*.X" parents: any single label under X is a public suffix
	except          map[string]struct{} // PSL "!X" carve-outs: X is the apex, its eTLD is X minus its first label
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
//
// The publicsuffix.org list has two sections: the ICANN suffixes and, below the
// "===BEGIN PRIVATE DOMAINS===" marker, privately-operated suffixes (blogspot.com,
// github.io, s3.amazonaws.com, …). Both load by default, so PublicSuffix mode
// reports foo.blogspot.com's apex as foo.blogspot.com while Iana-only mode reports
// blogspot.com — a deliberate difference. Set ICANNDomainsOnly to stop at the
// marker and treat only ICANN suffixes as public.
type Options struct {
	Iana             bool
	PublicSuffix     bool
	ICANNDomainsOnly bool // stop PSL parsing at the private-domains section
	Source           []string
}

const (
	ianaSource = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	pslSource  = "https://publicsuffix.org/list/public_suffix_list.dat"
)

// IDNAVersion reports the Unicode version the UTS-46 host mapping is pinned to
// (via the shared idna module). An A-label is a lookup key, so a re-vendor can
// change it — stamp this onto every stored/hashed host so a later pin bump is
// detectable as skew rather than a silent miss.
func IDNAVersion() string { return idna.Unicode() }

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

// Len is the number of registered rules loaded across all three PSL rule kinds
// (normal, wildcard, exception); 0 in rectify-only mode.
func (s *Sanitizer) Len() int { return len(s.tld) + len(s.wildcard) + len(s.except) }

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
// For hosts ok is false (the caller applies its own host validation). port is the
// port number removed, or 0 when none was present; invalid port text (non-numeric,
// out of range) is still stripped but reports 0. The leading-www label is not
// touched here — ToHost strips it PSL-aware, after idna, so www.<eTLD> forms (e.g.
// the "!www.ck" exception) are not reduced to a bare public suffix.
func prep(url *string) (isIP, ok bool, port int) {

	// WHATWG input cleaning: strip any tab/LF/CR, trim leading/trailing C0 controls
	// and space, and (for the special schemes this tool targets) treat backslash as
	// a slash. A valid host contains none of these, so this is safe and closes the
	// "http://evil.com\@good.com/" authority-confusion bypass (backslash ends the
	// authority, so the host is evil.com, not good.com).
	*url = stripURLWhitespace(*url)
	*url = strings.ReplaceAll(*url, "\\", "/")

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
	if idx := strings.LastIndexByte(*url, '@'); idx >= 0 {
		*url = (*url)[idx+1:] // strip user:pass — userinfo ends at the LAST '@' (WHATWG)
	}

	// port removal / ipv6 bracket unwrap. Invalid port text (non-numeric, out of
	// range) is deliberately stripped and reported as 0 rather than rejecting the
	// host — a rectifier still yields the host from a URL with a junk port (a
	// documented, tested choice; see prep's doc and TestPort).
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
		return true, isPublicIP(ip), port
	}

	// host form rectification and type assurance
	*url = strings.ToLower(*url)        // standardize case
	*url = strings.TrimRight(*url, ".") // remove ALL trailing dots (root labels)
	if d, dok := percentDecodeHost(*url); dok {
		*url = d // decode %XX host bytes (browser decodes the host before IDNA)
	} else {
		*url = "" // decoded to a forbidden host code point / malformed escape -> reject
	}
	if hasEmptyLabel(*url) {
		*url = "" // empty label (".x", "x..y") is not a valid host
	}
	return false, false, port
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

// stripURLWhitespace removes every tab/LF/CR (WHATWG strips these anywhere in a
// URL) and trims leading/trailing C0 controls and space.
func stripURLWhitespace(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	return strings.TrimFunc(s, func(r rune) bool { return r <= ' ' })
}

// isPublicIP reports whether ip is a usable, publicly-routable unicast address.
// It excludes unspecified, loopback, private (RFC1918 / ULA), link-local unicast
// and multicast (incl. cloud-metadata 169.254.0.0/16 and fe80::/10), all
// multicast, CGNAT (100.64.0.0/10), the remaining IANA special-purpose v4
// ranges (documentation TEST-NET-1/2/3, benchmarking 198.18.0.0/15, the
// deprecated 6to4 relay anycast 192.88.99.0/24), and reserved Class E
// (240.0.0.0/4, which also covers the v4 broadcast address) — so a threat
// tool never classifies e.g. 169.254.169.254 or 224.0.0.1 as a public host.
func isPublicIP(ip netip.Addr) bool {
	if ip.Is4In6() {
		ip = ip.Unmap() // judge ::ffff:a.b.c.d by its v4 identity
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if ip.Is4() {
		b := ip.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 { // CGNAT 100.64.0.0/10
			return false
		}
		if b[0] == 192 && b[1] == 0 && b[2] == 2 { // TEST-NET-1 192.0.2.0/24
			return false
		}
		if b[0] == 198 && b[1] == 51 && b[2] == 100 { // TEST-NET-2 198.51.100.0/24
			return false
		}
		if b[0] == 203 && b[1] == 0 && b[2] == 113 { // TEST-NET-3 203.0.113.0/24
			return false
		}
		if b[0] == 198 && b[1]&0xfe == 18 { // benchmarking 198.18.0.0/15
			return false
		}
		if b[0] == 192 && b[1] == 88 && b[2] == 99 { // deprecated 6to4 relay anycast 192.88.99.0/24
			return false
		}
		if b[0] >= 240 { // reserved (Class E) 240.0.0.0/4, incl. the limited broadcast 255.255.255.255
			return false
		}
	}
	return true
}

// hasEmptyLabel reports whether host has a zero-length DNS label — an empty host,
// a leading dot, or an interior "..". (A trailing dot is trimmed before this.)
// UTS-46 lookup mapping does not reject these, so guard them here.
func hasEmptyLabel(host string) bool {
	return host == "" || host[0] == '.' || strings.Contains(host, "..")
}

// forbiddenHostByte reports whether b is a WHATWG forbidden host code point — a
// control, space, or an authority/URL delimiter. A percent-escape that decodes to
// one of these would smuggle a different host past extraction, so it is rejected.
func forbiddenHostByte(b byte) bool {
	return b <= 0x20 || b == 0x7f || strings.IndexByte("\"#%/:<>?@[\\]^|", b) >= 0
}

// hasForbiddenHostByte reports whether host contains any WHATWG forbidden host
// code point. Used to re-check idna.ToASCII's OUTPUT (guaranteed pure ASCII), not
// just prep's raw input: UTS-46 mapping folds "fullwidth"/"halfwidth" Unicode
// punctuation (U+FF00-FFEF, e.g. '＠'->'@', '／'->'/', '：'->':', '＼'->'\') down to
// its literal ASCII form, so a delimiter that isn't present pre-mapping can appear
// post-mapping. The WHATWG URL spec's own "domain parser" re-checks ToASCII's
// output against this exact forbidden-byte set for exactly this reason (verified
// against the spec text); sanitize must too, or a folded delimiter sails through
// as part of a string reported Okay=true.
func hasForbiddenHostByte(host string) bool {
	for i := 0; i < len(host); i++ {
		if forbiddenHostByte(host[i]) {
			return true
		}
	}
	return false
}

// hasOverlongLabel reports whether any dot-delimited label in host exceeds the
// RFC 1035 63-octet limit. Neither idna profile enforces this (by design, on
// idna's side — see its own doc comment); sanitize adds it here since a
// syntactically-invalid name would otherwise still report Okay=true and feed a
// registrable-domain (apex/TLD) computation as if it were a real one.
func hasOverlongLabel(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if len(label) > 63 {
			return true
		}
	}
	return false
}

// percentDecodeHost decodes %XX escapes in host. ok is false for a malformed
// escape or one that decodes to a forbidden host byte; a host with no '%' is
// returned unchanged.
func percentDecodeHost(host string) (string, bool) {
	if !strings.ContainsRune(host, '%') {
		return host, true
	}
	var b strings.Builder
	b.Grow(len(host))
	for i := 0; i < len(host); i++ {
		if host[i] != '%' {
			b.WriteByte(host[i])
			continue
		}
		if i+2 >= len(host) {
			return "", false // dangling '%'
		}
		n, err := strconv.ParseUint(host[i+1:i+3], 16, 8)
		if err != nil {
			return "", false // malformed %XX
		}
		d := byte(n)
		if forbiddenHostByte(d) {
			return "", false // encoded delimiter/control -> reject
		}
		b.WriteByte(d)
		i += 2
	}
	return b.String(), true
}

// isASCII reports whether s is pure 7-bit ASCII (no idna conversion needed).
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// canonRule normalizes a PSL rule label (after any !/*. prefix has been stripped)
// to the canonical A-label form the host is matched in: ASCII rules are simply
// lowercased; U-label rules (e.g. "公司.cn") are converted to punycode so they match
// the A-label host ToHost produces. An unconvertible rule yields "" and is dropped.
func (s *Sanitizer) canonRule(row string) string {
	if isASCII(row) {
		return strings.ToLower(row)
	}
	if a, ok := idna.ToASCII(row, s.allowUnderscore); ok {
		return a
	}
	return ""
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
		s.wildcard = make(map[string]struct{})
		s.except = make(map[string]struct{})

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
				row := strings.TrimSpace(scanner.Text())
				if opt.ICANNDomainsOnly && strings.Contains(row, "===BEGIN PRIVATE DOMAINS===") {
					break // ICANN-only: stop before the PSL private-domains section
				}
				if len(row) == 0 || strings.HasPrefix(row, "//") || strings.HasPrefix(row, "#") {
					continue
				}
				// Categorize by PSL rule kind, then normalize the remaining label(s)
				// to the A-label (punycode) form so IDN rules match the A-label host
				// ToHost produces. The map keyed for each kind reflects its semantics
				// (see the Sanitizer doc): wildcard stores the parent, exception the
				// carved-out name, everything else the exact suffix.
				dst := s.tld
				switch {
				case row[0] == '!':
					row, dst = row[1:], s.except
				case strings.HasPrefix(row, "*."):
					row, dst = row[2:], s.wildcard
				}
				if row = s.canonRule(row); row != "" {
					dst[row] = struct{}{}
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

	result.IP, result.Okay, result.Port = prep(url)
	if result.IP {
		return
	}

	// Canonicalize idna labels to the punycode A-label, keeping the unicode display
	// (U-label) form so it can be exposed when a conversion actually occurred.
	display := *url
	ascii, ok := idna.ToASCII(*url, s.allowUnderscore)
	if ok && (hasEmptyLabel(ascii) || hasForbiddenHostByte(ascii)) {
		// idna's UTS-46 mapping can fold Unicode punctuation to a literal ASCII
		// delimiter or produce an empty label; re-check its OUTPUT the same way
		// prep already checked the raw input, so a folded "." or "@"/"/" can't
		// sail through disguised as a validated host.
		ok = false
	}
	if !ok {
		*url = "" // unconvertible idna label; fails validation below
	}

	// Strip a leading "www." label, PSL-aware: keep it when www is itself the apex
	// label (the "!www.ck" exception, or www.<eTLD>), so the host is not reduced to a
	// bare public suffix. Rectify-only mode (no list) always strips. The strip is
	// applied to both the canonical (A-label) and display (U-label) forms — "www" is
	// ASCII, so it prefixes both — keeping Display the U-label of the final host.
	if ok {
		if strings.HasPrefix(ascii, "www.") && (s.tld == nil || !s.wwwIsApexLabel(ascii)) {
			ascii, display = ascii[4:], display[4:]
			result.WWW = true
		}
		if ascii != display {
			result.Display = display
		}
		*url = ascii
	}

	// without a tld map fall back to basic host validation
	if s.tld == nil {
		result.Okay = strings.Contains(*url, ".") && len(*url) < 254 && !hasOverlongLabel(*url)
		return
	}

	// detect the public suffix (eTLD) per the PSL algorithm, then localize the apex.
	tld, matched := s.suffix(*url)
	if !matched {
		// unrecognized tld: reject, but still point apex at the rightmost label so the
		// caller can inspect the offending suffix (TLD stays 0 => host[TLD:] is the host).
		result.Apex = startOfLastLabel(*url)
		return
	}
	result.TLD = tld
	if tld == 0 {
		return // the whole host is a public suffix (bare tld); not a usable host
	}
	// apex (eTLD+1) is the public suffix plus the label immediately to its left
	result.Apex = startOfLabelBefore(*url, tld)
	result.Okay = len(*url) < 254 && !hasOverlongLabel(*url)
	return
}

// suffix locates the public suffix (eTLD) of host per the publicsuffix.org
// algorithm over the loaded rule sets, returning the byte index where it begins
// and whether any rule matched. Exception rules win outright; otherwise the
// longest matching normal or wildcard rule prevails. matched is false for an
// unrecognized tld (this validator deliberately does not apply the implicit "*"
// default, so an unknown suffix is rejected rather than treated as a tld).
func (s *Sanitizer) suffix(host string) (tld int, matched bool) {

	// Exception rules (!name) take priority. Walk suffixes longest -> shortest; the
	// first (longest) exact hit wins, and the public suffix is the rule minus its
	// leftmost label (so "!www.ck" makes "www.ck" the apex and "ck" its eTLD).
	if len(s.except) > 0 {
		for idx := 0; ; {
			cand := host[idx:]
			if _, ok := s.except[cand]; ok {
				if d := strings.IndexByte(cand, '.'); d >= 0 {
					return idx + d + 1, true
				}
				return idx, true
			}
			var ok bool
			if idx, ok = advanceLabel(cand, idx); !ok {
				break
			}
		}
	}

	// Longest matching normal or wildcard rule. Walking longest -> shortest, the
	// first hit is the longest: a normal rule makes the candidate itself the public
	// suffix; a wildcard makes the candidate (its parent-minus-one-label being a
	// wildcard base) the public suffix.
	for idx := 0; ; {
		cand := host[idx:]
		if _, ok := s.tld[cand]; ok {
			return idx, true
		}
		if d := strings.IndexByte(cand, '.'); d >= 0 {
			if _, ok := s.wildcard[cand[d+1:]]; ok {
				return idx, true
			}
		}
		var ok bool
		if idx, ok = advanceLabel(cand, idx); !ok {
			break
		}
	}
	return 0, false
}

// advanceLabel returns the absolute index (from idx) of the next label to the
// right within cand (== host[idx:]), and false when cand is host's last label
// (nothing left to advance to). Shared "walk suffix candidates longest-to-
// shortest" stepping logic for suffix's two rule-precedence loops above; it
// carries none of their match semantics (exception-wins-outright vs.
// longest-normal-or-wildcard-wins), which stay independent in each loop.
func advanceLabel(cand string, idx int) (int, bool) {
	next := strings.IndexByte(cand, '.')
	if next < 0 {
		return idx, false
	}
	return idx + next + 1, true
}

// startOfLastLabel returns the byte index of host's rightmost label.
func startOfLastLabel(host string) int {
	return startOfLabelBefore(host, len(host)+1)
}

// startOfLabelBefore returns the byte index of the label immediately to the left
// of the label starting at pos (pos > 0), i.e. the apex label given the public
// suffix start.
func startOfLabelBefore(host string, pos int) int {
	if d := strings.LastIndexByte(host[:pos-1], '.'); d >= 0 {
		return d + 1
	}
	return 0
}

// wwwIsApexLabel reports whether the leading "www" of host is the apex (eTLD+1)
// label itself rather than a subdomain — true only when host is a registrable
// domain whose first label is www (e.g. "www.ck" under the "!www.ck" exception, or
// "www.com"). In that case the www must be kept; otherwise it is a subdomain and
// may be stripped. Callers gate this on a loaded tld list.
func (s *Sanitizer) wwwIsApexLabel(host string) bool {
	tld, matched := s.suffix(host)
	if !matched || tld == 0 { // unknown tld, or host is itself a bare public suffix
		return false
	}
	return startOfLabelBefore(host, tld) == 0
}
