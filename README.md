```Sanitizer``` is a simple url to host rectifier and basic format validator for domain and ip addresses. It handles canonical hosts, ipv4/6, and idna to punycode conversion. On its own it rectifies and format-validates only; once a tld list is loaded it also reports the index locations within a domain for the tld and apex forms — using the icann and public suffix private tld domains, where the apex form is the effective tld+1 segment — and an unrecognized tld invalidates the domain.

```golang
// Sanitizer rectifies a raw url to its host form and validates the result.
type Sanitizer struct { /* ... */ }

// Result reports sanitizer status. Apex and TLD are byte offsets into the
// rewritten host and are non-zero only when a registered tld was matched.
// Port is the port number removed during rectification, 0 when none was
// present. Display holds the unicode (U-label) form and is set only when the
// host was converted to punycode — len(Display) > 0 signals the caller to
// store it.
type Result struct {
	Okay, IP, WWW bool   // status flags
	Apex, TLD     int    // index locations
	Port          int    // port detected during rectification (0 = none)
	Display       string // unicode form, set only when converted to punycode
}

// ToHost takes the raw url to host; reports status with ip conditional flag.
// When a tld list has been loaded it also sets the tld and apex form index
// locations; an unrecognized tld reports Okay false.
//
//	url := "blog.example.com"
//	r := s.ToHost(&url)
//	if r.Okay && !r.IP { // tld list loaded => registered tld guaranteed
//	 url[r.Apex:] = example.com
//	 url[r.TLD:] = com
//	}
func (s *Sanitizer) ToHost(url *string) (result Result)
```

## Constructors

A single `Sanitizer` covers three modes, selected at construction:

```golang
sanitize.NewSanitizer()      // rectify + validate only (no tld list)
sanitize.NewIANASanitizer()  // + iana.org tld list
sanitize.NewTLDSanitizer()   // + iana.org and publicsuffix.org tld lists
```

For full control, construct with `NewSanitizer()` and load lists yourself. A nil
or empty `Options` loads nothing (rectify only):

```golang
s := sanitize.NewSanitizer()
s.Configure(&sanitize.Options{Iana: true})                       // iana.org
s.Configure(&sanitize.Options{PublicSuffix: true})               // publicsuffix.org
s.Configure(&sanitize.Options{Source: []string{"/var/custom"}})  // custom list
```

iana.org and publicsuffix.org lists are fetched automatically and cached for 72h
under `./.sanitize` (or `/var/sanitize` on linux). `ToHost` only reads the loaded map,
so a constructed `*Sanitizer` is safe to share across goroutines.

## Canonical host and the display form

`ToHost` emits the canonical punycode A-label (e.g. `exämple.com` →
`xn--exmple-cua.com`) using non-transitional (UTS-46) processing — the form you
store, index, and match against. It is not human-readable, and `ToASCII` is not
perfectly reversible, so when a conversion happens the original unicode
(U-label) form is returned in `Result.Display`:

```golang
host := "www.exämple.com"
r := s.ToHost(&host)      // host == "xn--exmple-cua.com"
if r.Display != "" {      // "exämple.com" — keep it for display / publishing
	store(host, r.Display)
}
```

`Display` is empty when nothing was converted (ASCII input, already-punycode
input, or an ip).

## Underscore labels

By default STD3 ASCII rules reject underscore labels, so DNS service names
(`_dmarc`, `_sip._tcp`, `_acme-challenge`) are treated as malformed. Relax that
with `AllowUnderscore` (chainable; also permits other non-LDH ASCII UTS-46
allows — there is no underscore-only idna setting):

```golang
s := sanitize.NewTLDSanitizer().AllowUnderscore(true)
```

## Owned idna

The idna canonicalization policy (non-transitional profiles, STD3 handling,
`ToASCII`) lives in [`internal/idna`](internal/idna), behind one owned seam
rather than spread across the public API. It builds on a **vendored** copy of
`golang.org/x/net/idna` and its `golang.org/x/text` dependencies under
[`internal/x`](internal/x), so the module has **zero external dependencies** and
canonicalization is frozen against both dependency upgrades and the Go
toolchain's Unicode version (the tables are pinned to Unicode 15).

This matters because `sanitize` stores the canonical A-label as a durable lookup
key: if canonicalization drifted between writing a record and reading it back,
the same domain would map to a different key and silently fail to match. See
[`internal/x/README.md`](internal/x/README.md) for the full rationale and the
update procedure (treated as a canonicalization migration, not a routine bump).

## Examples

Runnable examples — library, HTTP server, Unix socket, and MCP server — live
under [`example/`](example); a stdin/stdout filter lives under [`cmd/`](cmd),
with a version-stamped cross-compile/deploy script at
[`build/sanitize`](build/sanitize).

testing example
```golang
	/*
		=== RUN   TestSanitize
		example.com {true false true 0 0 1234 }
		xn--exmple-cua.com {true false true 0 0 1234 exämple.com}
		example.com {true false true 0 0 1234 }
		100.10.10.10 {true true false 0 0 1234 }
		10.10.10.10 {false true false 0 0 1234 }
		abcd::dbca {true true false 0 0 1234 }
		--- PASS: TestSanitize (0.00s)
	*/

	var s sanitize.Sanitizer // zero value: rectify only
	for _, v := range []string{
		"https://www.example.com:1234/path",          // normal
		"https://www.exämple.com:1234/path",          // idna -> punycode, Display set
		"http://user:pass@www.example.com:1234/path", // user:pass
		"100.10.10.10:1234",                          // ipv4 valid
		"10.10.10.10:1234",                           // ipv4 private
		"https://[abcd::dbca]:1234",                  // ipv6 ported
	} {
		t := time.Now()
		r := s.ToHost(&v)
		fmt.Println(v, r, time.Since(t))

	}
```
