# sanitize

Rectify a raw, untrusted URL to a clean, validated **host** — and locate the
registrable domain (eTLD+1) — in one allocation-light call, with **zero external
dependencies**. It handles canonical hosts, IPv4/IPv6, and IDNA-to-punycode
conversion; load an IANA and/or Public Suffix list and it also validates the TLD
and reports the apex/TLD offsets.

```
raw url ──▶ ToHost(&url)  (rewrites *url in place)
              │
              ├─ prep: strip scheme·//·path·user:pass@·:port ; unwrap [ipv6]
              │
              ├─ netip.ParseAddr ──▶ IP literal ──▶ classify routable? ──▶ Result{IP, Okay, Port}
              │                                     (reject private/loopback/unspecified)
              │
              └─ host ──▶ lowercase · trim "." ──▶ idna.ToASCII (punycode A-label)
                            │                       (Display = U-label if converted)
                            │
                            ├─ tld list loaded ──▶ PSL algorithm (exception ▸ longest wildcard/normal)
                            │                       ──▶ locate eTLD + apex; keep "www." when it is the apex label
                            │                       ──▶ Result{Okay, Apex, TLD, Display, WWW}
                            │
                            └─ rectify-only ──▶ strip leading "www." ; Okay = contains "." && len < 254
```

## Documentation

**Start here**
- [Introduction](docs/introduction.md) — what `sanitize` is, the distinctive Unicode-pinned canonicalization, and the scope you control.
- [Executive Summary](docs/executive-summary.md) — the problem, what it does, and why it matters; leadership-readable.

**Deep dive**
- [Architecture](docs/architecture.md) — subsystems, the `prep`/`ToHost` data flow, the TLD/apex algorithm, and design trade-offs.

**Operations**
- [User Guide](docs/user-guide.md) — install, the three modes, calling `ToHost`, wire/result fields, caching, and day-2 gotchas.

**Examples**
- [Examples README](example/README.md) — runnable library, HTTP, Unix-socket, and MCP front-ends, plus the `cmd/` stdin/stdout filter.

## Synopsis

```go
s := sanitize.NewTLDSanitizer() // iana.org + publicsuffix.org lists

host := "https://www.Example.co.uk:8443/path?q=1"
r := s.ToHost(&host)             // host rewritten in place -> "example.co.uk"
if r.Okay && !r.IP {
	registrable := host[r.Apex:] // "example.co.uk" (eTLD+1)
	suffix := host[r.TLD:]       // "co.uk"        (public suffix)
}
```

A single `Sanitizer` covers three modes, selected at construction —
`NewSanitizer()` (rectify only), `NewIANASanitizer()` (iana.org), and
`NewTLDSanitizer()` (iana.org + publicsuffix.org) — or build one with
`NewSanitizer().Configure(&Options{…})` to load your own local/remote suffix
lists. See the [User Guide](docs/user-guide.md) for details.

## Layout

Root Go files (the library is a single file; front-ends live under `cmd/` and
`example/`):

| File | Purpose |
| --- | --- |
| [`sanitize.go`](sanitize.go) | The entire library: the `Sanitizer`, `Result`, and `Options` types; the constructors; `prep` (in-place URL→host rectifier); `fetch` (atomic TLD-list download); `Configure` (list loading + 72h cache); and `ToHost` (the sole entry point). |
| [`sanitize_test.go`](sanitize_test.go) | Print demos (`TestSanitize`, `TestTLDSanitize`) plus the assertion tests: rectification edge cases, non-transitional IDNA pinning (`faß.de → xn--fa-hia.de`), the `AllowUnderscore` STD3 contract, and the `Display` U-label behavior. |

Supporting directories: [`cmd/`](cmd) (stdin/stdout filter), [`build/`](build)
(version-stamped cross-compile/deploy for `cmd/`), [`example/`](example)
(library/HTTP/Unix-socket/MCP front-ends), [`internal/idna`](internal/idna)
(owned idna policy seam), and [`internal/x`](internal/x) (vendored
`x/net/idna` + `x/text`, pinned to Unicode 15). Runtime TLD lists cache under
`./.sanitize` (or `/var/sanitize` on Linux).
