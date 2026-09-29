# sanitize — Architecture

Internal design of the `sanitize` package, for maintainers and contributors. For
usage see the [User Guide](user-guide.md).

- [Design goals](#design-goals)
- [Package layout](#package-layout)
- [Types](#types)
- [IDNA & the shared idna dependency](#idna--the-shared-idna-dependency)
- [Request flow: ToHost](#request-flow-tohost)
- [The rectification pipeline: prep](#the-rectification-pipeline-prep)
- [IP classification](#ip-classification)
- [TLD & apex detection](#tld--apex-detection)
- [TLD list subsystem](#tld-list-subsystem)
- [Performance & allocation strategy](#performance--allocation-strategy)
- [Concurrency model](#concurrency-model)
- [Design decisions & trade-offs](#design-decisions--trade-offs)
- [Extension points](#extension-points)
- [Testing](#testing)

## Design goals

1. **One type, three modes.** A single `Sanitizer` covers rectify-only, IANA, and
   IANA+PSL, chosen at construction, plus orthogonal modifiers (`AllowUnderscore`)
   and a `Display` return. No separate types to keep in sync.
2. **Cheap on the hot path.** Rewrite in place, avoid heap allocation for IPs,
   minimize it for domains. Suitable for filtering high-volume streams.
3. **Correct on the hard cases.** IPv6 bracket/port forms, IPv4-mapped IPv6,
   IDNA→punycode, and the public-suffix boundary are handled centrally.
4. **Self-maintaining data, graceful offline.** TLD lists fetch and cache
   themselves; a fetch failure degrades to the last good cache.
5. **One dependency.** Standard library plus the shared, zero-dependency,
   Unicode-15-pinned `github.com/netstar-labs/idna` — so canonicalization is
   stable across dependency and toolchain upgrades, and agrees with sibling
   consumers (`normie`) on the same pin.

## Package layout

```
sanitize/
  sanitize.go          types, constructors, prep, fetch, Configure, ToHost
  sanitize_test.go     print demos + assertion tests
  rectify_test.go      security/edge-case regression suite (F1-F11)
  psl_internal_test.go white-box suffix() precedence tests
  cmd/                 stdin/stdout filter front-end
  build/               cross-compile + deploy script for cmd/ (version-stamped)
  example/             library, httpserver, unixsocket, mcpserver front-ends
  docs/                this documentation
  .sanitize/           default TLD cache, non-Linux (created at runtime; git-ignored)
```

The idna implementation is not vendored in this repo — it's a separate,
first-party module (`github.com/netstar-labs/idna`, itself zero-dependency and
vendoring `golang.org/x/net/idna`/`golang.org/x/text`), imported like any other
dependency. See that repo's own architecture docs for its internals.

The core is a single file. Front-ends are separate `main` packages that import
the library; they carry no sanitization logic of their own.

## Types

```go
type Sanitizer struct {
	tld             map[string]struct{} // normal exact suffixes (IANA tlds + PSL normal rules)
	wildcard        map[string]struct{} // PSL "*.X" parents: any single label under X is a public suffix
	except          map[string]struct{} // PSL "!X" carve-outs: X is the apex, its eTLD is X minus its first label
	allowUnderscore bool
}

type Result struct {
	Okay, IP, WWW bool   // status flags
	Apex, TLD     int    // byte offsets into the rewritten host
	Port          int    // port detected during rectification (0 = none)
	Display       string // unicode (U-label) form, set only on punycode conversion
}

type Options struct {
	Iana             bool
	PublicSuffix     bool
	ICANNDomainsOnly bool // stop PSL parsing at the private-domains section
	Source           []string
}
```

`tld`/`wildcard`/`except` are each a set (`map[string]struct{}`) — membership
only, no value payload — one per Public Suffix List rule kind (see
[TLD & apex detection](#tld--apex-detection)). `nil` `tld` is the sentinel for
rectify-only mode. A `Sanitizer` holds **no idna state** (the profiles are
package-level in the `netstar-labs/idna` module), so the zero-value
`Sanitizer` is immediately usable and safe for concurrent use.

Constructors are thin: `NewIANASanitizer` and `NewTLDSanitizer` are
`NewSanitizer().Configure(&Options{...})`. `AllowUnderscore(bool)` is a chainable
modifier that composes with any of them. `Options.ICANNDomainsOnly` stops PSL
parsing at the `===BEGIN PRIVATE DOMAINS===` marker, so a privately-operated
suffix (`blogspot.com`, `github.io`) is not treated as a public one.

## IDNA & the shared idna dependency

All punycode conversion goes through the shared, first-party
[`github.com/netstar-labs/idna`](https://github.com/netstar-labs/idna) module —
not vendored in this repo, but a separate module built for exactly this reason
(shared by both `sanitize` and its sibling `normie`, so the two never disagree
on the same host's A-label). `sanitize` calls its four exported functions:

```go
func ToASCII(host string, allowUnderscore bool) (ascii string, ok bool)
func ToASCIIErr(host string) (string, error)
func ToUnicode(host string, allowUnderscore bool) (unicode string, ok bool)
func Unicode() string // the pinned Unicode version, e.g. "15.0.0"
```

`sanitize` uses `ToASCII` (via `ToHost`) and `Unicode` (via `IDNAVersion`,
[User Guide](user-guide.md)). Internally, that module holds two immutable,
package-level profiles:

- **strict** — `MapForLookup()` + `Transitional(false)`: the default. STD3
  ASCII rules (letters, digits, hyphen).
- **loose** — adds `StrictDomainName(false)`: relaxes STD3 so underscore (and
  other non-LDH ASCII UTS-46 allows) validate; selected when `allowUnderscore`
  is set.

Both use **non-transitional** (UTS-46) processing, so deviation characters are
preserved as browsers and registries resolve them (`faß.de` → `xn--fa-hia.de`,
not `fass.de`).

The `netstar-labs/idna` module vendors `golang.org/x/net/idna` and its
`golang.org/x/text` dependencies in its own tree, pruned and build-tag-stripped
to **Unicode 15**, so canonicalization is frozen against both dependency
upgrades and the Go toolchain's Unicode version — the A-label a given input
produces will not move except by a deliberate re-vendor there.

This matters because `sanitize` stores the A-label as a **durable lookup key**;
if canonicalization drifted between writing a record and reading it back, the
same domain would map to a different key and silently fail to match. See the
`netstar-labs/idna` repo's own docs for the full rationale and its
(migration-grade) re-vendor procedure, and `IDNAVersion()` above for stamping
the pin onto stored records.

`sanitize` does not trust `ToASCII`'s output blindly, either: UTS-46 mapping
can fold Unicode punctuation (fullwidth/halfwidth forms) down to a literal
ASCII delimiter or produce an empty label, so `ToHost` re-checks the output
for both before accepting it (see [Request flow](#request-flow-tohost)) —
mirroring the equivalent re-check in the WHATWG URL spec's own domain-parsing
algorithm.

## Request flow: ToHost

`ToHost(url *string) Result` is the only entry point. It:

1. Calls [`prep`](#the-rectification-pipeline-prep), which rewrites `*url` to a
   bare host or IP and returns `(isIP, ipOK, port)`.
2. If `isIP`, returns immediately — `Okay` is the IP's public-routability.
3. **Converts IDNA:** captures the pre-conversion string, calls
   `idna.ToASCII(*url, s.allowUnderscore)`. On success it re-checks the
   *output* for an empty label or a WHATWG forbidden host byte (UTS-46 mapping
   can fold Unicode punctuation to one) and fails validation if either fires.
   On success it sets `*url` to the A-label and, if that differs from the
   input, records the unicode form in `Result.Display`. On any failure `*url`
   is **blanked** (`""`) so it fails downstream validation.
4. Strips a leading `www.` label, inside the same `if ok` block — PSL-aware:
   when a TLD map is loaded it runs its own internal suffix lookup
   (`wwwIsApexLabel`) first to check whether `www` is itself the apex label
   (the `!www.ck` exception, or `www.<eTLD>`) before stripping, so those forms
   are not wrongly reduced to a bare public suffix. This is a second,
   redundant suffix-list walk for `www.`-prefixed hosts on top of the walk in
   step 6 below — a known, minor performance cost, not a correctness issue
   (see [Design decisions](#design-decisions--trade-offs)).
5. If no TLD map is loaded (`tld == nil`), applies basic validation:
   `Okay = strings.Contains(host, ".") && len(host) < 254 && !hasOverlongLabel(host)`.
6. Otherwise runs the [TLD/apex walk](#tld--apex-detection) and sets
   `Okay = TLD > 0 && len(host) < 254 && !hasOverlongLabel(host)`.

`hasOverlongLabel` rejects any dot-delimited label over the RFC 1035 63-octet
limit — the idna module's own profile does not enforce this (by design, on
its side), so `sanitize` adds it here since a syntactically-invalid name would
otherwise still report `Okay = true`.

All mutation happens through the caller's `*string`; `Result` carries only flags,
offsets, the detected port, and the optional display form. No error is ever
returned — invalidity is `Okay == false`.

## The rectification pipeline: prep

`prep(url *string) (isIP, ok bool, port int)` is the shared normalizer (one
implementation, used by every mode). It does **structural** rectification only —
the idna conversion lives in `ToHost` so the profile choice and `Display` capture
sit with the sanitizer's state. Steps, in order, all operating in place via
string re-slicing (no allocation):

1. **Whitespace** — `stripURLWhitespace` removes any tab/LF/CR anywhere and
   trims leading/trailing C0 controls and space; then any backslash is
   rewritten to `/` (closes the `http://evil.com\@good.com/` authority-
   confusion bypass for the special schemes this tool targets — backslash
   ends the authority, so the host is `evil.com`, not `good.com`).
2. **Scheme** — a leading `//` (protocol-relative) is dropped; otherwise any
   `scheme://` prefix is dropped, case-insensitively, guarded by requiring the
   string's first `/` to be the one inside `://` (so a `://` embedded in a path
   or query is never mistaken for a scheme).
3. **Path** — cut at the first `/` (`IndexByte`).
4. **Credentials** — cut everything up to and including the **last** `@`
   (WHATWG: userinfo ends at the last `@`, so `a@b@c.com` is host `c.com`, not
   `b@c.com`).
5. **Port / IPv6 brackets** — only if a `:` is present:
   - `[...]:port` → inside the brackets (`Index("]:")`).
   - `[...]` → strip the brackets (`TrimSuffix "]"`).
   - **more than one `:`** (`LastIndexByte != IndexByte`) → a bare IPv6 literal;
     leave intact. This is what distinguishes `::ffff:1.2.3.4` from a ported
     `host:port` and prevents mangling IPv4-mapped IPv6.
   - otherwise (single `:`) → cut at the colon (`host:port` / `ipv4:port`).

   The removed port text is parsed (`strconv.ParseUint`, base 10, 16-bit) into
   `port`; invalid text (non-numeric, empty, out of range) is still stripped
   but reports 0, preserving the historical lenient behavior. Capture happens
   here — before the IP probe — so ported IP forms report their port too.
6. **IP probe** — `netip.ParseAddr`. On success, return
   `isIP=true, ok=isPublicIP(ip)` with the captured `port` (see
   [IP classification](#ip-classification)).
7. **Host form** — `ToLower`; trim **all** trailing dots (root labels), not
   just one; percent-decode (`percentDecodeHost`, rejecting a malformed escape
   or one that decodes to a WHATWG forbidden host byte — a browser decodes the
   host before IDNA, so this must too, or a percent-encoded delimiter would
   smuggle a different host past extraction); then reject an empty label
   (`hasEmptyLabel` — a leading dot, or `".."` anywhere). Returns `ok=false`;
   the caller runs idna conversion and validation. The leading-`www.` strip is
   *not* done here — `ToHost` does it PSL-aware, after idna (see
   [Request flow](#request-flow-tohost)), so `www.<eTLD>` forms are not
   prematurely reduced to a bare public suffix by a normalizer that has no PSL
   list to check against.

## IP classification

IP parsing uses `net/netip.ParseAddr`, not `net.ParseIP`. `netip.Addr` is a
value type, so parsing is **allocation-free**, and it exposes the predicates we
need directly. `isPublicIP` excludes: unspecified, loopback, private (RFC1918 /
ULA), link-local unicast and multicast (incl. cloud-metadata 169.254.0.0/16
and `fe80::/10`), all multicast, CGNAT (100.64.0.0/10), the remaining IANA
special-purpose v4 ranges (documentation TEST-NET-1/2/3, benchmarking
198.18.0.0/15, the deprecated 6to4 relay anycast 192.88.99.0/24), and reserved
Class E (240.0.0.0/4, which also covers the v4 broadcast address) — a
4-in-6-wrapped address (`::ffff:a.b.c.d`) is judged by its unwrapped v4
identity first. `netip` is also stricter than `net.ParseIP` (it rejects
non-canonical IPv4 such as leading zeros), which is desirable here.

## TLD & apex detection

Runs only when a TLD map is loaded and the value is not an IP, via
`suffix(host) (tld int, matched bool)`. The Public Suffix List has three rule
kinds, each held in its own set, checked in precedence order:

```go
// 1. exception rules ("!name") win outright, longest -> shortest.
if len(s.except) > 0 {
	for idx := 0; ; {
		cand := host[idx:]
		if _, ok := s.except[cand]; ok {
			if d := strings.IndexByte(cand, '.'); d >= 0 {
				return idx + d + 1, true // eTLD is the exception minus its first label
			}
			return idx, true
		}
		var ok bool
		if idx, ok = advanceLabel(cand, idx); !ok {
			break
		}
	}
}

// 2. otherwise, the longest matching normal or wildcard rule, longest -> shortest.
for idx := 0; ; {
	cand := host[idx:]
	if _, ok := s.tld[cand]; ok {
		return idx, true
	}
	if d := strings.IndexByte(cand, '.'); d >= 0 {
		if _, ok := s.wildcard[cand[d+1:]]; ok {
			return idx, true // cand's own start is the eTLD under this wildcard
		}
	}
	var ok bool
	if idx, ok = advanceLabel(cand, idx); !ok {
		break
	}
}
return 0, false // unrecognized tld
```

Both loops walk labels longest → shortest (`advanceLabel` steps to the next
label to the right, sharing the iteration mechanics but none of the match
semantics between the two loops), and `ToHost` then sets:

```go
tld, matched := s.suffix(*url)
if !matched {
	result.Apex = startOfLastLabel(*url) // unrecognized tld -> reject, but
	return                                // point Apex at the offending suffix
}
result.TLD = tld
if tld == 0 {
	return // whole host is itself a public suffix -> not a usable host
}
result.Apex = startOfLabelBefore(*url, tld) // the label immediately left of the suffix
result.Okay = len(*url) < 254 && !hasOverlongLabel(*url)
```

Worked examples (`host[Apex:]` = apex, `host[TLD:]` = suffix):

| Host | Lists | Apex → | TLD → | `Okay` |
| --- | --- | --- | --- | --- |
| `blog.example.com` | IANA | `example.com` | `com` | true |
| `blog.example.co.uk` | PSL | `example.co.uk` | `co.uk` | true |
| `test.co.uk` | IANA (no `co.uk`) | `co.uk` | `uk` | true |
| `test.co.uk` | PSL (`co.uk`, a normal rule) | `test.co.uk` | `co.uk` | true |
| `co.uk` | PSL | `co.uk` (Apex 0) | `co.uk` (TLD 0) | false — bare suffix |
| `sub.example.ck` | PSL (`*.ck` wildcard) | whole host | `example.ck` | true |
| `www.ck` | PSL (`!www.ck` exception) | whole host | `ck` | true — kept, not reduced |
| `sub.www.ck` | PSL (`!www.ck` exception) | `www.ck` | `ck` | true — exception applies regardless of deeper subdomains |
| `one.0x4433` | any | `0x4433` | — (TLD 0) | false — no registered suffix |

Exception rules are checked exhaustively before any normal/wildcard rule is
considered — a wildcard base can never shadow an exception carved out of it.
Within each of the two loops, the first (longest) hit wins, so `co.uk` matches
before `uk` ever would.

## TLD list subsystem

`Configure(opt *Options)`:

1. Returns in rectify-only mode for a `nil`/empty `Options` (nothing requested).
2. Resolves the source list into a fresh local slice — `Source` first, then the
   IANA and PSL URLs per the boolean flags. It does **not** mutate the caller's
   `Options` (no append into `opt.Source`).
3. Loads once: if `tld` is already non-nil, it's a no-op.

Loading each source:

- **Remote** (`://` present) → cache path is `<dir>/<basename>` under `./.sanitize`
  (or `/var/sanitize` on Linux, created with `MkdirAll 0755`). It's fetched only
  when missing or older than 72h.
- `fetch(url, target)` uses an `http.Client{Timeout: 30s}`, checks `200`, and
  writes **atomically**: `os.CreateTemp` in the target dir → `io.Copy` → `Close`
  → `os.Rename`. Any error removes the temp file and leaves the previous cache
  untouched. The response body is always closed. Failures are intentionally
  swallowed so a dead remote degrades to the local cache.
- **Parse** — `bufio.Scanner` per line, trimmed. `ICANNDomainsOnly` stops at the
  `===BEGIN PRIVATE DOMAINS===` marker; blank lines and `#`/`//` comments are
  skipped. Each remaining row is categorized by its PSL rule kind — a leading
  `!` routes it (minus the `!`) to `except`; a leading `*.` routes it (minus
  the `*.`) to `wildcard`; everything else goes to `tld` — then `canonRule`
  normalizes the remainder (lowercase, or idna-converted if it's an IDN rule,
  so it matches the A-label form `ToHost` produces) before inserting it into
  the chosen set.

This design means a first run needs network access, but subsequent runs (within
72h, or indefinitely offline) are local and fast, and a partially-downloaded file
can never poison the cache.

## Performance & allocation strategy

Two deliberate choices keep the hot path cheap:

- **In-place rewriting.** `prep` uses `TrimPrefix`/`IndexByte`/re-slicing, all of
  which return sub-slices of the original backing array — no copies. The caller's
  `*string` is the only storage. The `Display` capture is a string-header copy of
  that sub-slice, not a byte copy, so it does not allocate.
- **Value-typed IP parsing.** `netip.ParseAddr` avoids the heap allocation that
  `net.ParseIP` incurs.

Indicative micro-benchmarks (Apple silicon, cached lists):

| Path | Time | Allocations |
| --- | --- | --- |
| IP (`100.10.10.10:1234`) | ~37 ns | **0 B, 0 allocs** |
| Domain, ASCII (`https://www.example.co.uk/path`) | ~210 ns | 48 B, 1 alloc |
| Domain, IDNA (`https://www.exämple.co.uk/path`) | ~365 ns | 136 B, 4 allocs |

The ASCII domain's single allocation is `idna.ToASCII` producing the result
string; ASCII-only, already-lowercase hosts still pay it because the profile
builds a result. A host that actually contains non-ASCII costs more (punycode
encoding). TLD lookup itself is allocation-free (map lookups on sub-slices).

## Concurrency model

After construction/`Configure`, a `Sanitizer` is **immutable**: only `tld` is
read, and the idna profiles are package-level and immutable. `ToHost` writes
solely through the caller's `*string`, which the caller owns. Therefore one
`Sanitizer` serves unlimited concurrent `ToHost` calls — **including the zero
value**, since there is no per-instance state to lazily initialize (the earlier
lazy-`puny` race is gone). The HTTP and Unix-socket examples share a single
instance.

`Configure` and `AllowUnderscore` mutate the sanitizer and are setup steps; run
them before sharing, not concurrently with `ToHost`.

## Design decisions & trade-offs

- **Rewrite in place vs. return a new string.** Chosen for allocation savings;
  the cost is a surprising API (the input is mutated) and offsets that index the
  rewritten value. Callers pass a copy when needed — or read the pre-conversion
  unicode form from `Result.Display` when the host was punycoded.
- **`Okay` gated on a registered TLD.** In TLD-loaded mode an unknown suffix is
  invalid. This is stricter than "looks like a domain" and is the reason the
  Public Suffix list is worth loading.
- **Swallowed fetch errors.** Availability over visibility: a sanitizer keeps
  working from cache when the network or a remote list is down. The trade-off is
  silent staleness — mitigated by the 72h refresh and `Len()`.
- **Relative default cache dir (`./.sanitize`).** Zero-config for CLIs, but
  sensitive to the working directory for long-running servers; `Source` accepts
  absolute paths, and Linux uses the fixed `/var/sanitize`.
- **Full PSL rule-kind support (normal/wildcard/exception).** All three are
  modeled, each in its own set, with exception-wins-outright and
  longest-match precedence (see [TLD & apex detection](#tld--apex-detection))
  — not simplified away, since an unmodeled wildcard or exception would
  misidentify the apex for any suffix using one.
- **IDNA profile.** Non-transitional (UTS-46) `MapForLookup`; STD3 by default
  (underscore rejected, `AllowUnderscore` relaxes it); malformed punycode is
  blanked → invalid. `ToHost` re-checks the ASCII output itself for an empty
  label or a forbidden delimiter (UTS-46 mapping can fold Unicode punctuation
  into one) and enforces the 63-octet per-label limit the idna module's
  profile deliberately leaves to the caller — see
  [Request flow](#request-flow-tohost).
- **Shared, Unicode-15-pinned idna module, not vendored here.** Buys a single
  point of canonicalization shared with `normie`, and reproducible
  canonicalization independent of the Go toolchain; the cost of the pin itself
  (an update is a deliberate re-vendor and migration, not a `go get -u`) is
  carried by that module, not duplicated in this one.

## Extension points

- **New sources.** Any local path or `http(s)` URL in `Options.Source` is parsed
  with the same line format; no code change needed for additional lists.
- **Stricter/looser IDNA.** The profile options live in the shared
  `netstar-labs/idna` module, not here — changing them affects every consumer
  of that module. Within `sanitize` itself, toggle `AllowUnderscore` per
  sanitizer for STD3 relaxation.
- **Alternate cache location.** Adjust the `resource` selection in `Configure`,
  or pre-seed the cache directory and rely on the 72h reuse.

## Testing

Three test files, each with a distinct role:

- **`sanitize_test.go`** — print demos (`TestSanitize`, `TestTLDSanitize`,
  illustrative, show output and timing) plus the core assertion tests:
  `TestSanitizeCases`/`TestTLDSanitizeCases` (rectification edge cases and
  apex/TLD indexing, incl. the unregistered-TLD → `Okay=false` contract),
  `TestNonTransitional` (pins non-transitional processing), `TestAllowUnderscore`
  (the STD3 underscore contract), `TestDisplay` (the U-label return), and
  `TestICANNDomainsOnly` (F8: the private-domains marker).
- **`rectify_test.go`** — the security/edge-case regression suite, findings
  F1-F11: backslash authority-confusion, empty labels (literal, percent-encoded,
  and via post-IDNA-mapping Unicode punctuation), last-`@` userinfo,
  whitespace/percent-decoding, multi-trailing-dot, IP classification specials
  (link-local/multicast/broadcast/CGNAT/4-in-6/the remaining IANA
  special-purpose ranges), and the 63-octet per-label limit.
- **`psl_internal_test.go`** — white-box tests of `suffix()`'s rule precedence
  directly (package-internal, not `sanitize_test`): exception beats wildcard,
  longest match wins among normal/wildcard rules.

Run with `go test ./...`. The TLD assertion tests use the IANA list, so the first
run fetches it (or reads the cached `.sanitize/` copy).
