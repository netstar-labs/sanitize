# sanitize — Architecture

Internal design of the `sanitize` package, for maintainers and contributors. For
usage see the [User Guide](user-guide.md).

- [Design goals](#design-goals)
- [Package layout](#package-layout)
- [Types](#types)
- [IDNA & the vendored dependency](#idna--the-vendored-dependency)
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
5. **Zero external dependencies.** Standard library only — the idna
   implementation is vendored under `internal/x` and pinned to Unicode 15, so
   canonicalization is stable across dependency and toolchain upgrades.

## Package layout

```
sanitize/
  sanitize.go        types, constructors, prep, fetch, Configure, ToHost
  sanitize_test.go   print demos + assertion tests
  cmd/               stdin/stdout filter front-end
  build/             cross-compile + deploy script for cmd/ (version-stamped)
  example/           library, httpserver, unixsocket, mcpserver front-ends
  internal/idna/     owned idna policy seam (profiles + ToASCII)
  internal/x/        vendored x/net/idna + x/text deps, pinned to Unicode 15
  docs/              this documentation
  .sanitize/         default TLD cache, non-Linux (created at runtime; git-ignored)
```

The core is a single file. Front-ends are separate `main` packages that import
the library; they carry no sanitization logic of their own.

## Types

```go
type Sanitizer struct {
	tld             map[string]struct{} // loaded suffixes; nil in rectify-only mode
	allowUnderscore bool                // relax STD3 ASCII rules (see AllowUnderscore)
}

type Result struct {
	Okay, IP, WWW bool   // status flags
	Apex, TLD     int    // byte offsets into the rewritten host
	Port          int    // port detected during rectification (0 = none)
	Display       string // unicode (U-label) form, set only on punycode conversion
}

type Options struct {
	Iana         bool
	PublicSuffix bool
	Source       []string
}
```

`tld` is a set (`map[string]struct{}`) — membership only, no value payload. `nil`
`tld` is the sentinel for rectify-only mode. A `Sanitizer` holds **no idna
state** (the profiles are package-level in `internal/idna`), so the zero-value
`Sanitizer` is immediately usable and safe for concurrent use.

Constructors are thin: `NewIANASanitizer` and `NewTLDSanitizer` are
`NewSanitizer().Configure(&Options{...})`. `AllowUnderscore(bool)` is a chainable
modifier that composes with any of them.

## IDNA & the vendored dependency

All punycode conversion goes through [`internal/idna`](../internal/idna), a small
owned seam that keeps the idna policy in one place:

```go
func ToASCII(host string, allowUnderscore bool) (ascii string, ok bool)
```

It holds two immutable, package-level `idna.Profile` values:

- `strict` — `MapForLookup()` + `Transitional(false)`: the default. STD3 ASCII
  rules (letters, digits, hyphen).
- `loose` — adds `StrictDomainName(false)`: relaxes STD3 so underscore (and other
  non-LDH ASCII UTS-46 allows) validate; selected when `allowUnderscore` is set.

Both use **non-transitional** (UTS-46) processing, so deviation characters are
preserved as browsers and registries resolve them (`faß.de` → `xn--fa-hia.de`,
not `fass.de`).

`internal/idna` builds on a **vendored** copy of `golang.org/x/net/idna` and its
`golang.org/x/text` dependencies under [`internal/x`](../internal/x), pruned and
build-tag-stripped to **Unicode 15**. Consequences:

- The module has **zero external dependencies** (`go.mod` requires only the Go
  version).
- Canonicalization is frozen against both dependency upgrades and the Go
  toolchain's Unicode version — the A-label a given input produces will not move.

This matters because `sanitize` stores the A-label as a **durable lookup key**;
if canonicalization drifted between writing a record and reading it back, the
same domain would map to a different key and silently fail to match. See
[`internal/x/README.md`](../internal/x/README.md) for the full rationale and the
(migration-grade) update procedure.

## Request flow: ToHost

`ToHost(url *string) Result` is the only entry point. It:

1. Calls [`prep`](#the-rectification-pipeline-prep), which rewrites `*url` to a
   bare host or IP and returns `(isIP, ipOK, www, port)`.
2. If `isIP`, returns immediately — `Okay` is the IP's public-routability.
3. **Converts IDNA:** captures the pre-conversion string, calls
   `idna.ToASCII(*url, s.allowUnderscore)`. On success it sets `*url` to the
   A-label and, if that differs from the input, records the unicode form in
   `Result.Display`. On failure `*url` is **blanked** (`""`) so it fails
   downstream validation.
4. If no TLD map is loaded (`tld == nil`), applies basic validation:
   `Okay = strings.Contains(host, ".") && len(host) < 254`.
5. Otherwise runs the [TLD/apex walk](#tld--apex-detection) and sets
   `Okay = TLD > 0 && len(host) < 254`.

All mutation happens through the caller's `*string`; `Result` carries only flags,
offsets, the detected port, and the optional display form. No error is ever
returned — invalidity is `Okay == false`.

## The rectification pipeline: prep

`prep(url *string) (isIP, ok, www bool, port int)` is the shared normalizer (one
implementation, used by every mode). It does **structural** rectification only —
the idna conversion lives in `ToHost` so the profile choice and `Display` capture
sit with the sanitizer's state. Steps, in order, all operating in place via
string re-slicing (no allocation):

1. **Scheme** — a leading `//` (protocol-relative) is dropped; otherwise any
   `scheme://` prefix is dropped, case-insensitively, guarded by requiring the
   string's first `/` to be the one inside `://` (so a `://` embedded in a path
   or query is never mistaken for a scheme).
2. **Path** — cut at the first `/` (`IndexByte`).
3. **Credentials** — cut everything up to and including the first `@`.
4. **Port / IPv6 brackets** — only if a `:` is present:
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
5. **IP probe** — `netip.ParseAddr`. On success, return
   `isIP=true, ok=!Unspecified && !Loopback && !Private, www=false` with the
   captured `port`.
6. **Host form** — `ToLower`; trim a trailing `.`; strip a leading `www.` (record
   in `www`). Returns `ok=false`; the caller runs idna conversion and validation.

## IP classification

IP parsing uses `net/netip.ParseAddr`, not `net.ParseIP`. `netip.Addr` is a
value type, so parsing is **allocation-free**, and it exposes the predicates we
need directly (`IsUnspecified`, `IsLoopback`, `IsPrivate`). A public address is
one that is none of those. `netip` is also stricter than `net.ParseIP` (it
rejects non-canonical IPv4 such as leading zeros), which is desirable here.

## TLD & apex detection

Runs only when a TLD map is loaded and the value is not an IP. The map contains
every registered suffix (e.g. `com`, `uk`, `co.uk`). The walk finds the **longest
registered suffix** and the label immediately to its left.

```go
idx := 0
for {
	if _, ok := s.tld[(*url)[idx:]]; ok {   // is the remaining suffix registered?
		result.TLD = idx
		if idx == result.Apex {
			return // whole host is a bare suffix → not a usable host
		}
		break // registered suffix found
	}
	result.Apex = idx                        // remember this label boundary
	next := strings.IndexByte((*url)[idx:], '.')
	if next < 0 {
		break // no more labels; nothing registered
	}
	idx += next + 1                          // advance past the dot
}
result.Okay = result.TLD > 0 && len(*url) < 254
```

The loop tests suffixes from longest (the whole host) to shortest, advancing one
label at a time, and stops at the first hit — so with the Public Suffix list it
matches `co.uk` before it would reach `uk`. `Apex` trails one label behind the
match, so it points at the registrable domain (eTLD+1).

Worked examples (`host[Apex:]` = apex, `host[TLD:]` = suffix):

| Host | Lists | Apex → | TLD → | `Okay` |
| --- | --- | --- | --- | --- |
| `blog.example.com` | IANA | `example.com` | `com` | true |
| `blog.example.co.uk` | PSL | `example.co.uk` | `co.uk` | true |
| `test.co.uk` | IANA (no `co.uk`) | `co.uk` | `uk` | true |
| `test.co.uk` | PSL (`co.uk`) | `test.co.uk` | `co.uk` | true |
| `co.uk` | PSL | `co.uk` (Apex 0) | `co.uk` (TLD 0) | false — bare suffix |
| `one.0x4433` | any | `0x4433` | — (TLD 0) | false — no registered suffix |

The `idx == result.Apex` guard fires only when the entire host is itself a
registered suffix (both are still `0`), correctly rejecting a bare TLD. Otherwise
`idx` always exceeds `Apex` after advancing, so `TLD == 0` unambiguously means
"no registered suffix found" → `Okay = false`.

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
- **Parse** — `bufio.Scanner` per line: trim + lowercase, skip blanks and `#` /
  `//` comments, drop a `*.` Public Suffix wildcard prefix, insert into the set.

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
- **`*.` PSL wildcards dropped; `!` exceptions not modeled.** Simplicity over
  exhaustive public-suffix semantics; sufficient for suffix membership and apex
  location, but not a full PSL algorithm.
- **IDNA profile.** Non-transitional (UTS-46) `MapForLookup`; STD3 by default
  (underscore rejected, `AllowUnderscore` relaxes it); malformed punycode is
  blanked → invalid. The profile does not enforce label length or reject empty
  labels — stricter validation is an opt-in change in `internal/idna`.
- **Vendored, Unicode-15-pinned idna.** Buys zero external dependencies and
  reproducible canonicalization; the cost is carrying a pruned third-party
  snapshot, so an update is a deliberate re-vendor (and canonicalization
  migration), not a `go get -u`.

## Extension points

- **New sources.** Any local path or `http(s)` URL in `Options.Source` is parsed
  with the same line format; no code change needed for additional lists.
- **Stricter/looser IDNA.** Adjust the profiles in `internal/idna` (e.g. add
  `idna.ValidateLabels(true)` / `idna.VerifyDNSLength(true)`), or toggle
  `AllowUnderscore` per sanitizer for STD3 relaxation.
- **Alternate cache location.** Adjust the `resource` selection in `Configure`,
  or pre-seed the cache directory and rely on the 72h reuse.

## Testing

`sanitize_test.go` has two kinds of tests:

- **Print demos** (`TestSanitize`, `TestTLDSanitize`) — illustrative, show output
  and timing.
- **Assertion tests** — the real guard rails:
  - `TestSanitizeCases` / `TestTLDSanitizeCases` — rectification edge cases (IPv6
    bracket unwrap, IPv4-mapped IPv6, private/loopback/unspecified IPs, malformed
    punycode) and apex/TLD indexing plus the unregistered-TLD → `Okay=false`
    contract.
  - `TestNonTransitional` — pins non-transitional processing (`faß.de →
    xn--fa-hia.de`).
  - `TestAllowUnderscore` — the STD3 underscore contract (rejected by default,
    accepted and intact once enabled).
  - `TestDisplay` — the U-label is returned only when a conversion occurred.

Run with `go test ./...`. The TLD assertion tests use the IANA list, so the first
run fetches it (or reads the cached `.sanitize/` copy).
