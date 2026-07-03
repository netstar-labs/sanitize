# sanitize — User Guide

A practical guide to using the `sanitize` package: installing it, picking a mode,
calling `ToHost`, and reading the result.

- [Install](#install)
- [Quick start](#quick-start)
- [Choosing a mode](#choosing-a-mode)
- [Custom TLD lists (Configure)](#custom-tld-lists-configure)
- [Underscore labels (AllowUnderscore)](#underscore-labels-allowunderscore)
- [Calling ToHost](#calling-tohost)
- [Reading the result](#reading-the-result)
- [The display form](#the-display-form)
- [What rectification does](#what-rectification-does)
- [The TLD list cache](#the-tld-list-cache)
- [Concurrency](#concurrency)
- [Recipes](#recipes)
- [Gotchas & troubleshooting](#gotchas--troubleshooting)

## Install

```sh
go get github.com/netstar-labs/sanitize
```

Requires Go 1.24+. The module has **no external dependencies** — the idna
implementation (`golang.org/x/net/idna` and its `golang.org/x/text` deps) is
vendored under [`internal/x`](../internal/x) and pinned to Unicode 15, so
canonicalization is stable across dependency and toolchain upgrades.

## Quick start

```go
package main

import (
	"fmt"

	"github.com/netstar-labs/sanitize"
)

func main() {
	s := sanitize.NewTLDSanitizer() // IANA + Public Suffix lists

	host := "https://www.Example.co.uk:8443/path?q=1"
	r := s.ToHost(&host) // host is rewritten in place

	fmt.Println(host)     // example.co.uk
	fmt.Println(r.Okay)   // true
	fmt.Println(r.WWW)    // true  (a leading www. was stripped)
	if r.Okay && !r.IP {
		fmt.Println(host[r.Apex:]) // example.co.uk  (registrable domain / eTLD+1)
		fmt.Println(host[r.TLD:])  // co.uk          (public suffix)
	}
}
```

`ToHost` takes a `*string` and **rewrites it in place** to the bare host. Pass a
copy if you still need the original (see [Gotchas](#gotchas--troubleshooting)).

## Choosing a mode

There is a single `Sanitizer` type with three modes, selected at construction:

| Constructor | TLD lists | `ToHost` behavior |
| --- | --- | --- |
| `NewSanitizer()` | none | rectify + basic validation only; `Apex`/`TLD` stay `0` |
| `NewIANASanitizer()` | iana.org | also validates the TLD and locates apex/TLD |
| `NewTLDSanitizer()` | iana.org + publicsuffix.org | as above, plus multi-label suffixes like `co.uk` |

Rule of thumb:

- **Just need a clean host string / IP check?** `NewSanitizer()` — no network, no
  cache, fastest.
- **Need to validate that the TLD is real and find the registrable domain?**
  `NewTLDSanitizer()` — the Public Suffix list is what makes `example.co.uk` (not
  `co.uk`) come out as the apex.
- **Want ICANN TLDs only, without private/multi-label suffixes?**
  `NewIANASanitizer()`.

The zero value works too and behaves like `NewSanitizer()` — it holds no
per-instance state, so it is usable and safe to share immediately:

```go
var s sanitize.Sanitizer
r := s.ToHost(&host)
```

## Custom TLD lists (Configure)

For full control, construct with `NewSanitizer()` and load lists yourself with
`Configure`. `Options` selects the sources:

```go
type Options struct {
	Iana         bool     // pull https://data.iana.org/TLD/tlds-alpha-by-domain.txt
	PublicSuffix bool     // pull https://publicsuffix.org/list/public_suffix_list.dat
	Source       []string // extra local paths and/or http(s) URLs
}
```

```go
s := sanitize.NewSanitizer()
s.Configure(&sanitize.Options{Iana: true})                          // IANA only
s.Configure(&sanitize.Options{PublicSuffix: true})                  // PSL only
s.Configure(&sanitize.Options{Source: []string{"/etc/my-tlds.txt"}})// custom file
s.Configure(&sanitize.Options{Iana: true, Source: []string{
	"https://example.internal/extra-tlds.txt",
}})
```

Notes:

- A `nil` or empty `Options` loads nothing and leaves the sanitizer in
  rectify-only mode.
- The TLD set is loaded **once**; a second `Configure` on an already-loaded
  sanitizer is a no-op. Build a fresh `Sanitizer` to reload.
- `Configure` returns the receiver, so it chains: `NewSanitizer().Configure(opt)`.
- It does **not** mutate the `Options` you pass (sources are resolved into a
  private slice).
- List files are parsed one entry per line; blank lines and `#` / `//` comments
  are skipped, entries are lowercased, and Public Suffix wildcard (`*.`) prefixes
  are dropped.
- `Len()` reports how many TLD entries are loaded.

## Underscore labels (AllowUnderscore)

By default the idna profile enforces STD3 ASCII rules (letters, digits, hyphen),
so underscore labels are treated as malformed and blanked (`Okay == false`). That
rejects DNS service names such as `_dmarc`, `_sip._tcp`, and `_acme-challenge`. If
your inputs include those, relax the rule with `AllowUnderscore` (chainable):

```go
s := sanitize.NewTLDSanitizer().AllowUnderscore(true)
h := "_dmarc.example.com"
r := s.ToHost(&h) // h == "_dmarc.example.com", r.Okay == true
```

Note: this relaxes STD3 broadly (it also permits other non-LDH ASCII that UTS-46
allows) — there is no underscore-only idna setting.

## Calling ToHost

```go
func (s *Sanitizer) ToHost(url *string) (result Result)
```

- Accepts a raw URL or bare host via pointer and rewrites it in place to the
  cleaned host (or IP literal).
- Returns a `Result` describing what was found.
- Never returns an error — malformed input is reported via `Okay == false`.

## Reading the result

```go
type Result struct {
	Okay, IP, WWW bool   // status flags
	Apex, TLD     int    // index locations
	Port          int    // port detected during rectification (0 = none)
	Display       string // unicode form, set only when converted to punycode
}
```

| Field | Meaning |
| --- | --- |
| `Okay` | the host/IP is well-formed and usable (see rules below) |
| `IP` | the value is an IP literal, not a domain |
| `WWW` | a leading `www.` label was stripped during rectification |
| `Apex` | byte offset of the registrable domain (eTLD+1) in the rewritten host |
| `TLD` | byte offset of the TLD / public suffix in the rewritten host |
| `Port` | port number removed during rectification (`example.com:8443` → `8443`); `0` when none was present |
| `Display` | the unicode (U-label) form, set **only** when the host was converted to punycode (see [The display form](#the-display-form)) |

`Port` is reported for host, IPv4, and bracketed IPv6 forms alike. Only a valid
port (all digits, 1–65535) is reported: invalid port text (`:notaport`,
`:99999`, a bare trailing `:`) is still stripped from the host but reports `0`,
and an explicit `:0` is indistinguishable from no port. A bare IPv6 literal
without brackets (`abcd::dcba`) can never carry a port.

**What `Okay` means:**

- **IP** (`IP == true`): `Okay` is true only for a routable public address —
  private (RFC 1918 / ULA), loopback, and unspecified addresses are `false`.
- **Domain, rectify-only mode:** `Okay` is true when the host contains a `.` and
  is under 254 bytes.
- **Domain, TLD-loaded mode:** `Okay` is true only when a **registered TLD was
  matched** (`TLD > 0`). An unknown TLD (`one.0x4433`) or a bare public suffix
  (`co.uk` itself) is `false`.

**Slicing apex and TLD** (only meaningful when `Okay && !IP` in a TLD-loaded
sanitizer, where `TLD > 0` is then guaranteed):

```go
r := s.ToHost(&host)     // host now e.g. "blog.example.co.uk"
if r.Okay && !r.IP {
	registrable := host[r.Apex:] // "example.co.uk"
	suffix := host[r.TLD:]       // "co.uk"
}
```

Both offsets index into the **rewritten** host, not your original input.

## The display form

`ToHost` emits the canonical punycode A-label (`exämple.com` →
`xn--exmple-cua.com`) — the form you store and match against. It is not
human-readable, and the conversion is not perfectly reversible, so when a
conversion happens the original unicode (U-label) form is returned in
`Result.Display`:

```go
host := "www.exämple.com"
r := s.ToHost(&host)  // host == "xn--exmple-cua.com"
if r.Display != "" {  // "exämple.com" — keep it for display / publishing
	store(host, r.Display)
}
```

`Display` is empty when nothing was converted — ASCII input, already-punycode
input, or an IP — so `len(r.Display) > 0` is the signal that there is a
human-readable form worth retaining alongside the canonical host.

Conversion uses non-transitional (UTS-46) processing, so deviation characters are
preserved (`faß.de` → `xn--fa-hia.de`, not `fass.de`).

## What rectification does

Given a raw value, `ToHost` performs, in order:

1. Strip the scheme — any scheme (`http://`, `HTTPS://`, `ftp://`, …),
   case-insensitively — or a protocol-relative `//` prefix (`//example.com/x`).
2. Strip everything from the first `/` (path/query/fragment).
3. Strip `user:pass@` credentials.
4. Remove the port — recording it in `Result.Port` — and unwrap IPv6 brackets:
   - `example.com:8443` → `example.com` (`Port == 8443`)
   - `[2001:db8::1]:443` → `2001:db8::1` (`Port == 443`)
   - `[2001:db8::1]` → `2001:db8::1`
   - bare IPv6 literals (`abcd::dcba`, `::ffff:1.2.3.4`) are kept intact.
5. If it parses as an IP, classify and stop.
6. Otherwise: lowercase, trim a trailing canonical dot, strip a leading `www.`,
   then convert IDNA to punycode (`exämple.com` → `xn--exmple-cua.com`, with the
   unicode form returned in `Display`). A conversion error — malformed punycode
   like `xn--a.com`, or an underscore label unless [`AllowUnderscore`](#underscore-labels-allowunderscore)
   is set — blanks the host so it fails validation.
7. In a TLD-loaded sanitizer, walk the labels to find the registered suffix and
   set `Apex`/`TLD`.

## The TLD list cache

When you use `NewIANASanitizer`, `NewTLDSanitizer`, or `Configure` with remote
sources:

- On first use the lists are **fetched over HTTP** and written to a cache
  directory: `./.sanitize` by default, or `/var/sanitize` on Linux.
- Cached files are reused for **72 hours**, then re-fetched. A fetch failure
  leaves the existing cache intact (downloads are atomic — temp file + rename).
- **Offline with no cache**, the TLD map is empty and every domain reports as
  unregistered (`Okay == false`). Bundle a cache file or pass a local `Source`
  path for hermetic/offline builds.
- Because the default cache directory is relative, the working directory
  matters — see [Gotchas](#gotchas--troubleshooting).

## Concurrency

- A `Sanitizer` is **safe to share across goroutines** — `ToHost` only *reads*
  the loaded TLD map (the idna profiles are package-level and immutable). This
  holds for constructor-built sanitizers **and the zero value**; there is no
  per-instance lazy initialization to race on. The example HTTP and Unix-socket
  servers rely on this: one shared sanitizer, many concurrent requests.
- `Configure` and `AllowUnderscore` are setup steps that mutate the sanitizer;
  call them before sharing, not concurrently with `ToHost`.

## Recipes

**Clean host string only:**

```go
s := sanitize.NewSanitizer()
h := raw
if s.ToHost(&h); strings.Contains(h, ".") { /* h is the cleaned host */ }
```

**Group a feed by registrable domain:**

```go
s := sanitize.NewTLDSanitizer()
byApex := map[string]int{}
for _, raw := range feed {
	h := raw
	if r := s.ToHost(&h); r.Okay && !r.IP {
		byApex[h[r.Apex:]]++
	}
}
```

**Keep only routable public IPs:**

```go
h := raw
if r := s.ToHost(&h); r.IP && r.Okay { /* public address in h */ }
```

Runnable front-ends live under [`example/`](../example/) (library, HTTP server,
Unix socket, MCP server) and [`cmd/`](../cmd) (a stdin/stdout filter). See the
[examples README](../example/README.md).

## Gotchas & troubleshooting

- **`ToHost` mutates your string.** It takes `*string` and rewrites in place. If
  you need the original, pass a copy: `h := raw; s.ToHost(&h)` — or read the
  unicode form from `Result.Display` when it was punycoded.
- **`Apex`/`TLD` index the rewritten host.** Slice the post-`ToHost` string, not
  your original input.
- **Every domain reports `Okay == false`?** The TLD list didn't load — you're
  offline with no cache, or the process can't write the cache directory. Check
  `Len()`; if it's `0`, provide a local `Source` file.
- **Underscore hostnames rejected.** `_dmarc.example.com` and similar are blanked
  by default (STD3). Enable [`AllowUnderscore`](#underscore-labels-allowunderscore).
- **Cache lands in an unexpected place.** The default cache dir is relative
  (`./.sanitize`); a server that changes working directory (or an MCP host that
  sets its own) will create/read it there. Prefer an absolute `Source` path, or
  rely on the fixed `/var/sanitize` on Linux.
- **`Port` is `0` but the input had a port.** Only a valid port (all digits,
  1–65535) is reported; invalid port text is stripped leniently and reports `0`,
  as does an explicit `:0`.
- **`co.uk` is `Okay == false`.** That's correct with the Public Suffix list —
  `co.uk` is a suffix, not a registrable domain. `example.co.uk` is `Okay`.
- **Second `Configure` had no effect.** Lists load once per `Sanitizer`;
  construct a new one to change the loaded set.
