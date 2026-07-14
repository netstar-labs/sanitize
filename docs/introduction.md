# Meet sanitize — it strips the URL to its host, canonicalizes it, and refuses what it can't vouch for

A URL arriving from the wild is dressed for travel, not for storage. It wears a
scheme, sometimes a port, occasionally a set of credentials; it drags a path and
a query it no longer needs; its case is inconsistent, its brackets optional, its
script possibly foreign. Before any of that can be filtered, grouped, or matched
against a list, it has to be undressed down to the one thing that says where it
points: the host. `sanitize` is that threshold. It takes the raw, untrusted
string, strips away everything that is not the host, reduces what remains to a
single canonical form, and refuses to pass anything it cannot vouch for.

Concretely, `sanitize` is a single Go type — `Sanitizer` — with a single method,
`ToHost(url *string)`, and no external dependencies. Given a pointer to a raw
URL it rewrites the string **in place** to a bare host or IP literal: it drops
the scheme (or a protocol-relative `//`), the path, `user:pass@` credentials, and
the port; unwraps `[ipv6]` brackets while leaving bare IPv6 literals intact;
lowercases; trims the trailing canonical dot; converts internationalized labels to
their punycode A-label (`exämple.com` → `xn--exmple-cua.com`); and strips a leading
`www.` — but PSL-aware, keeping it when `www` is itself the registrable label, so
`www.ck` (carved out by the `!www.ck` exception) is not wrongly reduced to a bare
suffix. It then classifies the result as an IP or a domain — rejecting private,
loopback, and unspecified addresses — and, when a TLD list is loaded, applies the
Public Suffix List algorithm — exception rules first, then the longest matching
wildcard or normal rule — to locate the public suffix (eTLD) and the registrable
domain immediately above it. All of that comes back
in a small `Result`: the `Okay`/`IP`/`WWW` flags, the `Apex` and `TLD` byte
offsets into the rewritten host, the `Port` it removed, and — only when a
conversion actually happened — the human-readable `Display` (U-label) form. No
error is ever returned; invalidity is simply `Okay == false`.

The distinctive part is what happens to that canonical A-label after `sanitize`
produces it. Because the store-then-lookup contract depends on the same input
mapping to the same key indefinitely, `sanitize` vendors its IDNA implementation
(`golang.org/x/net/idna` and its `golang.org/x/text` dependencies) under
`internal/x` and **pins it to Unicode 15 outright** — deleting the lower-version
tables and stripping the `//go:build go1.x` selectors that would otherwise let
the Go toolchain swap the active Unicode table underneath you. Canonicalization
then moves only when a maintainer deliberately re-vendors it, frozen against both
dependency upgrades and compiler upgrades, so a domain canonicalized today still
matches the record it was written to months ago. That stability is what makes the
A-label safe to use as a durable lookup key rather than merely a display
convenience.

What stays in the operator's hands is the strictness of the verdict. `sanitize`
runs in one of three modes chosen at construction — rectify-only (no network, no
TLD list), IANA, or IANA + Public Suffix — and `Configure` accepts arbitrary
local or remote suffix lists on top of those; `AllowUnderscore` relaxes STD3 for
DNS service labels like `_dmarc`. The lists fetch and cache themselves (72h,
atomic temp-file-and-rename writes) and degrade to the last good cache when the
network is down, favoring availability over strict freshness. Public Suffix
handling is a **full PSL engine** for all three rule kinds — normal (`co.uk`),
`*.` wildcard (`*.ck` makes `example.ck` an eTLD and `sub.example.ck` the apex),
and `!` exception (`!www.ck` carves `www.ck` back out as registrable) — following
the publicsuffix.org algorithm (exceptions win, else the longest wildcard-or-normal
rule), with IDN rules normalized to their A-label at load so they match the
converted host. The honest limits are worth stating plainly: `ToHost` mutates the
string you hand it (pass a copy if you still need the original); the default cache
directory is relative (`./.sanitize`, or `/var/sanitize` on Linux), so a
long-running server's working directory matters; and it *locates* the public
suffix and registrable domain rather than resolving or validating — in rectify-only
mode (no list) it strips `www.` unconditionally, since there is no suffix data to
consult.

---

Hand it a raw, travel-dressed URL; get back a bare canonical host — stable enough
to store as a key, not just to show. How strict the verdict is, and which
suffixes count, stays yours to set.

## Read next

- **[Executive Summary](executive-summary.md)** — what it is and why, leadership-readable.
- **[Architecture](architecture.md)** — the rectification pipeline, the TLD/apex walk, and the design trade-offs.
- **[User Guide](user-guide.md)** — install, the three modes, calling `ToHost`, and day-2 operations.
- **[Examples](../example/README.md)** — runnable library, HTTP, Unix-socket, and MCP front-ends.
