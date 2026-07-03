# sanitize — Executive Summary

`sanitize` is a small, self-contained Go library (zero external dependencies)
that turns a raw, untrusted URL into a clean, validated **host** — and tells you
what that host is. It answers
three questions in a single call: *is this usable?*, *is it an IP or a domain?*,
and (for domains) *where is the registrable boundary?*

## The problem

Systems that ingest URLs from the wild — crawlers, threat-intelligence feeds, ad
filters, log processors, DNS tooling — repeatedly face the same messy pre-step:
strip the scheme, port, path, and credentials; unwrap IPv6 brackets; fold case
and canonical dots; convert international domains to punycode; reject private or
malformed addresses; and figure out the true registrable domain (the "apex", or
eTLD+1) so that `blog.example.co.uk` collapses to `example.co.uk`. Done ad hoc,
this logic is easy to get subtly wrong (IPv6 edge cases, IDNA, the difference
between `co.uk` and `com`) and is duplicated across services.

`sanitize` consolidates that into one reviewed, tested component.

## What it does

- **Rectifies** a raw URL to a bare host in place — scheme, path, `user:pass`,
  port, and IPv6 brackets removed; lowercased; trailing dot trimmed; `www.`
  stripped; IDNA converted to punycode (the unicode form is returned for display).
- **Classifies** the result as an IPv4/IPv6 literal or a domain, and rejects
  non-routable IPs (private, loopback, unspecified).
- **Validates** domains against the official **IANA** and **Public Suffix**
  lists; an unrecognized TLD is reported as invalid.
- **Locates** the TLD and apex (eTLD+1) as byte offsets into the cleaned host, so
  callers can slice out the registrable domain with zero extra work.

## Characteristics at a glance

| Aspect | Detail |
| --- | --- |
| Language | Go (module `github.com/netstar-labs/sanitize`, Go 1.24+) |
| Dependencies | **zero external** — idna (`x/net/idna` + `x/text`) vendored under `internal/x`, pinned to Unicode 15 |
| Performance | ~0.04 µs per IP, **zero allocations**; ~0.2 µs per domain, 1 allocation |
| TLD data | IANA (~1,400 entries) and/or Public Suffix (~10,000+); auto-fetched, cached 72h |
| Footprint | single type, one method; usable as the zero value |
| Deployment | in-process library, plus example HTTP / Unix-socket / MCP / CLI front-ends |

## Why it matters

- **Correctness by default.** IPv6 bracket forms, IPv4-mapped IPv6, IDNA, and the
  public-suffix boundary are handled centrally and covered by assertion tests, so
  every consumer inherits the same correct behavior instead of re-deriving it.
- **Cheap enough for the hot path.** In-place string rewriting and value-typed IP
  parsing keep it allocation-free for addresses and allocation-light for domains,
  suitable for filtering high-volume streams.
- **Operationally simple.** No database or service to run; the TLD lists refresh
  themselves from authoritative sources and degrade gracefully to a local cache
  when offline.

## Typical uses

Domain/IP allow- and deny-list filtering, feed normalization and de-duplication
(grouping by apex), URL canonicalization before storage or lookup, and input
validation at API boundaries.

## Where to go next

- **[User Guide](user-guide.md)** — install, the three modes, the `ToHost` call,
  reading results, caching, and concurrency.
- **[Architecture](architecture.md)** — the rectification pipeline, the TLD/apex
  algorithm, the caching subsystem, and the performance strategy.
- **[Examples](../example/)** — runnable library, HTTP, Unix-socket, and MCP
  front-ends; a stdin/stdout filter under [`cmd/`](../cmd).
