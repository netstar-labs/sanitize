# Audit — correctness + optimization (auditor C)

Scope: owned code — `sanitize.go` (595 lines), `cmd/main.go` (88 lines).

## CONFIRMED and fixed

### 1. [SECURITY, sev:critical] Post-idna.ToASCII output not re-validated for delimiters/empty labels

`ToHost` ran its own delimiter/empty-label validation (`hasEmptyLabel`, the
percent-decode forbidden-byte screen) in `prep()`, **before** `idna.ToASCII`
was called. UTS-46 mapping folds "fullwidth"/"halfwidth" Unicode punctuation
(U+FF00-FFEF, e.g. `．`→`.`, `＠`→`@`, `／`→`/`, `：`→`:`, `＼`→`\`) to its
literal ASCII form — nothing re-checked that OUTPUT, so a fullwidth-punctuation
host sailed through pre-mapping validation clean, then decoded into a real
delimiter/empty label inside a string still reported `Okay=true`.

Root-caused as a **regression** of commit `06eeb92`'s own "F2" fix, which
closed the identical hole for literal-ASCII and percent-encoded input
specifically because "UTS-46 lookup mapping passes them through and produced a
corrupted apex" — the Unicode-mapping vector reopened the same hole the
maintainer already believed was closed.

**Confirmed exploitable**, not theoretical:
- Default (strict) profile, zero config: a fullwidth-dot host → embedded empty
  label (`"a..b.com"`), `Okay=true`, and (TLD-loaded mode) a corrupted
  Apex/TLD (`host[Apex:]` = `"b.com"` — the empty label between `a` and
  `b.com` is invisible unless the string is inspected byte-by-byte).
- `AllowUnderscore(true)` (the loose profile — documented, realistic config
  for `_dmarc`/`_sip._tcp`-style DNS-record consumers): a fullwidth `@` or `/`
  decodes to a literal delimiter embedded in the reported host, `Okay=true`
  (`host[Apex:]` = `"com@evil.com"` or the apex silently walking past a
  literal `/` into what a real path-splitting consumer would read as a
  different segment entirely). Under the default strict profile this case is
  already caught (STD3 rejects the post-mapping non-LDH byte).

**Verified against the actual spec text** (not summarized): Unicode TR46 §4
runs Map before Break, so mapping-then-splitting is standard, not a sanitize
invention — but TR46 §4.1 only requires non-empty labels to pass any check, so
an empty label passes vacuously, unconditionally, confirmed in the vendored
idna code itself (`verifyDNSLength` gates the empty-label rejection, and
neither `sanitize` profile enables it). The WHATWG URL spec's "domain parser"
algorithm re-checks `ToASCII`'s *output* against the exact same
forbidden-domain-code-point set `sanitize` already had (`forbiddenHostByte`) —
unconditionally, regardless of STD3/strict settings. A real browser therefore
*would* catch a post-mapping `@`/`/` and fail the host: this is precisely the
missing check, not "browser-consistent" behavior.

**Fix**: after `idna.ToASCII` succeeds, re-run `hasEmptyLabel` and a new
`hasForbiddenHostByte` scan (the output is guaranteed pure ASCII, so no
percent-decoding is needed at this stage) over the result, and fail validation
if either fires — mirroring the WHATWG algorithm exactly.

**Verdict: CONFIRMED**, independently re-derived and could not be refuted by
an adversarial skeptic (own scratch reproduction, checked the spec text
directly, root-caused via `git blame` against the F2 fix it regresses).
Fixed, regression-tested, sabotage-verified.

### 2. [BUG, sev:med] 63-octet per-label DNS limit never enforced

The idna module's own doc comment explicitly disclaims this ("a caller that
needs those invariants must check them separately"); `sanitize` only checked
total name length. A single 70-byte label (74 bytes total, well under the
254-byte cap) reported `Okay=true`. Fix: `hasOverlongLabel`, checked at both
`Okay` call sites (rectify-only and TLD-loaded mode).

**Verdict: CONFIRMED** (directly reproduced, mechanical/deterministic — no
skeptic needed). Fixed, regression-tested (incl. the 63-byte boundary case),
sabotage-verified.

### 3. [SECURITY/MINOR, sev:low] `isPublicIP` missed several IANA special-purpose ranges

Correctly excluded unspecified/loopback/private/link-local/multicast/CGNAT/
broadcast (incl. 4-in-6-wrapped forms), but not: documentation (TEST-NET-1/2/3,
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), benchmarking (198.18.0.0/15),
the deprecated 6to4 relay anycast (192.88.99.0/24), or reserved Class E
(240.0.0.0/4). None of these route on the real internet, so this is a coverage
gap rather than an exploitable bypass to something reachable — lower severity
than finding 1 — but worth closing given the doc comment already enumerated a
specific exclusion list these were conspicuously absent from.

**Verdict: CONFIRMED** (directly reproduced against all 6 ranges). Fixed
(240.0.0.0/4 also subsumes the prior standalone broadcast special-case,
simplified away), regression-tested, sabotage-verified.

### 4. [BUG, sev:med] `cmd/main.go` ignored `Result.Okay`, only checked `r.TLD > 0`

`TLD` is set in `ToHost` before `Okay` is computed, so an otherwise-invalid
host (e.g. one over the length caps) that still matches a registered tld was
printed to stdout as a "valid registrable domain" by the CLI filter,
contradicting the library's own correctness field. Fix: extracted the routing
switch into a testable `decide()` function; condition is now
`r.TLD > 0 && r.Okay`.

**Verdict: CONFIRMED** (read directly, mechanical). Fixed, regression-tested,
sabotage-verified.

### 5. [BUG, sev:low] `cmd/main.go` silently swallowed a file-open error

A failed `os.Open` on the file argument discarded the error and left `reader`
on `os.Stdin` — a mistyped path in a pipeline/cron invocation would emit empty
output at exit code 0 with no indication anything was wrong. Fix: print to
stderr and `os.Exit(1)`.

**Verdict: CONFIRMED** (read directly). Fixed.

### Scope note: `canonRule` does not carry the new post-output re-check

The fix in finding 1 applies to `ToHost`'s call into `idna.ToASCII` — the path
that processes untrusted, attacker-controlled input. `canonRule` (used only to
canonicalize PSL/IANA rule *labels* at list-load time) also calls
`idna.ToASCII` directly but was deliberately left as-is: its input is the
maintainer-configured TLD list source, not a raw untrusted URL, so it sits
outside the threat model finding 1 addresses. Flagged here for a maintainer's
awareness in case the trust model around PSL-source configuration ever
changes (e.g. `Options.Source` pointed at a third-party-controlled URL) —
not treated as part of this fix.

## Reported, not changed (documented as a known limitation)

### 6. [SECURITY/MINOR] Rectify-only mode: decimal/octal/hex-obfuscated loopback IPs pass as opaque host strings

`0177.0.0.1` and `0x7f.0.0.1` (octal/hex-style IPv4 octets — the classic
decimal/octal-IP SSRF obfuscation technique) fall through to host-form
handling in rectify-only mode and report `Okay=true, IP=false`, purely because
they contain a dot and are short; `net/netip.ParseAddr` deliberately rejects
these forms (confirmed: `ParseAddr("0177.0.0.1")` errors "IPv4 field has octet
with leading zero"), which is correct Go-side behavior but diverges from a
browser's legacy IPv4 host parser, which does resolve these to `127.0.0.1`.

**Not fixed**: implementing full `inet_aton`-style legacy IPv4 parsing is
explicitly the job of the sibling package `normie` ("full inet_aton radix
rules"), not `sanitize` — adding it here would duplicate that functionality
rather than compose with it, and the gap is confined to rectify-only mode
(with any TLD list loaded, the numeric final label fails the TLD match and is
correctly rejected). Left as a known, documented limitation rather than a
sanitize-side fix.

## Clean, verified-correct (traced by hand and via a built-harness run against the real 10,342-rule PSL)

- PSL precedence/apex localization — the highest-risk piece of this file:
  exception-wins-over-wildcard and longest-match-wins both implemented
  correctly (`sub.example.ck` apex = whole host under `*.ck`; `www.ck` kept
  intact under `!www.ck`; `sub.www.ck` still resolves apex `www.ck`).
- Backslash-as-slash authority confusion and last-`@`-wins userinfo stripping
  (already regression-tested as F1/F4; re-confirmed).
- IPv6 bracket/port edge cases, malformed/out-of-range port text.
- Malformed/dangling percent-escapes and delimiter percent-encoding correctly
  rejected; a layered two-byte invalid-UTF-8 case still safely caught
  downstream by idna's own `utf8.ValidString` guard (idna repo, separately
  audited/fixed).
- `CAFÉ.COM` → `xn--caf-dma.com`, `Display=café.com` — correct case-folding +
  A-label/U-label split.
- No panics across ~40 adversarial inputs.
- `rectify_test.go`/`psl_internal_test.go`'s existing F1-F8 suite passes and
  does not cover any of findings 1-5 above (confirmed non-redundant).

## [MINOR/PERF, not fixed] Redundant PSL walk for `www.`-prefixed hosts

`wwwIsApexLabel` does its own `suffix()` call, duplicating the walk `ToHost`
performs again on the (possibly-stripped) host — one extra full suffix-list
walk specifically for `www.`-prefixed hosts. Measured via
`testing.AllocsPerRun`: plain ASCII hosts cost 1 allocation/op end-to-end even
for a full URL input; the README's "allocation-light" claim holds — this is a
CPU-cycle nit, not an allocation problem. Documented in
`docs/architecture.md`'s request-flow section; not fixed in this pass.
