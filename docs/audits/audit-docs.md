# Audit — doc / comment vs code drift (auditor D)

Scope: README.md, docs/*.md, doc comments in sanitize.go/cmd/main.go.

## Root cause

Four feature/fix commits landed after the docs were written and were never
back-ported: `docs/architecture.md`, `docs/user-guide.md`,
`docs/executive-summary.md` were untouched since the initial commit;
`README.md`/`docs/introduction.md` were updated once (2026-07-13) then never
again. Root-caused via `git log --format=%ad` per file against
`git log -- sanitize.go`, not guessed.

## Fixed in this pass

1. **"Zero external dependencies"** — false since commit `6aeb6a3` (Jul 28)
   replaced the vendored `internal/idna`/`internal/x` tree with the shared,
   first-party `github.com/netstar-labs/idna` module (confirmed:
   `go.mod` requires it; neither `internal/idna` nor `internal/x` exists
   anywhere in this repo). Present in README.md, docs/introduction.md,
   docs/executive-summary.md (x2), docs/architecture.md, docs/user-guide.md.
   Fixed everywhere.
2. **`docs/architecture.md` — comprehensively stale**, never touched since the
   initial commit despite 4 subsequent commits to `sanitize.go`:
   - "IDNA & the vendored dependency" section described a package that no
     longer exists.
   - `Types` section's shown `Sanitizer` had only `tld`/`allowUnderscore`;
     missing `wildcard`/`except` (added `ae10a83`). Shown `Options` omitted
     `ICANNDomainsOnly` (added `06eeb92`).
   - "IP classification" undersold the actual protections (missing
     link-local/multicast/CGNAT/broadcast, all added in the SSRF-hardening
     commit `06eeb92`, plus the A1-audit additions).
   - "TLD & apex detection" showed the pre-`ae10a83` single-map algorithm;
     the real one is the three-tier exception/wildcard/normal walk.
   - Design-decision bullet: *"`*.` PSL wildcards dropped; `!` exceptions not
     modeled ... not a full PSL algorithm"* — flatly false; `ae10a83` added
     full three-way support with correct precedence, load-bearing for apex
     correctness.
   Rewritten section by section to match current `sanitize.go` exactly (see
   the docs commit for the full diff).
3. **`docs/user-guide.md`** — "Public Suffix wildcard (`*.`) prefixes are
   dropped" described pre-`ae10a83` behavior (fold into the normal set).
   Actual `Configure` categorizes by rule kind into three separate maps with
   different match semantics. Replaced with an accurate description.
4. **`docs/executive-summary.md`** — dependency row restated the vendored-tree
   claim in the at-a-glance table specifically (the row most likely to be
   copy-pasted into a leadership slide). Fixed.
5. **`README.md` Layout table** — listed only `sanitize.go`/`sanitize_test.go`;
   omitted `rectify_test.go` (added `06eeb92`) and `psl_internal_test.go`
   (added `ae10a83`) — an omission that existed even at the moment the table
   was last declared "PSL-accurate" (`d49c7dd`, same day as `ae10a83`). Both
   added with descriptions.
6. **README ASCII diagram** — omitted the security-hardening steps added in
   `06eeb92` (backslash-to-slash, C0/whitespace stripping, percent-decode +
   reject, empty-label rejection) and the IP-literal box's exclusions
   (link-local/multicast/CGNAT/broadcast). Not a false claim (the full detail
   is correctly in `sanitize.go`'s own doc comments) but bumped from cosmetic
   to outdated given these are the SSRF-relevant protections; appended.

## `IDNAVersion` — investigated, kept, now documented

See `audit-simplify.md` for the least-code angle. This auditor's contribution:
traced `IDNAVersion` to commit `6aeb6a3`'s own message ("so callers can
version-stamp stored A-labels for skew detection") and confirmed it's exactly
the operational guidance the sibling `netstar-labs/idna` repo's README
recommends. `deadcode` flags it unreachable only because nothing in-repo's
*tests* call an exported skew-detection helper — expected for this kind of
API, not evidence of unused code. **Verdict: keep and document, not dead
code.** Added to `docs/user-guide.md` in this pass.

## Confirmed clean (verified, not read-and-assumed)

- Every code example in `README.md`/`docs/user-guide.md`/`example/README.md`
  actually **executed** and matched exactly (README synopsis; the
  `example/library`, `cmd/`, and `httpserver` front-ends run and diffed
  against their documented output — one expected drift: PSL/IANA entry
  *counts* differ from a live network fetch growing since the doc was
  written, not a code/doc bug).
- `docs/introduction.md`/README's PSL and `www.` handling — deliberately
  rewritten (`d49c7dd`) after the wildcard/exception feature landed, verified
  correct against `TestSuffix`.
- go.mod / Go version / module path — clean, matches every doc.
- `sanitize.go`'s own doc comments (checked line-by-line against every
  function body) — clean, and notably more accurate than `docs/*.md`, since
  they're edited in the same commit as the code they describe.

## Unverifiable (reported, not independently confirmed)
- None outstanding after this pass — the one item flagged during the review
  (live PSL/IANA entry counts) is an expected, explained drift in a number
  that's read once from a live network source, not a claim about the code.
