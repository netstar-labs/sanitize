# Audit — duplication / dedup (auditor B)

Scope: owned code — `sanitize.go`, `cmd/main.go`.

## Fixed in this pass

1. **`advanceLabel` — the "walk to the next label" step, duplicated verbatim
   in both of `suffix()`'s loops** (exception-rule loop and normal/wildcard
   loop): `IndexByte(cand, '.')`, advance past it or stop. Extracted; carries
   none of the match-precedence logic (exception-wins-outright vs.
   longest-normal-or-wildcard-wins), which stays independent in each loop.
   Confirmed via `TestPublicSuffixRules` (specifically guards against a
   `suffix()` precedence regression) — unchanged after the refactor.
2. **`startOfLastLabel` now delegates to `startOfLabelBefore(host,
   len(host)+1)`** instead of duplicating its `LastIndexByte`+1 logic — the
   two are arithmetically identical (`host[:len(host)+1-1] == host`, and
   slicing to `len(s)` is legal). Both named functions kept (see
   `audit-simplify.md` for why).
3. **`cmd/main.go`'s duplicated stdout/stderr gating → `route` helper.**
   `if ok { fmt.Fprintln(w, host) } else { fmt.Fprintln(bad, host) }`
   appeared twice (IP-mode and TLD-mode gating); extracted, and now also used
   by the fixed `decide()`-based routing (see `audit-correctness.md` finding
   4). Committed alongside the `cmd/main.go` bug fixes.

All three verified behaviorally identical — full suite (incl. PSL precedence
tests) green before/after.

## Considered and NOT recommended

- **`canonRule` (list-load-time idna conversion, once per PSL row) vs. the
  idna call in `ToHost` (every request)** — both call `idna.ToASCII`, but
  `canonRule` has an ASCII fast-path (skip idna entirely) specifically because
  it runs across ~9,000+ PSL rows at load time, whereas `ToHost`
  unconditionally needs both the A-label and U-label back (for `Display`) on
  every request. Merging would either strip the load-time fast path or force
  `ToHost` to compute/discard a U-label it doesn't need on the common case — a
  real behavioral/perf difference disguised as similar-looking code, not
  genuine duplication.
- The three-way port/bracket switch in `prep` — one location with three
  cases, not a repeated pattern elsewhere.
- `fetch`'s temp-file-then-rename — single occurrence, nothing to dedup
  against.
- `strings.ToLower` one-liners (two call sites wrapping a single stdlib call
  each) — a helper would be pure ceremony.
- Three `make(map[string]struct{})` inits in `Configure` — 3 lines for 3
  differently-named fields; a loop over pointers to each would be less
  readable than what's there.
