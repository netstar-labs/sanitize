# Audit — simpler pathways (auditor A) + least-code

Scope: owned code — `sanitize.go`, `cmd/main.go`.

## Fixed in this pass

1. **`stripURLWhitespace`'s redundant `ContainsAny` pre-check.** `strings.Map`
   already has a zero-allocation fast path for unchanged input
   (`if b.Cap() == 0 { return s }` in the stdlib source) — the guard just
   duplicated a check `Map` performs internally, at the cost of an extra full
   scan on every call. Removed.
2. **`unhex` replaced with `strconv.ParseUint(_, 16, 8)`.** Identical
   accept/reject semantics (hex digits, error on anything else, including a
   short tail); removes a whole hand-rolled helper function. Independently
   found by both auditor A and the least-code pass.
3. **`ToHost`'s two separate `if ok`-gated blocks merged into one.** Cosmetic
   control-flow tidy-up; behaviorally identical.
4. **`cmd/main.go`'s duplicated env-flag switch → `envBool` helper.**
   Cross-validated independently by auditor A, auditor B, and the least-code
   pass — three of five auditors converged on the same finding. Committed
   alongside the `cmd/main.go` bug fixes (same file, same pass).

All four verified behaviorally identical: full existing suite green
before/after each, no test needed beyond the existing coverage since none
change observable behavior.

## Investigated, not removed: `IDNAVersion` (least-code finding)

The least-code auditor flagged `IDNAVersion()` (a one-line forward to
`idna.Unicode()`) as having zero callers anywhere in this repo, its examples,
or any sibling repo checked — the "wrapper that only forwards, nobody calls
it" pattern. Auditor D (doc drift) investigated further and found it was
added in commit `6aeb6a3` specifically "so callers can version-stamp stored
A-labels for skew detection" — exactly the operational discipline the shared
`netstar-labs/idna` module's own docs recommend ("stamp `Unicode()` onto every
stored A-label / hash so a re-vendor is detectable as skew"). It was
undocumented here, not unused-by-design; **kept, and now documented** in
`docs/user-guide.md`'s new "Stamping the pin" section rather than removed.

## Considered and NOT recommended

- `startOfLastLabel` (one call site, arithmetically identical to
  `strings.LastIndexByte(host, '.') + 1`) — a "helper used once" by the letter
  of the least-code ladder, but its name documents intent next to its twin
  `startOfLabelBefore` (which *is* reused and earns its extraction); inlining
  would trade a self-explanatory name for a subtle off-by-one trick. Not
  removed outright — instead made to *delegate* to `startOfLabelBefore` (see
  `audit-dedup.md`), which keeps the name and removes the duplicated
  arithmetic.
- `isPublicIP`'s CGNAT check as `netip.MustParsePrefix("100.64.0.0/10")`
  instead of manual byte-range arithmetic — arguably more legible, exactly as
  much code either way, current form already test-covered. Not worth the diff
  on its own.
- The two suffix-matching loops in `suffix()` collapsed into one higher-order
  walker taking a match callback — rejected: `suffix()` is a hot path
  (called on every `ToHost`, and again from `wwwIsApexLabel`), and a
  closure-based walker would allocate for no semantic gain while burying the
  exception/wildcard/normal precedence rules — the actual load-bearing logic
  — behind an extra layer of indirection. The narrower `advanceLabel`
  extraction (see `audit-dedup.md`) gets the real duplication without this
  cost.
