# Audit findings — netstar-labs/sanitize

**Pass**: A1 adversarial-audit (four report-only auditors + adversarial verify
pass) plus a least-code pass, run 2026-09-29, alongside a dependency bump
(`github.com/netstar-labs/idna` v0.1.0 → v0.1.1, picking up that repo's own
audit fixes). Scope: owned code (`sanitize.go`, `cmd/main.go`, docs).

**Baseline** (`go vet`, `staticcheck`, `gofmt -l`): clean. `deadcode -test
./...` flagged one thing: `sanitize.go:80: unreachable func: IDNAVersion` —
investigated (see below), not a defect.

## Top line

One critical security finding (a real regression of a previously-fixed
vulnerability), four correctness bugs, and a broad set of low-risk
simplify/dedup/doc fixes — all fixed on this branch. Every fix carries a
regression test and was sabotage-verified (revert → confirm the test fails
with an attributable message → restore). The highest-severity finding was
additionally verified by an independent adversarial skeptic against the
actual UTS-46/WHATWG spec text before being fixed, and the full set of fixes
was re-verified by a second independent skeptic before merge.

## CONFIRMED and fixed

| # | Severity | Finding | Commit |
|---|---|---|---|
| 1 | **critical** | `ToASCII`/`ToASCIIErr`/`ToUnicode` didn't re-validate idna's output for delimiters/empty labels — Unicode fullwidth punctuation (e.g. '．','＠','／') folds to a literal ASCII delimiter post-mapping, smuggling an empty label or embedded `@`/`/` into a host reported `Okay=true`. A regression of commit `06eeb92`'s own prior fix for the same bug class. | `b0d1f04` |
| 2 | med | 63-octet per-label DNS limit never enforced (idna's own profile deliberately leaves this to the caller). | `06dd332` |
| 3 | low | `isPublicIP` missed 6 IANA special-purpose ranges (TEST-NET-1/2/3, benchmarking, deprecated 6to4 relay anycast, reserved Class E). | `06dd332` |
| 4 | med | `cmd/main.go` printed an invalid (over-length) host as a "valid registrable domain" because its routing switch checked `r.TLD > 0` without `r.Okay`. | `1de29c1` |
| 5 | low | `cmd/main.go` silently swallowed a file-open error, emitting empty output at exit 0 instead of failing loudly. | `1de29c1` |

Full reproductions, spec citations, and root-cause tracing:
`audit-correctness.md`.

## Applied (low-risk, no public-behavior change)

- **Dedup** (auditor B): `advanceLabel` helper for `suffix()`'s duplicated
  loop-stepping logic; `startOfLastLabel` now delegates to
  `startOfLabelBefore`; `cmd/main.go`'s `route` helper. `audit-dedup.md`.
- **Simplify** (auditor A + least-code, cross-validated): dropped
  `stripURLWhitespace`'s redundant pre-check; replaced `unhex` with
  `strconv.ParseUint`; merged `ToHost`'s two `if ok` blocks; `cmd/main.go`'s
  `envBool` helper (independently found by 3 of 5 auditors).
  `audit-simplify.md`.
- **Docs**: comprehensive drift fix — the worst offender,
  `docs/architecture.md`, described a package that no longer existed (a false
  "zero dependencies" claim, a stale `Types`/`IP classification`/`TLD & apex
  detection` section, and a design-decision bullet flatly contradicted by a
  feature shipped since). Fixed across 5 files. `audit-docs.md`.
- **Documented, not code-changed**: `IDNAVersion` investigated and kept (a
  deliberate skew-detection feature, not dead code — now documented, where it
  previously wasn't); the octal/hex-obfuscated-IP gap in rectify-only mode
  documented as a known limitation (full legacy IPv4 parsing is the sibling
  `normie` package's job, not `sanitize`'s).

Re-validation after every commit: `go build`, `go vet`, `staticcheck`,
`gofmt -l`, `go test -race` all green.

## REFUTED / no action

- Auditors A and B independently surfaced the same marginal duplication
  pattern candidates and both declined to act on the marginal ones (see
  `audit-simplify.md`/`audit-dedup.md` "Considered and NOT recommended"
  sections) — cross-validated conclusions, not acted on.

## Dimension reports

- `audit-simplify.md` — auditor A + least-code
- `audit-dedup.md` — auditor B
- `audit-correctness.md` — auditor C, with the adversarial-skeptic verification
- `audit-docs.md` — auditor D
