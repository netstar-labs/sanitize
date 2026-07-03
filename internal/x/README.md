# Vendored idna dependencies

Pruned copies of `golang.org/x/net/idna` and the `golang.org/x/text` packages it
needs, relocated under this module's `internal/` tree and imported through
[`internal/idna`](../idna). After this vendor the module has **zero external
dependencies** (`go.mod` requires only the Go version), and idna is **pinned to
Unicode 15 independent of the Go toolchain** (see below).

| Vendored path | Upstream | Version |
| --- | --- | --- |
| `internal/x/net/idna` | `golang.org/x/net/idna` | v0.40.0 |
| `internal/x/text/transform` | `golang.org/x/text/transform` | v0.25.0 |
| `internal/x/text/unicode/bidi` | `golang.org/x/text/unicode/bidi` | v0.25.0 |
| `internal/x/text/unicode/norm` | `golang.org/x/text/unicode/norm` | v0.25.0 |
| `internal/x/text/secure/bidirule` | `golang.org/x/text/secure/bidirule` | v0.25.0 |

Only runtime `.go` files were copied; `*_test.go` and the code generators
(`gen*.go`, `maketables.go`, `triegen.go`, which are `//go:build ignore` and
import ungvendored tooling) were excluded. Two edits were then applied:

1. Import paths and package import comments were rewritten
   `golang.org/x/{net,text}/… → github.com/netstar-labs/sanitize/internal/x/{net,text}/…`.
2. The pre-Unicode-15 variants (`tables9…13.0.0.go` in idna/bidi/norm, plus
   `idna9.0.0.go`, `trie12.0.0.go`, `pre_go118.go`, `bidirule9.0.0.go`) were
   deleted and the `//go:build go1.x` selectors stripped from the Unicode-15
   files that remain, so canonicalization no longer varies by toolchain.

The upstream BSD `LICENSE` and `PATENTS` are kept in `internal/x/net` and
`internal/x/text`.

## Why freeze idna this way

`sanitize` stores the canonical punycode A-label as a **durable key** — telemetry
is validated and canonicalized on the way in, persisted, then looked up later by
re-canonicalizing partner queries and published. That contract only holds if a
given input maps to the same A-label *indefinitely*. If canonicalization shifts
between the write and a later read, the same domain canonicalizes to a different
key and silently fails to match the stored record (records split; lookups miss).

idna canonicalization can drift from two directions, and pinning a module version
alone does not stop both:

1. **Dependency upgrades.** A routine `go get -u` of `x/net`/`x/text` can change
   mapping tables or processing. Vendoring makes the code first-party, so it
   changes only when we deliberately re-copy it.

2. **The Go toolchain's Unicode version.** `x/net/idna` selects its Unicode
   tables by *Go build tag*, not by module version — e.g. upstream `tables15.0.0.go`
   is `//go:build go1.21` — so merely upgrading the compiler can swap the active
   Unicode table and change canonicalization with no dependency change at all. To
   remove that coupling entirely, the lower-version table variants were deleted
   and the `//go:build go1.x` selectors stripped from the Unicode-15 files that
   remain. No version selector is left in the vendored stack
   (`grep -r '//go:build go1' internal/x` → nothing), so **every toolchain
   compiles Unicode 15** — the mapping is pinned to Unicode 15 outright, not
   merely for Go ≥ 1.21. (Filenames like `tables15.0.0.go` are kept as-is; they
   just record the Unicode/Go era the code came from.)

Combined with non-transitional (UTS-46) processing, this makes the A-label a
stable, reproducible key for as long as this vendored copy is in place.

## Updating

Because this is a pruned snapshot (not a verbatim mirror), an update is a
re-vendor from scratch, not a diff against upstream. Treat it as a
**canonicalization migration**, not a routine bump:

1. Re-copy runtime files from the chosen `x/net`/`x/text` versions, re-apply the
   import-path rewrite, then re-prune to the target Unicode version (delete the
   lower-version table variants and strip their `//go:build go1.x` selectors).
2. Run the suite. `sanitize`'s tests pin known outputs (e.g. `faß.de →
   xn--fa-hia.de`); any diff means the canonical form of some inputs changed.
3. If outputs changed, re-canonicalize stored keys before shipping — otherwise
   old and new keys will not match.
