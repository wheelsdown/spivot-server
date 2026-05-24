# AGENTS.md

Spivot Server is the Go backend API service for the Spivot iOS app. The
primary release artifact is a well-labeled, OCI-compliant container image
published from this repo.

Everything below is what you need to contribute code.

## Build & Test

All workflows go through [just](https://just.systems/). Prefer the
project recipes over invoking underlying tools directly; the justfile
handles version injection, race tests, linting, and container validation.

```bash
just build          # Build for the current platform -> dist/
just build-linux    # Build linux/amd64 and linux/arm64 binaries
just container      # Build a local OCI image
just container-archive <version>
                    # Build a multi-arch OCI archive -> dist/release/
just ci             # Full local gate: fmt check + tidy + lint + race tests + container check
just test           # Tests only, always with -race
just lint           # golangci-lint v2
just fmt-check      # gofmt check
```

`just ci` must pass locally before every push. Do not rely on GitHub
Actions to catch what could have been caught locally.

## Code Conventions

- **Go 1.26+** required.
- **Conventional commits**: `feat:`, `fix:`, `docs:`, `refactor:`,
  `test:`, `chore:`.
- **Prefer the standard library**. Add third-party dependencies only when
  they remove real complexity and after the trade-off is understood.
- **Context propagation**: pass the caller's `ctx` through downstream
  calls. Do not use `context.Background()` inside handlers or request
  paths when a caller context is available.
- **HTTP handlers**: set explicit timeouts at the server boundary, keep
  handlers small, and return bounded responses. Shared outbound HTTP
  behavior should live under `internal/platform` once it stops being
  one-off code.
- **Error handling**: handle errors explicitly. Wrap with useful context
  at boundaries. Do not silently drop errors; if a cleanup error is
  intentionally ignored, make that visible in code.
- **String truncation**: never truncate by byte index (`s[:n]`) when the
  string may contain user text. Use rune-aware truncation so UTF-8 stays
  valid.
- **Contract structs**: exported structs that define API-facing,
  persistence-facing, or cross-package contracts need explicit
  serialization tags (`json`, `yaml` when config-facing, `snake_case`
  names, `-` for runtime-only fields).
- **Config defaults**: if configuration is introduced, set defaults in
  code through a clear defaults function rather than hiding behavior in
  struct tags.
- **Tests**: table-driven where possible, and keep riskier behavior under
  focused tests. The project test recipe uses the race detector.
- **Logging**: structured logging via `slog`. INFO tells the operator
  story, DEBUG is for deep troubleshooting, WARN is degraded behavior,
  and ERROR is broken behavior. Include relevant context fields.
- **Documentation**: see the [Documentation](#documentation) section
  below. The short version: GoDoc is a product surface, not commentary,
  and the bar differs for exported (full contract) vs unexported
  (rationale where it earns its place).
- **Provider pattern**: new integrations should sit behind a small
  interface owned by the consuming package, especially when external
  services or vendor APIs are involved.

## Documentation

Treat GoDoc as a primary product surface, not as code commentary. Two
audiences, two bars:

- A reader landing on [pkg.go.dev](https://pkg.go.dev) (or running
  `go doc`) should be able to use a package correctly without opening
  the source.
- A reader navigating the source should understand *why* each piece
  exists in its current form, especially where the obvious naive
  implementation would be wrong.

Documentation is part of the reader-facing interface. A PR that changes
behavior without updating the affected doc comments is incomplete;
reviewers should treat that the same way they treat a PR that changes
a function without updating its tests.

### Exported symbols (full contract)

Every exported package, type, function, method, variable, and constant
gets a doc comment that:

- Starts with the symbol name and reads as a complete sentence.
- States the **inputs** the caller must provide, including validation
  rules, required vs optional fields, and allowed forms.
- States the **outputs**: return semantics, whether returned
  slices/structs are fresh copies vs shared references, which fields
  the caller may mutate.
- States the **error contract**: which errors are returned when, how
  to detect sentinel errors via `errors.Is`, what context is wrapped.
- States the **concurrency** guarantees: which methods are safe under
  concurrent use, where serialization happens.
- States the **side effects**: filesystem mutations, permission
  changes, durability guarantees, observable state changes.
- Cross-references related symbols via Go 1.19+ `[Identifier]` doc
  links so pkg.go.dev produces clickable references.

Package-level documentation in `doc.go` uses Go 1.19+ heading syntax
(`# Heading`) to render a navigable table of contents on pkg.go.dev.
For non-trivial packages, structure with sections such as Architecture,
Security Model, On-disk Layout, Lifecycle, Concurrency, and Future
Evolution. The "what does this package *not* protect against" list is
as important as the "what does it protect" list for security review.

Add runnable `Example*` functions for the primary usage patterns of
non-trivial packages. Examples render on pkg.go.dev and are exercised
by `go test`, so they can't bit-rot silently. Use `// Output:` comments
to validate the deterministic portions of stdout. See
`internal/platform/identity/example_test.go` for the established
pattern.

### Unexported symbols (rationale, not ceremony)

The reader of an unexported function is always reading the source, with
the body in front of them. Document the *why*, not the *what*. The
test for whether a comment is doing real work:

> If a contributor were to delete this unexported symbol in a PR,
> would the surrounding code make clear why that's wrong?

If yes, a short comment or none is fine. If no, the comment is doing
real work and must exist.

Rich docs are warranted on unexported symbols when:

- They encode subtle invariants the body doesn't show (ordering,
  concurrency assumptions, partial-failure semantics).
- They exist because of a specific bug or edge case (the obvious naive
  implementation would be wrong — for example,
  `internal/platform/identity.randomSerial`'s rejection loop).
- They encode a security or durability policy (validation alphabets,
  atomic-write sequences, hash algorithm choices).
- They sit at an internal layer boundary even if private (the only
  place that knows the correct sequence of primitive operations).

Skip ceremonial docs on:

- One-liners where the signature carries the meaning.
- Pure formatting or conversion helpers and simple field accessors.
- Test helpers.
- Code that's purely organizational with no novel logic.

The discipline is not "write ten lines on every private function" but
"if the answer to *why is this here?* isn't obvious from the
surrounding code, write the missing context."

## Container & Release Engineering

- The production artifact is the container image, not a macOS package or
  local binary archive.
- Keep the Dockerfile OCI-focused: non-root runtime user, useful
  `org.opencontainers.image.*` labels, healthcheck, version injection,
  and a minimal runtime filesystem.
- `just container-check` should prove more than "the image builds": it
  validates required OCI labels, runs `spivot-server version`, starts the
  container, and waits for the healthcheck to become healthy.
- `just container-archive <version>` uses Docker Buildx to build a
  multi-architecture OCI archive for `linux/amd64` and `linux/arm64`,
  writes Buildx metadata, and creates a SHA-256 checksum under
  `dist/release/`. It manages a `docker-container` Buildx builder named
  `spivot-release` by default; override with `SPIVOT_BUILDX_BUILDER`.
- Release tags are semver tags with a leading `v`, such as `v0.1.0` or
  `v0.1.0-rc.1`.
- GitHub Actions publishes the multi-arch GHCR image on release tags. Do
  not add macOS signing, notarization, or installer-package workflow here.
- `just release-github <version> [kind]` runs the full local gate, builds
  the multi-arch OCI archive, cuts the GitHub release, uploads the
  archive/checksum/metadata as release assets, and leaves GHCR publication
  to the tag-triggered workflow.
- Build-time version data is injected with `ldflags`; do not hardcode
  release versions in Go source.

## Architecture Notes

- The command entry point under `cmd/spivot-server` should stay thin:
  parse flags, construct OS-level dependencies, then delegate to internal
  packages.
- HTTP API code lives under `internal/server/api`.
- Process lifecycle wiring lives under `internal/app`.
- Cross-cutting helpers such as build metadata and logging live under
  `internal/platform`.
- Keep package boundaries honest. Avoid shared "utility" packages until
  two real call sites prove the abstraction belongs there.

## Security

- Do not log secrets, bearer tokens, session tokens, or raw credentials.
- Keep request/response logging bounded and deliberate.
- Containers should run as a non-root user.
- Network listeners should be explicit about address and port defaults.
- If persistent storage or auth is added, document the operator-visible
  defaults and failure modes in the same PR.

## Pull Requests

- Run `just ci` locally before pushing.
- Keep PRs focused: one logical change per PR.
- Use conventional commit format for PR titles and commits.
- Reference issues with `Refs #NNN` or `Closes #NNN` when applicable.
- Update docs in the same PR when behavior changes. GoDoc counts as
  documentation: exported symbols, package comments, and type
  definitions are part of the reader-facing interface.

## Common Review Feedback

- **Context propagation** - do not detach request work from cancellation
  unless the lifecycle is intentionally backgrounded and documented.
- **Race conditions** - shared state needs synchronization, and tests run
  with `-race`.
- **Silent failures** - if something can fail, handle or log it.
- **Unbounded data** - cap returned collections and logged payloads.
- **Release drift** - keep `just ci`, the Dockerfile, and GitHub release
  workflow aligned so local validation matches what CI will publish.
