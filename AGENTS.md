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

GoDoc is a primary product surface, not commentary on the source. A
reader on pkg.go.dev (or running `go doc`) should be able to use any
package correctly without opening it. Exported symbols carry that
load: document the contract, not the Go shape. Package-level docs use
Go 1.19+ heading syntax for navigable structure; cross-reference
related symbols with `[Identifier]` doc links; add runnable `Example*`
tests (see `internal/platform/identity/example_test.go`) for the
primary usage patterns so the docs cannot bit-rot.

Unexported symbols answer a different question: *why is this here in
its current form?* The test for whether a comment is earning its place:

> If a contributor deleted this symbol in a PR, would the surrounding
> code make clear why that's wrong?

If no, document the why. If yes, no comment needed.

Documentation is part of the reader-facing interface. A PR that
changes behavior without updating the affected docs is incomplete, the
same way a PR that changes a function without updating its tests is
incomplete.

## API Contract (OpenAPI)

The native API's machine-readable contract is generated from the Go
source — never hand-edit `internal/server/api/spec/openapi.{json,yaml}`.

- The route table in `internal/server/api/routes.go` is the single
  source of truth: mux registration, auth posture, and OpenAPI
  operation metadata all come from the same entry. Add new endpoints
  there; nothing is registered ad hoc.
- Contract-struct GoDoc IS the spec: a field's doc comment becomes its
  property `description` in the generated document. Optional
  `openapi:"format=…,enum=…,readOnly"` struct tags add schema metadata
  the `json` tag cannot express.
- After touching routes or contract structs, run `just generate` and
  commit the regenerated artifacts.
- The server serves the committed artifacts in-process:
  `/openapi.json`, `/openapi.yaml`, and the Scalar explorer at
  `/docs/` (vendored, offline-capable — see `internal/server/docs`).

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
