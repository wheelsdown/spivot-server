# Spivot Server

[![CI](https://github.com/wheelsdown/spivot-server/actions/workflows/ci.yml/badge.svg)](https://github.com/wheelsdown/spivot-server/actions/workflows/ci.yml)
[![Release](https://github.com/wheelsdown/spivot-server/actions/workflows/release.yml/badge.svg)](https://github.com/wheelsdown/spivot-server/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/wheelsdown/spivot-server.svg)](https://pkg.go.dev/github.com/wheelsdown/spivot-server)
[![Go Report Card](https://goreportcard.com/badge/github.com/wheelsdown/spivot-server)](https://goreportcard.com/report/github.com/wheelsdown/spivot-server)
[![OCI Image](https://img.shields.io/badge/OCI-ghcr.io%2Fwheelsdown%2Fspivot--server-blue)](https://github.com/wheelsdown/spivot-server/pkgs/container/spivot-server)

Spivot Server is the reference Go back end for OpenCaravan, an open protocol
for coordinating group drives over networks. The server is being built
alongside the first OpenCaravan specification so the protocol has a practical,
operable reference implementation from the beginning.

The primary release artifact is a well-labeled, OCI-compliant container image.
The current codebase is intentionally early: it has the command/server
foundation, health/version endpoints, release tooling, and the first storage
schema foundation for tracked journeys.

## Project Status

Spivot Server is pre-release software. Expect API and schema changes while the
OpenCaravan protocol vocabulary settles.

Current foundation:

- Go HTTP service with a small `main` shim around a testable `run` entry point.
- Structured logging with `log/slog`.
- Health, readiness, and version endpoints.
- Container-first release engineering with OCI labels and health checks.
- Embedded SQL migration metadata for OpenCaravan journey storage.

## Requirements

- Go 1.26+
- [just](https://just.systems/)
- Docker, for container builds and the full CI gate
- `golangci-lint` v2, for local linting

## Quick Start

```bash
git clone https://github.com/wheelsdown/spivot-server.git
cd spivot-server

just ci
just serve
```

In another shell:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/v1/version
```

You can also run the command directly while developing:

```bash
go run ./cmd/spivot-server serve
```

## Common Workflows

All project workflows go through the `justfile`.

```bash
just build          # Build for the current platform -> dist/
just build-linux    # Build linux/amd64 and linux/arm64 binaries
just container      # Build a local OCI image
just container-run  # Run the local dev image on port 8080
just test           # Run tests with the race detector
just lint           # Run golangci-lint v2
just ci             # Full local gate
```

`just ci` is the required local gate before pushing changes. It runs formatting
checks, module tidiness, linting, race tests, container build validation, OCI
label checks, `spivot-server version`, and a live container health check.

## API Surface

The current HTTP surface is deliberately small:

```text
GET /             service summary
GET /health       liveness check
GET /readyz       readiness check
GET /v1/version   build and runtime version metadata
```

Future OpenCaravan API routes will be documented as they land. Go package
documentation is part of the public reader experience; exported symbols and
packages should have useful Godoc comments.

## Storage Schema

The first schema foundation lives in
[`internal/platform/storage`](internal/platform/storage). Migrations are embedded
with Go's standard `embed` package so the server can expose and apply the exact
schema it was built with.

The initial OpenCaravan migration covers:

- server policy snapshots
- federated servers
- accounts and account devices
- vehicles
- journeys and per-journey policy snapshots
- journey invites and participant consent
- participant sessions
- journey segments
- telemetry batches
- position samples

The schema stores protocol-facing data conservatively: text identifiers,
RFC3339 timestamp strings, integer-scaled coordinates, hashed invite tokens, and
JSON extension documents. Runtime storage uses SQLite, with the embedded
migrations applied at startup before the server begins handling API traffic.

Container deployments reserve `/etc/spivot` for operator configuration and
`/var/lib/spivot` for durable state. The default SQLite database path is
`/var/lib/spivot/spivot.db` in the container and `data/spivot.db` for local
development unless `SPIVOT_DATABASE_PATH` is set.

## Containers

Build a local OCI image:

```bash
just container
```

Run it locally:

```bash
just container-run
```

Published releases are intended to be consumed from GitHub Container Registry:

```bash
docker pull ghcr.io/wheelsdown/spivot-server:latest
```

For production Docker Compose deployments behind an existing reverse proxy, see
[docs/deployment/docker-compose.md](docs/deployment/docker-compose.md).

## Release Engineering

Release tags use semver with a leading `v`, such as `v0.1.0` or
`v0.1.0-rc.1`.

```bash
just prepare-release v0.1.0
just publish-release v0.1.0
```

The convenience wrapper runs both phases:

```bash
just release-github v0.1.0
```

The release workflow publishes multi-architecture OCI images to GHCR on release
tags. Version data is injected at build time; release versions should not be
hardcoded in Go source.

## Repository Layout

```text
cmd/spivot-server/       command entry point and CLI parsing
internal/app/            process lifecycle wiring
internal/server/api/     HTTP API server
internal/platform/       build info, logging, storage, and shared platform code
scripts/releng/          release engineering helpers
```

## Contributing

See [AGENTS.md](AGENTS.md) for the project conventions used by Codex and other
automation:

- prefer the Go standard library
- keep PRs focused
- use conventional commits
- run `just ci` locally before every push
- keep exported Go symbols and packages documented for Godoc

## License

Spivot Server is licensed under the Apache License, Version 2.0. See
[LICENSE](LICENSE) and [NOTICE](NOTICE) for the full text and attribution.

"Spivot" is a trademark of the Spivot project. The code license does not grant
trademark rights; see [TRADEMARK.md](TRADEMARK.md) for what you can do with the
name.
