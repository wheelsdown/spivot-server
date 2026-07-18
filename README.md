# Spivot Server

[![CI](https://github.com/wheelsdown/spivot-server/actions/workflows/ci.yml/badge.svg)](https://github.com/wheelsdown/spivot-server/actions/workflows/ci.yml)
[![Release](https://github.com/wheelsdown/spivot-server/actions/workflows/release.yml/badge.svg)](https://github.com/wheelsdown/spivot-server/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/wheelsdown/spivot-server.svg)](https://pkg.go.dev/github.com/wheelsdown/spivot-server)
[![Go Report Card](https://goreportcard.com/badge/github.com/wheelsdown/spivot-server)](https://goreportcard.com/report/github.com/wheelsdown/spivot-server)
[![OCI Image](https://img.shields.io/badge/OCI-ghcr.io%2Fwheelsdown%2Fspivot--server-blue)](https://github.com/wheelsdown/spivot-server/pkgs/container/spivot-server)

Spivot Server is the reference Go back end for OpenCaravan, an open
protocol for coordinating group drives — road trips, convoys, club
runs, and the everyday logistics of people moving together in more
than one vehicle. The server is being built alongside the first
OpenCaravan specification so the protocol has a practical, operable
reference implementation from the beginning.

## Peer-coordinated, not server-gated

The design premise of OpenCaravan is that a journey belongs to its
participants, not to a server.

The events that matter in a group drive — a vehicle joining, its
access list changing, a driver taking the wheel, a garage adding an
owner — are **signed statements by the participant with the authority
to make them**. A vehicle's metadata is signed by its owner. An ACL
revision is signed by the owner it belongs to. A driver attestation is
signed by the driver themselves. Each payload travels as canonical
bytes under an integrity envelope, so any peer holding the signer's
certificate chain can verify it — over this server's API, but equally
device-to-device at a trailhead with no coverage, or relayed through
whatever transport the moment offers. Enrollment exists precisely to
make that possible: it binds a device to a key, and apps pin the CA
chain so peer-to-peer validation works with no server in the path.

The server, in turn, verifies, records, and redistributes — it is a
durable coordinator and an auditor, not a gatekeeper. When a driver
attestation arrives, the server doesn't decide whether the handoff was
*allowed to happen*; it evaluates the claim against the ACL that was
in effect at that moment and records the outcome — authorized,
emergency fallback, or violation — as an auditable judgment. Low-trust
events are retained as evidence, not rejected. Peers gossiping the
same event to the server is the normal case, answered idempotently
rather than treated as a conflict. History is append-only signed
revision chains; departure freezes a chain rather than deleting it.

The goal is an ecosystem: many apps, written by many people,
coordinating journey events with each other — through this server,
through ad hoc or alternative network flows when that's what the road
provides, and through both interchangeably. This repository exists so
that ecosystem has a reference coordinator that is honest, inspectable,
and boring to operate.

## Project Status

Spivot Server is pre-release software. Expect API and schema changes
while the OpenCaravan protocol vocabulary settles.

The current release line carries the complete identity stack
(client-app enrollment against a server-local CA, session macaroons,
invite-gated onboarding), the journey / vehicle / garage protocol
surface with signed-payload integrity verification throughout, and a
generated OpenAPI contract served by the binary itself. The precise
capabilities of any build are what its contract says they are — see
[`/docs/`](docs/api.md) on a running server, or the
[API documentation](docs/api.md).

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
open http://127.0.0.1:8080/docs/
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

`just ci` is the required local gate before pushing changes. It runs
formatting checks, module tidiness, OpenAPI artifact freshness,
linting, race tests, container build validation, OCI label checks,
`spivot-server version`, and a live container health check.

## Documentation

Technical specifics live in targeted documents so this page can stay
introductory:

- [docs/api.md](docs/api.md) — the generated OpenAPI contract, the
  embedded `/docs/` explorer, and how the three version vectors
  (server, protocol, contract) relate.
- [docs/identity.md](docs/identity.md) — the certificate authority,
  enrollment invites, first-run bootstrap, and the invite minting
  policy.
- [docs/vehicles.md](docs/vehicles.md) — how this server realizes the
  OpenCaravan vehicle protocol: journey vehicles, ACL revisions,
  driver attestations and trust evaluation, and household garages,
  with curl walkthroughs. Read
  [opencaravan-go/docs/vehicles.md](https://github.com/opencaravan/opencaravan-go/blob/main/docs/vehicles.md)
  first for the canonical wire-format specification.
- [docs/storage.md](docs/storage.md) — the SQLite schema, embedded
  migrations, and data-directory layout.
- [docs/deployment/](docs/deployment/) — operator recipes: Docker
  Compose, the HTTP/3 + mTLS Traefik front end, and container build
  mechanics.
- [docs/release-checklist.md](docs/release-checklist.md) — the release
  process around `just prepare-release` / `just publish-release`.

## Repository Layout

```text
cmd/spivot-server/       command entry point and CLI parsing
internal/app/            process lifecycle wiring
internal/server/api/     HTTP API: route table, handlers, generated spec
internal/server/docs/    embedded Scalar API explorer
internal/server/middleware/  identity + session attach/require middleware
internal/tools/openapigen/   OpenAPI generator (go:generate)
internal/platform/       build info, identity (CA + key store), auth
                         (macaroon issuer/verifier), logging, proxy
                         (forwarded-headers handling), storage, and
                         shared platform code
scripts/releng/          release engineering helpers
docs/                    project documentation (see above)
examples/deploy/         reverse-proxy example configurations
```

## Contributing

See [AGENTS.md](AGENTS.md) for the project conventions used by Codex
and other automation:

- prefer the Go standard library
- keep PRs focused
- use conventional commits
- run `just ci` locally before every push
- keep exported Go symbols and packages documented for Godoc

## License

Spivot Server is licensed under the Apache License, Version 2.0. See
[LICENSE](LICENSE) and [NOTICE](NOTICE) for the full text and
attribution.

"Spivot" is a trademark of the Spivot project. The code license does
not grant trademark rights; see [TRADEMARK.md](TRADEMARK.md) for what
you can do with the name.
