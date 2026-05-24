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
- Health, readiness, version, and server discovery endpoints.
- In-band server policy snapshot advertisement.
- Server-local certificate authority (`spivot-server ca init`) that issues
  short-lived client app certificates.
- Single-use invite tokens for client app enrollment, with first-run
  bootstrap logging for unattended container deployments.
- `POST /v1/client-apps/enroll` HTTP endpoint that redeems a
  server_registration invite + CSR for a 7-day signed leaf certificate.
- Identity middleware that resolves a presented client certificate
  (direct mTLS or proxy-forwarded) to its enrolled `(user_id, client_app_id)`
  via the `issued_certificates` audit table.
- Macaroon issuer + verifier (`internal/platform/auth/macaroon`)
  backed by a `macaroon_roots` HMAC keystore. The OpenCaravan caveat
  vocabulary (`time<T`, `journey=`, `user=`, `client_app=`,
  `action=`) is enforced at verify time, with unknown predicates
  rejected fail-closed.
- `POST /v1/sessions` endpoint that issues a session macaroon for
  an authenticated client app. One macaroon authorizes one
  `SessionAction` against an optional journey; multi-action
  sessions are deferred to a future protocol extension.
- Session validation middleware (`AttachSession` + `RequireSession`)
  that lifts the `Authorization: Macaroon ...` header, verifies
  the macaroon signature once per request, and provides
  composable per-handler constraints (action match, journey path
  parameter match, custom). Mirrors the two-tier shape of the
  identity middleware.
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
GET  /                          service summary
GET  /health                    liveness check
GET  /readyz                    readiness check
GET  /v1/server                 server discovery, capabilities, and policy snapshot
GET  /v1/version                build and runtime version metadata
POST /v1/client-apps/enroll     redeem a server_registration invite + CSR
                                for a signed leaf certificate
POST /v1/sessions               (requires client cert) issue a session
                                macaroon for a single SessionAction,
                                optionally scoped to a journey
```

Future OpenCaravan API routes will be documented as they land. Go package
documentation is part of the public reader experience; exported symbols and
packages should have useful Godoc comments.

## Certificate Authority

Spivot Server acts as its own certificate authority for the client apps that
enroll with it. The CA's keypair and self-signed root certificate are
generated on demand and persisted under `<data-dir>/identity/`:

```bash
spivot-server ca init        # generate keypair + self-signed root if absent
spivot-server ca cert        # print the CA's certificate as PEM
```

`ca init` is idempotent: re-running it loads the existing CA and prints its
fingerprint. The key is written with 0600 permissions and is never logged.
Subject defaults to `CN=Spivot Server CA`; override with `--common-name` and
`--organization` flags (or `SPIVOT_CA_COMMON_NAME` / `SPIVOT_CA_ORGANIZATION`
env vars).

Phase 2a of the auth rollout adds the CA primitive and an audit table
(`issued_certificates`) for every leaf certificate the CA signs. Later
phases wire the CA into the enrollment HTTP endpoint and the
identity/session middleware.

## Client App Enrollment Invites

Spivot Server uses single-use invite tokens to gate which apps may enroll.
Each token carries a scope (`server_registration` for new users,
`journey` for joining a private journey), an expiration, and a one-time-use
guarantee. Only the SHA-256 hash of the token is stored on disk; the
plaintext is shown to the operator exactly once at issuance.

### First-run bootstrap

The first time a fresh server starts with zero registered users and no
active `server_registration` invite, it self-issues a 24-hour invite and
prints a fenced banner to its stdout. The expected operator flow:

```
docker run ... ghcr.io/wheelsdown/spivot-server:latest serve
...
████████████████████████████████████████████████████████████████████
  SPIVOT SERVER FIRST-RUN BOOTSTRAP
  ────────────────────────────────────────────────────────────────
  No administrator is registered. Use this server_registration
  invite to enroll the first user. Single-use, 24h expiry.

      <43-character base64url token>

  iOS app: Settings → Add Account → Use Invite
████████████████████████████████████████████████████████████████████
```

The operator copies the token from container logs into the first
administrator's app. Subsequent restarts while the bootstrap invite is
still active stay silent. Once a user is registered, the bootstrap path
never runs again.

### Day-two invites

After bootstrap, additional invites are issued by an administrator via
the CLI (later phases will add an authenticated HTTP endpoint):

```bash
spivot-server invite create                         # 24h server_registration invite
spivot-server invite create -scope journey -lifetime 168h    # 7 days
```

The output includes the plaintext token, the scope, the expiration time,
and the stored token hash for audit correlation.

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

The Phase 2a migration adds:

- `issued_certificates` — audit trail of every leaf certificate the CA has
  signed (serial, subject, validity window, issuance time, revocation time).

The Phase 2b migration adds:

- `client_app_invites` — hashed invite tokens (token_hash, scope,
  created/expiration timestamps, used_time, used_by_client_app_id).

The Phase 3a migration adds:

- `client_apps` — descriptive record for each enrolled app installation
  (id, owning user, display name, created time).
- `user_id` and `client_app_id` columns on `issued_certificates`
  linking every signed leaf back to the requesting user and app.

The Phase 4a migration adds:

- `macaroon_roots` — HMAC root keys this server uses to mint and
  verify session macaroons. Each row records an opaque id (embedded
  in every macaroon so the verifier can pick the right key),
  creation timestamp, and rotation timestamp. Rotated rows are
  retained so macaroons issued under a rotated key remain
  verifiable until their own `time<T` caveat fires.

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
internal/platform/       build info, identity (CA + key store), logging,
                         storage, and shared platform code
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
