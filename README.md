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

The primary release artifact is a well-labeled, OCI-compliant multi-arch
container image. The current release line includes the complete
client-app enrollment + session macaroon auth stack, the first
protected CRUD endpoints (journey + telemetry), and a documented HTTP/3
+ mTLS Traefik recipe an operator can stand up in under fifteen
minutes.

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
- First end-to-end protected endpoints: `POST /v1/journeys`
  (identity-only), `GET /v1/journeys/{id}` (journey-scoped
  session macaroon), and `POST /v1/journeys/{id}/telemetry`
  (journey-scoped + `telemetry.write` session macaroon, plus a
  participant-membership check). Validates the full auth stack
  composes correctly before unlocking the rest of the protocol
  API surface.
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
POST /v1/journeys               (requires client cert) create a new
                                journey with the caller as host
POST /v1/garages                (requires client cert) create a new
                                garage with the caller as the sole
                                accepted owner; revision_version = 1
GET  /v1/garages                (requires client cert) list every
                                garage where the caller is an owner,
                                accepted or pending (so clients
                                surface invitations alongside owned)
GET  /v1/garages/{id}           (requires client cert; caller must
                                be an owner) load the garage's
                                current head state + materialized
                                owner list
POST /v1/garages/{id}/revisions (requires client cert; caller must
                                be an accepted owner and must equal
                                Garage.signed_by) publish the next
                                signed revision (rename, add/remove
                                owners)
POST /v1/garages/{id}/ownership-acceptances
                                (requires client cert; caller must
                                equal acceptance.accepter_user_id)
                                accept a pending ownership
                                invitation
POST /v1/garages/{id}/vehicles  (requires client cert; caller must
                                be an accepted owner) add a vehicle
                                to the garage at revision_version=1
GET  /v1/garages/{id}/vehicles  (requires client cert; caller must
                                be an owner, accepted or pending)
                                list the garage's vehicles —
                                pending invitees can preview the
                                library they're being invited into
GET  /v1/garages/{id}/vehicles/{vid}
                                (requires client cert; caller must
                                be an owner) load a single garage
                                vehicle's current head state
POST /v1/garages/{id}/vehicles/{vid}/revisions
                                (requires client cert; caller must
                                be an accepted owner) publish a
                                new signed revision (rename,
                                change photos, update capacity)
POST /v1/garages/{id}/invites   (requires client cert; caller must
                                be an accepted owner) mint a fresh
                                invite token for sharing the garage;
                                response carries the plaintext
                                token once, never retrievable from
                                the server again
GET  /v1/garages/{id}/invites   (requires client cert; caller must
                                be an accepted owner) list every
                                invite issued for the garage —
                                token field is never populated on
                                this path
POST /v1/garages/{id}/invites/{inviteId}/revoke
                                (requires client cert; caller must
                                be an accepted owner) revoke an
                                outstanding invite so further
                                redeems fail
POST /v1/garage-invites/redeem  (requires client cert) body
                                {"token": "..."}; redeems the
                                invite and adds the caller as an
                                accepted owner of the inviter's
                                garage. Token in body so it
                                doesn't leak into access logs
GET  /v1/journeys/{id}          (requires session macaroon scoped to
                                the journey + journey.read) load journey
POST /v1/journeys/{id}/telemetry
                                (requires session macaroon scoped to
                                the journey + telemetry.write) record
                                a telemetry batch
POST /v1/journeys/{id}/vehicles  (requires session macaroon scoped to
                                the journey + journey.write) upload a
                                journey-scoped Vehicle and its initial
                                signed ACL revision
GET  /v1/journeys/{id}/vehicles  (requires session macaroon scoped to
                                the journey + journey.read) list every
                                Vehicle uploaded against the journey
GET  /v1/journeys/{id}/vehicles/{vid}
                                (requires session macaroon scoped to
                                the journey + journey.read) load a
                                single journey vehicle
POST /v1/journeys/{id}/vehicles/{vid}/acl-revisions
                                (requires session macaroon scoped to
                                the journey + journey.write) append a
                                new signed VehicleACL revision; the
                                vehicle's current_acl_version pointer
                                advances when the supplied version is
                                strictly greater
POST /v1/journeys/{id}/vehicles/{vid}/driver-attestations
                                (requires session macaroon scoped to
                                the journey + journey.write) record a
                                signed DriverAttestation; the server
                                resolves the VehicleACL revision
                                current at the attestation's
                                effective_time and classifies the
                                trust outcome as authorized,
                                emergency_fallback, or acl_violation.
                                Gossiped replays of the same
                                (vehicle, driver, effective_time)
                                tuple return 200 with the existing
                                record instead of 409
GET  /v1/journeys/{id}/vehicles/{vid}/driver-attestations
                                (requires session macaroon scoped to
                                the journey + journey.read) list
                                every recorded DriverAttestation
                                ordered by effective_time ascending,
                                including low-trust rows so clients
                                can audit the full chain of custody
GET  /v1/journeys/{id}/vehicles/{vid}/current-driver
                                (requires session macaroon scoped to
                                the journey + journey.read) returns
                                the DriverAttestation in effect at
                                the optional ?at=<rfc3339> timestamp
                                (defaults to now); includes fork
                                siblings when the attestation chains
                                to a contested predecessor
```

Future OpenCaravan API routes will be documented as they land. Go package
documentation is part of the public reader experience; exported symbols and
packages should have useful Godoc comments.

## OpenCaravan Protocol Version

The `/v1/server.protocol.version` field advertises the OpenCaravan
wire-format version this server implements (currently `0.1.0`). The
protocol version is **decoupled** from the spivot-server release
version: spivot-server releases that fix bugs or add capabilities
without changing the wire format do not bump the protocol version, and
spivot-server releases that consume a new wire format from
opencaravan-go bump the protocol version in lockstep with that
module's tag.

The 0.x prefix signals pre-stable; a 1.0 protocol release will mark
the wire format as frozen. A client should treat `0.1.x` and `0.1.y`
as compatible (additive extensions only), and a leading-digit change
(e.g., `0.1` → `0.2`) as a breaking wire-format revision that needs
matching client work.

In practice, when reading a deployed server: `spivot-server v0.X.Y`
and `OpenCaravan vA.B.C` are independent vectors. A long divergence
(server at `v0.5.0` while protocol is still `0.1.0`) is informative,
not a bug — it tells a client author that the wire format has been
stable for many server releases.

## Vehicles, Garages, and Driver Attestations

[`docs/vehicles.md`](docs/vehicles.md) covers how this server
realizes the OpenCaravan vehicle protocol: storage schema rationale,
per-endpoint behavior, the integrity verifier internals, and curl
walkthroughs for the journey-side vehicle lifecycle and household
garage sharing flows. Read
[opencaravan-go/docs/vehicles.md](https://github.com/opencaravan/opencaravan-go/blob/main/docs/vehicles.md)
first for the canonical wire-format specification; this server's
doc starts every section by cross-referencing the spec.

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

Every leaf certificate the CA signs is recorded in the
`issued_certificates` audit table (serial, subject, validity window,
issuance time, revocation time). The identity middleware resolves a
presented client certificate's serial back to its enrolled
`(user_id, client_app_id)` through that table, so revoking a row by
setting `revoked_at` is sufficient to break the identity binding —
short-lived (7-day) leaf certs make CRL/OCSP infrastructure
unnecessary for v0.

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

The current schema covers, by capability area:

- **Identity and accounts** — accounts, account devices, vehicles.
- **Journeys** — journeys with per-journey policy snapshots, journey
  invites, journey participants and consent, participant sessions, and
  journey segments.
- **Telemetry** — telemetry batches and position samples.
- **Auth** — `issued_certificates` (audit trail of every leaf cert the
  CA signs: serial, subject, validity window, issuance time, revocation
  time), `client_app_invites` (hashed invite tokens with scope and
  one-time-use semantics), `client_apps` (one row per enrolled app
  installation), and `macaroon_roots` (HMAC root keys the session
  macaroon issuer signs against — rotated rows retained so macaroons
  signed under a since-rotated key remain verifiable until their own
  `time<T` caveat fires).
- **Federation and policy** — server policy snapshots, federated
  servers (placeholder, federation isn't wired yet).

The schema stores protocol-facing data conservatively: text identifiers,
RFC3339 timestamp strings, integer-scaled coordinates, hashed invite tokens, and
JSON extension documents. Runtime storage uses SQLite, with the embedded
migrations applied at startup before the server begins handling API traffic.

Container deployments reserve `/etc/spivot` for operator configuration and
`/var/lib/spivot` for durable state. The default SQLite database path is
`/var/lib/spivot/spivot.db` in the container and `data/spivot.db` for local
development unless `SPIVOT_DATABASE_PATH` is set.

## Containers

`just container` performs a multi-arch build (defaults to
`linux/amd64,linux/arm64`) via `docker buildx`. Output is a per-arch
`docker save`-compatible tarball under `dist/` plus the host-arch
variant loaded into the local Docker daemon for `just container-run`:

```bash
just container
# → dist/spivot-server-linux-amd64.tar
# → dist/spivot-server-linux-arm64.tar
# → ghcr.io/wheelsdown/spivot-server:dev loaded into the local daemon
```

To smoke-test a release candidate against a remote deploy host, push
the same multi-arch build to GHCR:

```bash
echo "$(gh auth token)" | docker login ghcr.io -u "$(gh api user -q .login)" --password-stdin
just container-push ghcr.io/wheelsdown/spivot-server:dev
```

Tagged releases are intended to be consumed from GitHub Container
Registry:

```bash
docker pull ghcr.io/wheelsdown/spivot-server:latest
```

For production Docker Compose deployments behind an existing reverse
proxy, see
[docs/deployment/docker-compose.md](docs/deployment/docker-compose.md).
For the canonical HTTP/3 + mTLS deployment recipe (Traefik in front,
client cert termination, worked enrollment walkthrough), see
[docs/deployment/reverse-proxy.md](docs/deployment/reverse-proxy.md)
and
[examples/deploy/traefik/mtls/](examples/deploy/traefik/mtls/).

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
internal/server/api/     HTTP API handlers
internal/server/middleware/  identity + session attach/require middleware
internal/platform/       build info, identity (CA + key store), auth
                         (macaroon issuer/verifier), logging, proxy
                         (forwarded-headers handling), storage, and
                         shared platform code
scripts/releng/          release engineering helpers
docs/deployment/         operator-facing deployment recipes
examples/deploy/         reverse-proxy example configurations
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
