# API Contract

The API's machine-readable contract is generated from the Go source —
the route table and contract structs *are* the spec — and served by
the running binary:

- **`/docs/`** — embedded Scalar API explorer, offline-capable, no
  CDN dependency
- **`/openapi.json`** / **`/openapi.yaml`** — the OpenAPI 3.1
  document
- [`internal/server/api/spec/`](../internal/server/api/spec/) — the
  same artifacts, committed, for reading without a running server

The surface spans five domains: System (health, readiness, discovery,
version), Identity (client-app enrollment, session macaroons,
server-registration invites), Journeys (create, fetch, telemetry
batches), Journey Vehicles (signed vehicle bundles, ACL revisions,
driver attestations, current-driver resolution), and Garages (shared
vehicle libraries with signed revisions, two-phase ownership
acceptance, and invite tokens).

Every operation records its authentication posture in an
`x-spivot-auth` extension derived from the same route table that
wires the middleware, so the documented contract cannot drift from
the enforced one. A stale committed spec fails `just ci`. Failure
responses share one RFC 7807-style problem envelope; clients branch
on its `code` field.

## Versioning

Three version vectors travel independently:

- **Server release** (`spivot-server v0.X.Y`) — the software.
- **OpenCaravan protocol version** (`/v1/server` →
  `protocol.version`) — the wire format. A server release that fixes
  bugs or adds capabilities without changing the wire format does not
  bump it; a release that consumes a breaking wire-format change from
  opencaravan-go bumps it in lockstep with that module's tag. The 0.x
  prefix signals pre-stable; clients should treat `0.1.x` → `0.1.y`
  as compatible (additive only) and a minor-digit change (`0.1` →
  `0.2`) as a breaking revision needing matching client work.
- **Contract version** (`info.version` in the OpenAPI document) —
  the documented HTTP surface. Bumped when the documented contract
  changes shape; frozen at 1.0.0 when the surface is declared stable.

A long divergence between vectors is informative, not a bug: a server
at `v0.5.0` still speaking protocol `0.1.0` tells a client author the
wire format has been stable for many releases.
