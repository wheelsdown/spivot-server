# Storage

The schema foundation lives in
[`internal/platform/storage`](../internal/platform/storage). Migrations
are embedded with Go's standard `embed` package so the server can
expose and apply the exact schema it was built with; they run at
startup before the server begins handling API traffic. Runtime storage
uses SQLite.

The current schema covers, by capability area:

- **Identity and accounts** — accounts, account devices, vehicles.
- **Journeys** — journeys with per-journey policy snapshots, journey
  invites, journey participants and consent, participant sessions, and
  journey segments.
- **Vehicles and attestations** — journey vehicles with signed
  metadata + ACL revision chains (canonical payload bytes stored
  verbatim), and driver attestations with server-evaluated trust
  flags.
- **Garages** — garages, signed garage revisions, materialized owner
  rows, ownership acceptances, garage vehicles with revision chains,
  and hashed garage-invite tokens with redemption records.
- **Telemetry** — telemetry batches and position samples.
- **Auth** — `issued_certificates` (audit trail of every leaf cert the
  CA signs: serial, subject, validity window, issuance time,
  revocation time), `client_app_invites` (hashed invite tokens with
  scope and one-time-use semantics), `client_apps` (one row per
  enrolled app installation), and `macaroon_roots` (HMAC root keys the
  session macaroon issuer signs against — rotated rows retained so
  macaroons signed under a since-rotated key remain verifiable until
  their own `time<T` caveat fires).
- **Federation and policy** — server policy snapshots, federated
  servers (placeholder, federation isn't wired yet).

The schema stores protocol-facing data conservatively: text
identifiers, RFC3339 timestamp strings, integer-scaled coordinates,
hashed invite tokens, and JSON extension documents. Signed protocol
payloads are stored as the exact canonical bytes the signer produced,
so a reader can re-verify signatures against what was actually signed.

Container deployments reserve `/etc/spivot` for operator configuration
and `/var/lib/spivot` for durable state. The default SQLite database
path is `/var/lib/spivot/spivot.db` in the container and
`data/spivot.db` for local development unless `SPIVOT_DATABASE_PATH`
is set.
