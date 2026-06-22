# Vehicles, Garages, and Driver Attestations: Implementation Notes

This document describes **how spivot-server realizes** the OpenCaravan
vehicle protocol. The canonical protocol specification lives in
[opencaravan-go/docs/vehicles.md](https://github.com/opencaravan/opencaravan-go/blob/main/docs/vehicles.md);
read that first for the wire types, signature semantics, and the
two-layer (garage / journey) design intent.

This document covers what's specific to this server: schema layout
rationale, per-endpoint status codes, the integrity verifier
internals, and a curl walkthrough of the full vehicle lifecycle.
Each section starts by cross-referencing the corresponding spec
section so a reader can move between "what the protocol says" and
"how spivot-server does it" without re-deriving anything.

## Storage Schema

Cross-ref: [Two Layers](https://github.com/opencaravan/opencaravan-go/blob/main/docs/vehicles.md#two-layers).

The server persists the vehicle layer across several SQLite tables.
Each table either materializes a current-state projection (fast
lookups) or retains the full signed-revision history (audit trail).
The pattern is consistent: a head-pointer row in the projection
table + revision rows in a `_revisions` companion table, with
canonical payload bytes retained verbatim so signatures can be
re-verified later without re-canonicalizing from parsed fields.

### Journey layer

| Table | Migration | Role |
| --- | --- | --- |
| `journey_vehicles` | [000006](../internal/platform/storage/migrations/000006_journey_vehicles.sql) | Head pointer per uploaded journey-scoped `Vehicle`. Carries the denormalized fields + the integrity envelope of the most recent ACL revision. |
| `journey_vehicle_acl_revisions` | 000006 | Full history of signed `VehicleACL` updates. Driver attestations validate against the revision current at their effective time. |
| `driver_attestations` | [000007](../internal/platform/storage/migrations/000007_driver_attestations.sql) | One row per signed handoff. Server-computed `trust_flag` (`authorized` / `emergency_fallback` / `acl_violation`) is stored alongside the raw payload. The server **never deletes** an attestation on trust failure. |

### Garage layer

| Table | Migration | Role |
| --- | --- | --- |
| `garages` | [000008](../internal/platform/storage/migrations/000008_garages.sql) | Head pointer per garage with `current_revision_version` for fast lookup. |
| `garage_revisions` | 000008 | Full history of signed `Garage` payloads. |
| `garage_owners` | 000008 | Materialized current owner list per garage. `accepted_time` is NULL while the invitation is pending; non-NULL once the recipient has published a `GarageOwnershipAcceptance`. `added_in_revision_version` binds each owner row to the revision that first introduced it — used to prevent accepting against the wrong revision. |
| `garage_ownership_acceptances` | 000008 | Signed acceptance audit trail. |
| `garage_vehicles` | [000009](../internal/platform/storage/migrations/000009_garage_vehicles.sql) | Head pointer per garage-scoped vehicle. |
| `garage_vehicle_revisions` | 000009 | Full history of signed `GarageVehicle` updates. |
| `garage_invites` | [000010](../internal/platform/storage/migrations/000010_garage_invites.sql) | Token-based onboarding. Plaintext token hashed (SHA-256) before persistence; returned to inviter once on creation. CHECK constraint enforces `redemption_count <= max_redemptions`. |
| `garage_invite_redemptions` | 000010 | Per-redemption audit row. UNIQUE on `(invite, redeemer)` prevents the same user from consuming a slot twice. |

### Integrity verification support

| Column | Migration | Purpose |
| --- | --- | --- |
| `issued_certificates.cert_pem` | [000011](../internal/platform/storage/migrations/000011_issued_certificate_pem.sql) | Full PEM-encoded leaf cert stored at enrollment time so the integrity verifier can resolve any enrolled client app's public key. |
| `telemetry_batches.driver_attestation_hash` | [000012](../internal/platform/storage/migrations/000012_telemetry_driver_attestation_link.sql) | Optional link from a telemetry batch to the `DriverAttestation` in effect when its samples were captured. Stored verbatim — gossipped attestations may reach the server after the batch they describe; correlation happens at audit replay. |

### Why ACL revisions live in their own table

The `Vehicle` payload carries the ACL inline at its current
version; the **server** keeps every version ever published as a
separate row so that a `DriverAttestation` referencing
`acl_version_consulted = N` can be validated against the ACL that
was current at the attestation's `effective_time` — not whatever
the ACL has since become. Decoupling attestation validity from
later ACL revisions is the load-bearing piece of the
offline-tolerant model: a driver who attested at v=2 is not
retroactively unauthorized by a v=3 revocation, and a driver who
was authorized at attestation time stays authorized when their
attestation finally syncs.

## Authorization

Cross-ref:
[Design Intent](https://github.com/opencaravan/opencaravan-go/blob/main/docs/vehicles.md#design-intent),
[Server-side Semantics](https://github.com/opencaravan/opencaravan-go/blob/main/docs/vehicles.md#server-side-semantics).

Every write to a signed-payload endpoint passes **three layers** of
check:

1. **Session macaroon caveats.** `RequireSession` middleware verifies
   the caller holds a macaroon naming this journey + the right
   action (e.g., `journey.write` for vehicle uploads). The caveat
   path is the only place a session can be rejected before the
   handler runs.
2. **Session-vs-payload identity match.** The handler enforces
   `payload.signer_field == session.user_id` so a `journey.write`
   holder can't attribute payloads to another user.
3. **Cryptographic signature verification.** The integrity verifier
   resolves `Integrity.KeyID` (a client app id) to the signer's
   enrolled cert, cross-checks `cert.user_id ==
   payload.signer_field` (cryptographic counterpart of layer 2),
   and verifies the ecdsa-p256-sha256 signature over the
   canonical bytes.

Each layer catches things the others can't. Session caveat alone is
just "you presented a macaroon for this journey." Identity match
alone is just "the caller named themselves in the payload." Only
the third layer requires a cryptographic proof that the user
named in the payload actually signed it.

### Garage-side authorization

Garage endpoints use **identity-only** auth (no journey-scoped
session macaroon). Authority is enforced per-handler:

- **Write** (create, revision append, vehicle add/edit): caller must
  be an **accepted** owner of the garage. Pending invitees see 403
  with `not_accepted_owner`. Non-owners see 404 (existence not
  leaked).
- **Read** (list, get): caller must be an owner — accepted OR
  pending. Pending invitees can preview the garage they're being
  invited into.
- **Invite redeem**: any authenticated user holding the token.
  Redemption IS the acceptance for invite-driven adds; the
  signed-revision invariant doesn't apply because the audit trail
  lives in `garage_invite_redemptions` instead.

## Endpoints

| Endpoint | Auth | Status codes |
| --- | --- | --- |
| `POST /v1/journeys/{id}/vehicles` | session: `journey.write` | 201 / 400 (invalid payload, bad signature shape) / 403 (session-vs-payload mismatch, signer-vs-cert mismatch, signature invalid) / 409 (duplicate owner, duplicate id) / 503 (verifier not wired) |
| `GET /v1/journeys/{id}/vehicles` | session: `journey.read` | 200 / 503 |
| `GET /v1/journeys/{id}/vehicles/{vid}` | session: `journey.read` | 200 / 404 / 503 |
| `POST /v1/journeys/{id}/vehicles/{vid}/acl-revisions` | session: `journey.write` | 201 / 400 / 403 (owner mismatch, signature invalid) / 404 / 409 (version conflict) |
| `POST /v1/journeys/{id}/vehicles/{vid}/driver-attestations` | session: `journey.write` | 201 (fresh) / 200 (gossiped replay returns stored record) / 400 (bad ACL-at-time, missing integrity) / 403 (driver mismatch) / 404 (vehicle missing) |
| `GET /v1/journeys/{id}/vehicles/{vid}/driver-attestations` | session: `journey.read` | 200 / 404 |
| `GET /v1/journeys/{id}/vehicles/{vid}/current-driver[?at=<rfc3339>]` | session: `journey.read` | 200 / 400 (invalid `?at`) / 404 (no attestation in effect yet) |
| `POST /v1/journeys/{id}/telemetry` | session: `telemetry.write` | 202 / 400 (empty `driver_attestation_hash` when present) / 403 / 409 |
| `POST /v1/garages` | identity | 201 / 400 (must be revision_version=1) / 403 (signer mismatch) |
| `GET /v1/garages` | identity | 200 |
| `GET /v1/garages/{id}` | identity | 200 / 404 (non-owner or unknown) |
| `POST /v1/garages/{id}/revisions` | identity (accepted owner) | 201 / 403 (pending invitee) / 404 / 409 (version conflict) |
| `POST /v1/garages/{id}/ownership-acceptances` | identity (must match accepter_user_id) | 201 / 200 (idempotent replay) / 400 / 403 / 404 (no pending invitation) |
| `POST /v1/garages/{id}/vehicles` | identity (accepted owner) | 201 / 403 / 404 |
| `GET /v1/garages/{id}/vehicles` | identity (any owner) | 200 / 404 |
| `GET /v1/garages/{id}/vehicles/{vid}` | identity (any owner) | 200 / 404 |
| `POST /v1/garages/{id}/vehicles/{vid}/revisions` | identity (accepted owner) | 201 / 403 / 404 / 409 |
| `POST /v1/garages/{id}/invites` | identity (accepted owner) | 201 (token returned ONCE) / 403 / 404 |
| `GET /v1/garages/{id}/invites` | identity (accepted owner) | 200 (NO plaintext tokens) |
| `POST /v1/garages/{id}/invites/{inviteId}/revoke` | identity (accepted owner) | 204 / 404 |
| `POST /v1/garage-invites/redeem` | identity | 201 / 400 / 404 / 409 / 410 (expired/revoked/exhausted) |

All error responses use the standard Problem Details shape (`code`,
`detail`, `status`).

## Integrity Verifier

Cross-ref:
[`Integrity` Envelope](https://github.com/opencaravan/opencaravan-go/blob/main/docs/protocol-model.md#integrity)
and
[Driver Attestation Validation](https://github.com/opencaravan/opencaravan-go/blob/main/docs/vehicles.md#driver-attestation-validation).

The integrity verifier lives in
[`internal/platform/auth/integrity`](../internal/platform/auth/integrity).
It accepts a canonical payload + Integrity envelope and runs the
full chain:

1. Structural validate (`Integrity.Validate()` plus a non-empty
   canonical-bytes check).
2. Algorithm gate — only `ecdsa-p256-sha256` is implemented.
3. Signature base64 decode + ASN.1 SEQUENCE-of-two-positive-INTEGERs
   parse. Malformed bytes surface as `ErrSignatureMalformed`
   distinct from a wrong-key failure.
4. Resolve `Integrity.KeyID` (treated as the signing client app's
   `client_app_id`) via the `KeyResolver` to the cert's public
   key. The production resolver
   ([`NewStoreResolver`](../internal/platform/auth/integrity/store_resolver.go))
   loads the cert PEM from `issued_certificates` and returns the
   parsed public key.
5. Type/curve check (P-256 only).
6. ECDSA verify against the SHA-256 digest of the canonical bytes.

Each failure mode maps to a distinct sentinel
([`ErrUnsupportedAlgorithm`, `ErrSignatureMalformed`,
`ErrSignatureInvalid`, `ErrKeyIDUnresolved`, `ErrKeyTypeMismatch`,
`ErrResolverTransport`, `ErrEmptyCanonicalPayload`](../internal/platform/auth/integrity/verifier.go))
so the handler can map to the right HTTP status (400 vs 403 vs
500) without re-parsing the error string.

The shared
[`verifySignedPayload`](../internal/server/api/integrity_verify.go)
helper does the cert lookup ONCE (caller's helper loads the
`CertIdentity` for the cross-check, and the verifier reuses the
same `cert.PublicKey` via `VerifyPayloadWithKey`). This closes a
TOCTOU window where the cert could be revoked between two
separate lookups, and saves a DB round-trip per request.

## Garage Invite Flow

Cross-ref:
[Sharing](https://github.com/opencaravan/opencaravan-go/blob/main/docs/vehicles.md#sharing-a-garage).

The protocol's `GarageOwnershipAcceptance` requires the inviter to
know the invitee's `user_id` before publishing a pending-owner
revision. In practice users don't trade UUIDs — they share an
opaque code. The server provides a token-based onboarding path
that sidesteps the signed-revision invariant for invite-driven
adds:

1. Accepted owner A calls `POST /v1/garages/{id}/invites`. Server
   mints a token, returns the plaintext **once**, stores only the
   SHA-256 hash.
2. A shares the token with B out-of-band (SMS, in-person, QR
   code).
3. B calls `POST /v1/garage-invites/redeem` with the token in the
   request body. Server verifies the token (not expired, not
   revoked, not exhausted, B not already an owner) and adds B
   directly as an accepted owner. The redemption IS the
   acceptance; no separate signed payload is required.

Two atomicity protections in `RedeemGarageInvite`:

- **Pre-check + conditional UPDATE**: the redemption-limit check
  runs as `redemption_count < max_redemptions` inside the
  `UPDATE redemption_count + 1 WHERE ...` clause, so two
  concurrent redeems both passing the pre-check can't both
  increment past the limit. The loser returns
  `ErrGarageInviteExhausted`; the tx rolls back.
- **CHECK constraint**: a defense-in-depth `CHECK
  (redemption_count <= max_redemptions)` at the DB layer rejects
  any future code path that bypasses the conditional UPDATE.

## Audit Trail and Trust Flags

Cross-ref:
[Trust](https://github.com/opencaravan/opencaravan-go/blob/main/docs/vehicles.md#trust-and-trust-flags).

The server **never deletes** a signed payload on trust failure.
Every `DriverAttestation` is persisted with its server-computed
`trust_flag`:

- `authorized`: driver was in `AuthorizedDrivers` of the
  `VehicleACL` revision current at `effective_time`. Vehicle
  owners are implicitly authorized regardless of ACL membership.
- `emergency_fallback`: driver was NOT in the ACL but the
  vehicle's `EmergencyRule.Kind == any_journey_participant` AND
  the driver is a joined participant. Recorded with reduced
  trust; clients should surface a "non-ACL emergency driver"
  indicator.
- `acl_violation`: driver was not in the ACL and no fallback
  applied. The record is retained as evidence; consumers must
  treat it as untrusted.

### Fork detection

When two drivers concurrently take over a vehicle (offline
handoff in opposite directions of a vehicle splitting at a
junction, for example), both attestations chain to the same
`PriorAttestationHash`. The server detects this by querying
`DriverAttestationForkSiblings(vehicle_id, prior_hash)`:

- The `POST .../driver-attestations` response includes a
  `fork_siblings` array with **every** attestation sharing the
  prior hash (including the just-recorded one). Single-element
  list = no fork; ≥2 = contested predecessor.
- The `GET .../current-driver` response includes
  `fork_siblings` with the OTHER claimants (excluding the
  selected one) so clients can render "you're attributed to
  driver X, but driver Y has a competing claim."

Both responses are advisory: the server picks one record as
"current" (highest `effective_time`, tie-broken by `received_at`
descending) but the fork is preserved in the audit log for
human / host resolution.

### Telemetry chain of custody

If a `telemetry_batches` row carries a
`driver_attestation_hash` and the linked attestation later fails
verification (e.g., the signing cert is revoked, or a later audit
finds the canonical bytes don't match), the telemetry rows under
that attestation can be flagged with downgraded trust — never
deleted. The hash is the join key future audit replays walk; the
correlation pass is not yet implemented but the column is in
place.

## Curl Walkthrough: Journey-Side Vehicle Lifecycle

The walkthrough below assumes you've already enrolled a client
app (see [README](../README.md) Enrollment section) and minted
session macaroons for the actions used. Replace `$JOURNEY`,
`$VEHICLE`, `$MAC_WRITE`, `$MAC_READ`, `$CERT` with concrete
values from your enrollment.

### 1. Upload a Vehicle when joining the journey

```bash
curl -sX POST "https://spivot.example/v1/journeys/$JOURNEY/vehicles" \
  --cert "$CERT" --key "$KEY" \
  -H "Authorization: Macaroon $MAC_WRITE" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "...uuid...",
    "owner_user_id": "...your-user-id...",
    "display_name": "Riley'\''s Subaru",
    "make": "Subaru", "model": "Outback", "model_year": 2022,
    "color": "Autumn Green", "capacity": 5,
    "authorized_drivers": ["...your-user-id...", "...partner-user-id..."],
    "acl_version": 1,
    "emergency_rule": {"kind": "any_journey_participant"},
    "integrity": {
      "algorithm": "ecdsa-p256-sha256",
      "key_id": "...your-client-app-id...",
      "signature": "...base64-encoded-asn1-ecdsa-signature-over-canonical-bytes..."
    }
  }'
```

201 on success. The signature covers the canonical encoding of
the Vehicle struct **excluding the `integrity` field itself**
(see opencaravan-go's `CanonicalEncoding` for the rules).

### 2. Publish an ACL revision (add a new authorized driver)

```bash
curl -sX POST "https://spivot.example/v1/journeys/$JOURNEY/vehicles/$VEHICLE/acl-revisions" \
  --cert "$CERT" --key "$KEY" \
  -H "Authorization: Macaroon $MAC_WRITE" \
  -H "Content-Type: application/json" \
  -d '{
    "vehicle_id": "'"$VEHICLE"'",
    "owner_user_id": "...your-user-id...",
    "acl_version": 2,
    "authorized_drivers": ["...you...", "...partner...", "...new-driver..."],
    "effective_time": "2026-06-22T15:00:00Z",
    "integrity": { "...signed over canonical ACL bytes..." }
  }'
```

### 3. Submit a driver attestation (offline handoff, later synced)

```bash
curl -sX POST "https://spivot.example/v1/journeys/$JOURNEY/vehicles/$VEHICLE/driver-attestations" \
  --cert "$CERT" --key "$KEY" \
  -H "Authorization: Macaroon $MAC_WRITE" \
  -H "Content-Type: application/json" \
  -d '{
    "vehicle_id": "'"$VEHICLE"'",
    "segment_id": "...uuid...",
    "driver_user_id": "...your-user-id...",
    "effective_time": "2026-06-22T15:30:00Z",
    "acl_version_consulted": 2,
    "prior_attestation_hash": "sha256:abc...64-hex...",
    "integrity": { "...signed over canonical attestation bytes..." }
  }'
```

The response includes a `trust_flag` (set by the server based on
the ACL at `effective_time`) plus `fork_siblings` if anyone else
claims the same predecessor.

### 4. Query the current driver

```bash
curl -s "https://spivot.example/v1/journeys/$JOURNEY/vehicles/$VEHICLE/current-driver" \
  --cert "$CERT" --key "$KEY" \
  -H "Authorization: Macaroon $MAC_READ"
```

Optionally pass `?at=2026-06-22T15:30:00Z` to query a specific
historical moment.

### 5. Submit telemetry linked to the attestation

```bash
curl -sX POST "https://spivot.example/v1/journeys/$JOURNEY/telemetry" \
  --cert "$CERT" --key "$KEY" \
  -H "Authorization: Macaroon $MAC_TELEMETRY" \
  -H "Content-Type: application/json" \
  -d '{
    "client_batch_id": "batch-001",
    "samples": [...],
    "driver_attestation_hash": "sha256:def...64-hex-of-the-attestation..."
  }'
```

## Curl Walkthrough: Household Garage Sharing

### 1. User A creates a garage

```bash
curl -sX POST "https://spivot.example/v1/garages" \
  --cert "$A_CERT" --key "$A_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "...uuid...",
    "name": "Wheelsdown Household",
    "revision_version": 1,
    "revision_time": "...",
    "owners": [{"user_id": "...A...", "added_time": "...", "accepted_time": "..."}],
    "signed_by": "...A...",
    "integrity": { "...signed by A..." }
  }'
```

### 2. A adds a vehicle to the garage

```bash
curl -sX POST "https://spivot.example/v1/garages/$GARAGE/vehicles" \
  --cert "$A_CERT" --key "$A_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "...uuid...", "garage_id": "'"$GARAGE"'",
    "revision_version": 1, "revision_time": "...",
    "display_name": "Riley'\''s Subaru", "capacity": 5,
    "signed_by": "...A...",
    "integrity": { "...signed by A..." }
  }'
```

### 3. A mints an invite for user B

```bash
curl -sX POST "https://spivot.example/v1/garages/$GARAGE/invites" \
  --cert "$A_CERT" --key "$A_KEY" \
  -H "Content-Type: application/json" \
  -d '{"expires_in_seconds": 86400, "max_redemptions": 1}'
```

Response carries `token` (plaintext, shown once). A shares this
with B via SMS/QR/whatever.

### 4. B redeems

```bash
curl -sX POST "https://spivot.example/v1/garage-invites/redeem" \
  --cert "$B_CERT" --key "$B_KEY" \
  -H "Content-Type: application/json" \
  -d '{"token": "...the-token-A-shared..."}'
```

B is now an accepted owner. Both A and B see the garage in `GET
/v1/garages` and can view + edit its vehicles.

## Operator Concerns

### Reading the audit trail

Driver attestation history for a vehicle:

```bash
curl -s "https://spivot.example/v1/journeys/$JOURNEY/vehicles/$VEHICLE/driver-attestations" \
  --cert "$CERT" --key "$KEY" \
  -H "Authorization: Macaroon $MAC_READ" | jq '.attestations[] | {effective_time, driver_user_id, trust_flag, acl_version_consulted}'
```

Returns every attestation including low-trust rows
(`acl_violation`, `emergency_fallback`) so operators can audit
chain of custody.

### Cert revocation

Revoking a client app's cert (setting `revoked_at` on the
`issued_certificates` row) immediately disables that key for new
signature verifications: `EnrolledCertByClientAppID` filters on
`revoked_at IS NULL`. Existing recorded payloads keep their
canonical bytes — future audit replays can re-verify the
signature against the historical (now-revoked) cert if needed,
since the cert PEM is retained even when revoked. Revocation
doesn't retroactively flip a `trust_flag` on existing
attestations; that's a separate downgrade pass.

### Storage growth

`*_revisions` tables grow monotonically — the protocol's
audit-trail guarantees forbid deletion. For long-running
deployments, plan capacity for the ratio of revisions to head
rows. Typical patterns:

- `journey_vehicles`: ~1 revision per ACL change (rare). 1×.
- `garage_revisions`: ~1 revision per owner add/remove/rename. ~3×.
- `driver_attestations`: 1 row per segment handoff. ~10× per
  journey of moderate length.

`telemetry_batches` rows carry the optional `driver_attestation_hash`
but never carry the attestation bytes themselves — the
correlation happens at query time via the join key.

## Extension Points

The protocol intentionally leaves several extension surfaces open
for future versions. See
[opencaravan-go's extension-points
section](https://github.com/opencaravan/opencaravan-go/blob/main/docs/vehicles.md#extension-points)
for the canonical list. This server's storage shape is forward
compatible with all of them:

- **Cross-journey vehicle linkage** for owners: would add an
  optional `garage_vehicle_ref` column on `journey_vehicles`.
- **Co-signed handoff mode**: would extend `DriverAttestation`
  with a `prior_driver_signature` field and add a verification
  pass at record time. The storage shape already preserves the
  full canonical payload, so the addition is backward
  compatible.
- **Batch attestation upload**: would add a new endpoint that
  accepts N attestations in one POST; the underlying storage
  method is already idempotent on the replay key.
