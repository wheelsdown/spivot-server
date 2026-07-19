# API Naming Conventions

The rulebook for issue #52: how models, operations, and paths are
named so that a human or agent new to the project can open `/docs/`
and infer intent and topology from the names alone. Spivot's naming
decisions are authoritative for the OpenCaravan protocol at this
stage; opencaravan-go conforms (its tracking issue mirrors this
document).

## The three kinds of model

Every schema in the contract is exactly one of these, and its name
says which:

1. **Signed statements** — portable protocol payloads bearing an
   `Integrity` envelope, signed by the participant with the authority
   to make them. They are the primary objects of the peer-coordinated
   design: any peer can verify them with no server in the path.
   *Named as clean protocol nouns*: `Vehicle`, `VehicleACL`,
   `DriverAttestation`, `Garage`, `GarageOwnershipAcceptance`.
2. **Server records** — this server's view of a signed statement or
   chain of them: reception metadata (`received_at`), head pointers,
   derived judgments (`trust_flag`), materialized projections.
   *Named `<Noun>Record`*: `GarageRecord`, `DriverAttestationRecord`.
   The suffix teaches the split: a `DriverAttestation` is what the
   driver signed; a `DriverAttestationRecord` is what this server
   knows about it. (This also matches the internal storage
   vocabulary, which already uses `Record` for these rows.)
3. **Server-native resources** — things with no signed counterpart:
   system surface, capabilities, invites the server mints, receipts.
   *Named as clean nouns*: `Journey`, `RegistrationInvite`,
   `Health`, `Problem`.

Corollaries:

- **No `Response` suffix, ever.** It describes transport, not domain.
  `Request` survives only on true request-only shapes (bodies that
  exist solely to parameterize an operation), and those are named
  resource-first to match their operationIds:
  `JourneyCreateRequest`, `GarageInviteRedeemRequest`.
- **List envelopes are `<Noun>List`.** They stay named types (the
  envelope lets future phases add pagination without breaking
  clients), but they earn no more name than that.
- **One concept, one name.** The vehicle profile (make, model, year,
  color, capacity, photos) exists once, as `Vehicle`. Putting a
  vehicle in a garage or engaging it in a journey is a *placement* —
  a thin signed statement referencing the vehicle — not a new
  vehicle type. (Protocol 0.2 work, tracked upstream; see Staging.)

## The verb vocabulary

OperationIds are `<resource><Verb>`, resource-first, with verbs drawn
only from this table. `ValidateRoutes` enforces the suffix.

| Verb     | Semantics                                                        |
|----------|------------------------------------------------------------------|
| `Create` | make a new server resource; 201; not idempotent                  |
| `Get`    | read one resource                                                |
| `List`   | read a collection                                                |
| `Append` | advance a signed revision chain; version must strictly increase  |
| `Record` | idempotent ingest of a peer-signed statement; gossiped replays return the existing record with 200 |
| `Accept` | counter-sign a pending grant (ownership); idempotent replay 200  |
| `Redeem` | consume a capability token; the token is the authority           |
| `Revoke` | cancel an outstanding capability; idempotent                     |

If an operation doesn't fit a verb, that's a design conversation, not
a new verb.

## Paths

- Paths mirror containment, and every path segment names a resource
  that exists. No segment lives only to justify its children.
- Capability lifecycle actions (`redeem`, `revoke`) may be verb
  subpaths (`…/invites/{id}/revoke`, `…/garage-invites/redeem`) —
  they act on a capability rather than address a resource, and
  `redeem` deliberately keeps its token out of the URL.
- A vehicle's bare `/revisions` chain is its metadata (the vehicle
  *is* its metadata); the authorization chain is the qualified
  `/acl-revisions`.

## The rename table

Wire-level JSON field names do not change in this pass; these are
schema (component), operationId, and path changes only. Contract
version goes to `0.2.0`.

### Models — system and identity

| Current                        | Proposed                        | Kind    |
|--------------------------------|---------------------------------|---------|
| `RootResponse`                 | `ServerBanner`                  | native  |
| `HealthResponse`               | `Health`                        | native  |
| `ReadinessResponse`            | `Readiness`                     | native  |
| `VersionResponse`              | `VersionInfo`                   | native  |
| `ServerInfoResponse`           | `ServerInfo`                    | native  |
| `ProblemResponse`              | `Problem`                       | native  |
| `ClientAppInviteCreateRequest` | `RegistrationInviteCreateRequest` | request |
| `ClientAppInviteResponse`      | `RegistrationInvite`            | native  |
| `ClientAppInviteListResponse`  | `RegistrationInviteList`        | native  |
| `SessionResponse` *(upstream)* | `SessionGrant`                  | native  |
| `ClientAppEnrollmentResponse` *(upstream)* | `EnrollmentGrant`   | native  |

(`ImplementationInfo`, `ProtocolInfo`, `ServerCapabilities` family,
`ServerPolicySnapshot`, `SessionRequest`, `ClientAppEnrollmentRequest`,
`ClientAppEnrollment`, `KeyAttestation` are already right.)

### Models — journeys and vehicles

| Current                             | Proposed                  | Kind    |
|-------------------------------------|---------------------------|---------|
| `JourneyResponse`                   | `Journey`                 | native  |
| `TelemetryBatchResponse`            | `TelemetryBatchReceipt`   | native  |
| `JourneyVehicleResponse`            | `JourneyVehicleRecord`    | record  |
| `JourneyVehicleListResponse`        | `JourneyVehicleList`      | native  |
| `JourneyVehicleACLRevisionResponse` | `VehicleACLRecord`        | record  |
| `JourneyVehicleRevisionResponse`    | `VehicleRevisionRecord`   | record  |
| `DriverAttestationResponse`         | `DriverAttestationRecord` | record  |
| `DriverAttestationForkSibling`      | `AttestationForkSibling`  | native  |
| `DriverAttestationListResponse`     | `DriverAttestationList`   | native  |
| `CurrentDriverResponse`             | `CurrentDriver`           | native  |

### Models — garages

| Current                             | Proposed                          | Kind    |
|-------------------------------------|-----------------------------------|---------|
| `GarageResponse`                    | `GarageRecord`                    | record  |
| `GarageOwnerResponse`               | `GarageOwnerRecord`               | record  |
| `GarageListResponse`                | `GarageList`                      | native  |
| `GarageRevisionAppendResponse`      | `GarageRevisionRecord`            | record  |
| `GarageOwnershipAcceptanceResponse` | `GarageOwnershipAcceptanceRecord` | record  |
| `GarageVehicleResponse`             | `GarageVehicleRecord`             | record  |
| `GarageVehicleListResponse`         | `GarageVehicleList`               | native  |
| `GarageInviteResponse`              | `GarageInvite`                    | native  |
| `GarageInviteListResponse`          | `GarageInviteList`                | native  |
| `GarageInviteRedeemResponse`        | `GarageInviteRedemption`          | native  |

### Operations and paths

| Current                                  | Proposed                                   |
|------------------------------------------|--------------------------------------------|
| `clientAppEnroll` / `POST /v1/client-apps/enroll` | `enrollmentCreate` / `POST /v1/enrollments` |
| `clientAppInviteCreate` / `POST /v1/client-apps/invites` | `registrationInviteCreate` / `POST /v1/registration-invites` |
| `clientAppInviteList` / `GET /v1/client-apps/invites` | `registrationInviteList` / `GET /v1/registration-invites` |

All other operationIds already follow `<resource><Verb>` with table
verbs and keep their paths. `/v1/garage-invites/redeem` stays (see
Paths).

## Guardrails

Landed with the rename pass, so the convention is enforced rather
than aspirational — the same pattern as the missing-doc error and
the tag-group check:

- `ValidateRoutes`: operationId must end in a vocabulary verb.
- Generator: component names ending in `Response` fail generation.
- Generator: a component name colliding across the statement/record
  boundary (same noun for both kinds) fails generation.

## Staging

1. **This document** — maintainer reviews the table; renames here are
   the decision of record.
2. **Server pass** (contract `0.2.0`): Go type renames + route table
   updates + guardrails. Schema names follow Go type names through
   the generator automatically; one PR, mechanical after the table is
   agreed.
3. **Upstream pass** (opencaravan-go, protocol 0.2): `SessionGrant` /
   `EnrollmentGrant` renames, then the substantive redesign — the
   platonic `Vehicle` entity plus signed placement payloads replacing
   `GarageVehicle`'s duplicated profile. Spivot consumes the new
   module and regenerates; the spec follows.
4. **Then** the journey-expansion phase builds on the settled
   vocabulary.
