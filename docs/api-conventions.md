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
- **One concept, one name.** The vehicle exists once, as `Vehicle`.
  There is no `JourneyVehicle` and no `GarageVehicle` — not as a
  model, not as an operationId. Containment is a relationship
  expressed by paths and thin signed statements, never by forking
  the entity. See "The vehicle topology" below.

## The vehicle topology

A vehicle is a platonic, atomic entity in OpenCaravan: a profile
(display name, make, model, year, color, capacity, photos, notes)
owned by a user, with its own signed revision chain, verifiable
standalone. Garages contain vehicles; journeys engage them. Neither
containment owns the vehicle or mints a new vehicle type.

**Entity** — vehicles live at their own address, independent of any
container:

```
vehicleCreate          POST /v1/vehicles
vehicleList            GET  /v1/vehicles                  (the caller's)
vehicleGet             GET  /v1/vehicles/{id}
vehicleRevisionAppend  POST /v1/vehicles/{id}/revisions   (owner-signed)
```

The protocol `Vehicle` payload is already entity-shaped (owner,
profile, revision chain) — it is the one vehicle model. The server's
view is the one `VehicleRecord`.

**Relationships** — two thin signed statements reference a vehicle by
id; neither carries a copy of the profile:

- `VehicleEngagement` — "I bring vehicle V to journey J", signed by
  the engaging participant. Journey-scoped concerns (the ACL for this
  trip, driver attestations, telemetry linkage) attach to the
  engagement, addressed by the vehicle's id within the journey path.
- `VehiclePlacement` — "vehicle V is in garage G's library", signed
  by an accepted garage owner.

`GarageVehicle` is deleted from the protocol. Its duplicated profile
fields are the fracture this design removes.

**Reads in context** return `VehicleRecord` — the same model
everywhere — with a small context object describing the relationship
(`EngagementContext`: journey id, current ACL version, engaged-by/at;
`PlacementContext`: garage id, placed-by/at). Contextual reads use
adjective-marked operationIds so no compound vehicle noun exists:

```
vehicleEngage       POST /v1/journeys/{id}/vehicles     body: vehicle_id + VehicleEngagement + initial VehicleACL
engagedVehicleList  GET  /v1/journeys/{id}/vehicles
engagedVehicleGet   GET  /v1/journeys/{id}/vehicles/{vid}
vehicleACLAppend    POST /v1/journeys/{id}/vehicles/{vid}/acl-revisions
driverAttestationRecord / driverAttestationList / currentDriverGet   (unchanged paths)

vehiclePlace        POST /v1/garages/{id}/vehicles      body: vehicle_id + VehiclePlacement
placedVehicleList   GET  /v1/garages/{id}/vehicles
placedVehicleGet    GET  /v1/garages/{id}/vehicles/{vid}
```

Topology consequences, stated plainly:

- **Vehicle revisions happen in one place** — `/v1/vehicles/{id}/revisions`,
  owner-signed. The 0.1 garage-side revision endpoint (any accepted
  owner edits the garage's copy) is deleted; garages contain
  vehicles, they do not edit them. A profile update propagates to
  every context because there is only one vehicle.
- **Engage and place take references.** Clients create a vehicle
  once, then engage/place it by id. The 0.1 create-inline-in-journey
  flow is deleted with the rest of the compat surface.
- **The engagement is where journey-vehicle features grow** (per-stage
  assignments in the multi-stage journey phase attach to
  `EngagementContext` / the engagement statement, not to a vehicle
  subtype).

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
| `Engage` | bind an existing entity into a journey by signed statement       |
| `Place`  | bind an existing entity into a garage by signed statement        |

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
  *is* its metadata) and lives only at the entity's own address,
  `/v1/vehicles/{id}/revisions`. The journey-scoped authorization
  chain is the qualified `/acl-revisions` under the engagement path.

## Compatibility posture

**Backwards compatibility is explicitly a non-goal.** There are no
legacy implementations to protect; the objective is an API surface
that is correct and extensible, decided once. Schema names,
operationIds, paths, and wire-level JSON field names all change
wherever the better name exists — no aliases, no deprecation
shims, no migration paths. Contract version goes to `0.2.0`; the
compatibility ratchet starts at the 1.0 freeze, not before.

## The rename table

The table lists schema (component), operationId, and path changes.
JSON field renames are decided case-by-case during the pass under
the same principles — the table is not exhaustive on fields.

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

| Current                             | Proposed                  | Kind      |
|-------------------------------------|---------------------------|-----------|
| `JourneyResponse`                   | `Journey`                 | native    |
| `TelemetryBatchResponse`            | `TelemetryBatchReceipt`   | native    |
| `JourneyVehicleResponse`            | `VehicleRecord` (+ `EngagementContext`) | record |
| `GarageVehicleResponse`             | `VehicleRecord` (+ `PlacementContext`)  | record |
| `JourneyVehicleListResponse` / `GarageVehicleListResponse` | `VehicleList` | native |
| `JourneyVehicleCreateRequest`       | `VehicleEngageRequest`    | request   |
| — *(new)*                           | `VehiclePlaceRequest`     | request   |
| — *(new, protocol)*                 | `VehicleEngagement`       | statement |
| — *(new, protocol)*                 | `VehiclePlacement`        | statement |
| `GarageVehicle` *(protocol)*        | **deleted** — the fracture this pass removes | — |
| `JourneyVehicleACLRevisionResponse` | `VehicleACLRecord`        | record    |
| `JourneyVehicleRevisionResponse`    | `VehicleRevisionRecord`   | record    |
| `DriverAttestationResponse`         | `DriverAttestationRecord` | record    |
| `DriverAttestationForkSibling`      | `AttestationForkSibling`  | native    |
| `DriverAttestationListResponse`     | `DriverAttestationList`   | native    |
| `CurrentDriverResponse`             | `CurrentDriver`           | native    |

### Models — garages

| Current                             | Proposed                          | Kind    |
|-------------------------------------|-----------------------------------|---------|
| `GarageResponse`                    | `GarageRecord`                    | record  |
| `GarageOwnerResponse`               | `GarageOwnerRecord`               | record  |
| `GarageListResponse`                | `GarageList`                      | native  |
| `GarageRevisionAppendResponse`      | `GarageRevisionRecord`            | record  |
| `GarageOwnershipAcceptanceResponse` | `GarageOwnershipAcceptanceRecord` | record  |
| `GarageInviteResponse`              | `GarageInvite`                    | native  |
| `GarageInviteListResponse`          | `GarageInviteList`                | native  |
| `GarageInviteRedeemResponse`        | `GarageInviteRedemption`          | native  |

(Garage vehicle models are covered by the vehicle topology above —
they cease to exist as garage-flavored types.)

### Operations and paths

| Current                                  | Proposed                                   |
|------------------------------------------|--------------------------------------------|
| `clientAppEnroll` / `POST /v1/client-apps/enroll` | `enrollmentCreate` / `POST /v1/enrollments` |
| `clientAppInviteCreate` / `POST /v1/client-apps/invites` | `registrationInviteCreate` / `POST /v1/registration-invites` |
| `clientAppInviteList` / `GET /v1/client-apps/invites` | `registrationInviteList` / `GET /v1/registration-invites` |
| — *(new)* | `vehicleCreate` / `POST /v1/vehicles` |
| — *(new)* | `vehicleList` / `GET /v1/vehicles` |
| — *(new)* | `vehicleGet` / `GET /v1/vehicles/{id}` |
| — *(new)* | `vehicleRevisionAppend` / `POST /v1/vehicles/{id}/revisions` |
| `journeyVehicleCreate` | `vehicleEngage` (same path; body becomes a reference + engagement) |
| `journeyVehicleList` / `journeyVehicleGet` | `engagedVehicleList` / `engagedVehicleGet` (same paths) |
| `journeyVehicleACLAppend` | `vehicleACLAppend` (same path) |
| `journeyVehicleRevisionAppend` / `POST …/journeys/{id}/vehicles/{vid}/revisions` | **deleted** — revisions live at `/v1/vehicles/{id}/revisions` |
| `garageVehicleCreate` | `vehiclePlace` (same path; body becomes a reference + placement) |
| `garageVehicleList` / `garageVehicleGet` | `placedVehicleList` / `placedVehicleGet` (same paths) |
| `garageVehicleRevisionAppend` / `POST …/garages/{id}/vehicles/{vid}/revisions` | **deleted** — garages contain vehicles, they do not edit them |

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

One coordinated pass across both repos — nothing here is deferred to
a later phase:

1. **This document** — maintainer reviews; the tables above are the
   decision of record.
2. **opencaravan-go** (protocol 0.2): delete `GarageVehicle`; add
   `VehicleEngagement` and `VehiclePlacement`; rename
   `SessionResponse` → `SessionGrant` and
   `ClientAppEnrollmentResponse` → `EnrollmentGrant`; field docs land
   on every type this pass touches.
3. **spivot-server** (contract 0.2.0), against the new module: the
   full vehicle topology (`/v1/vehicles`, engage/place by reference,
   contextual reads, single revision chain), every rename in the
   tables, and the guardrails — in the same pass, not after it.
   Storage schema changes as needed with **no data migration**
   (pre-1.0 posture; the deployed pre-0.2 data set is expendable —
   coordinate the reset with the operator, which is the one
   deployment that exists).
4. The journey-expansion phase starts only on the settled surface.
