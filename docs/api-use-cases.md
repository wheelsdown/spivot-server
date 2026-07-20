# API Use-Case Walkthroughs

The validation harness for the API surface: real tasks walked
end-to-end through the (post-#52) contract, each with an honest
verdict. The test for every scenario is the #52 goal — can a
newcomer, human or agent, predict these calls from the names alone?

Verdicts:

- **SANE** — the calls exist and read the way a newcomer would guess.
- **AWKWARD** — possible, but requires tribal knowledge or reads
  wrong; feeds the #52 execution pass.
- **GAP** — no surface exists; feeds the journey-expansion roadmap.

This is a living document. Scenarios are cheap — when a design
question comes up, add the scenario here first and walk it.

## Arc 1 — Onboarding

### 1.1 First operator brings up a server

Boot container → bootstrap invite banner → `enrollmentCreate` with
invite + CSR → `EnrollmentGrant` (leaf cert + pinned CA chain) →
`sessionCreate`. **SANE.** The bootstrap path is documented and
self-narrating in the container logs.

### 1.2 Enrolled user invites a friend

`registrationInviteCreate` → hand token out-of-band → friend's app
`enrollmentCreate` redeems it. **SANE** post-rename ("registration
invite" says what it does; "client-app invite" did not).

### 1.3 Same user adds a second device (new phone, iPad)

**GAP.** Enrollment only mints new users; the
register-an-app-under-an-existing-user path is explicitly deferred
(422 today). A real user has two devices in week one. Needs: an
identity-scoped enrollment flow (existing user authorizes a new
client app, e.g. a device invite minted from an enrolled session).

### 1.4 User loses a phone

Server-side revocation exists (revoke the issued cert row), but only
via operator/CLI. **GAP** for self-service: "sign out my lost
device" wants an API surface eventually.

## Arc 2 — Vehicles and the household

### 2.1 Create your truck

`vehicleCreate` with a signed `Vehicle` payload. **SANE** — the
entity has its own home; no journey or garage required to exist
first (this is the fix #52 makes; in 0.1 a vehicle could only be
born inside a container).

### 2.2 Update the photo after a wash

`vehicleRevisionAppend`. Supersession means every garage and journey
sees the new photo immediately. **SANE.**

### 2.3 Share the truck's administration with your spouse

Append a revision whose administrators list adds the spouse.
**AWKWARD — one open design point**: does the spouse accept
administration (two-phase, like garage ownership), or is the grant
unilateral? Garage precedent says acceptance ("nobody becomes
responsible by someone else's signature alone") — administration
carries the same responsibility flavor. Decide in #52 execution;
lean acceptance for consistency.

### 2.4 The household garage

`garageCreate` → revision naming spouse as co-owner →
`garageOwnershipAccept` by spouse → `vehiclePlace` both cars.
**SANE**, and the acceptance flow's why is documented on the
schemas.

### 2.5 Take a vehicle OUT of the garage

**GAP — and it feeds #52 execution, not the backlog.** The proposed
surface creates relationships (`vehiclePlace`, `vehicleEngage`) with
no way to end them: no unplace, no disengage. Sell a car, leave a
convoy early, break down and get towed — relationship teardown is
half of every relationship's lifecycle. Designing the statement
(`VehiclePlacement`/`VehicleEngagement`) without its termination
semantics would recreate the accretive smell #52 exists to remove.
Likely shape: a signed release statement (or a terminal revision of
the placement/engagement), verb `Release`, paths
`…/vehicles/{vid}/release`.

### 2.6 Sell the truck to a stranger

Administration is delegable, but is creatorship transferable?
**GAP (acknowledged, deferred)** — full ownership transfer between
users is a real eventual flow; out of scope for this pass, noted so
the administrators design doesn't foreclose it.

## Arc 3 — Journey preparation

### 3.1 Host plans a trip

`journeyCreate` (title, description). **SANE** as far as it goes —
but journeys are created `planned` and nothing can ever change that.

### 3.2 Invite the crew

**GAP.** `journey_invites` has existed in the schema since migration
000001 and has zero API surface. There is no way for anyone but the
host to be *in* a journey today (the host is the only participant
row ever created). The whole participant lifecycle — invite, join,
consent, leave — is unexposed. This is the front door of the
journey-expansion phase, and the garage-invite pattern (mint,
show-once token, redeem, revoke) is the proven template to mirror:
predictability comes from reusing the shape.

### 3.3 Bring your vehicle

`vehicleEngage` (vehicle_id + engagement + initial `DriverACL`).
**SANE** post-#52: create once, engage by reference; the DriverACL
name makes "who may drive on this trip" unmistakable.

### 3.4 Pre-authorize your co-driver

Initial `DriverACL` lists the co-driver, or `driverACLAppend` later.
**SANE.**

### 3.5 Start the trip

**GAP.** No journey state transitions (`planned → active → closed`).
The protocol defines the states; the schema stores them; no
operation moves them. Needs design attention in expansion: state
transitions interact with retention (`deletion_time`) and telemetry
acceptance windows.

### 3.6 Plan the stages (day 1, overnight, day 2)

**GAP.** `journey_segments` is in the schema; driver attestations
already carry `segment_id` — pointing at rows nothing can create.
Multi-stage structure is the headline feature of the expansion
phase; the engagement (`EngagementContext`) is where per-stage
vehicle assignment will attach, per the topology doc.

## Arc 4 — On the road

### 4.1 Swap drivers at a rest stop

`driverAttestationRecord`, signed by the incoming driver; server
evaluates against the DriverACL in effect at that moment; gossiped
duplicates return 200. **SANE** — this flow is the design's best
self-advertisement: peer-signed, at-time evaluation, fork-visible.

### 4.2 Emergency: an unlisted participant must drive

Same call; server records `emergency_fallback` per the DriverACL's
emergency rule. Evidence retained, trust downgraded, nobody blocked
in a crisis. **SANE.**

### 4.3 Stream positions

`telemetryBatchRecord` with client batch idempotency. **SANE** for
the write half.

### 4.4 "Where is everyone?"

**GAP — the loudest one.** Telemetry is write-only. There is no read
surface for positions at all: no per-journey latest-positions query,
no participant track history. The core promise of coordinating a
group drive — see your convoy on a map — has no API. (Storage
currently persists batch envelopes without expanding samples; the
read surface and sample expansion land together.)

### 4.5 "Who's driving the truck right now?"

`currentDriverGet` (optionally `?at=`), fork siblings surfaced.
**SANE** — and the at-time query shape is the template 4.4's reads
should follow for predictability.

### 4.6 Vehicle breaks down mid-journey

Tow truck comes; the vehicle leaves the journey. **GAP** — same
teardown hole as 2.5 (`Release`), plus an open interaction: what
happens to an active DriverACL and pending attestation chain when
the engagement ends? Termination semantics must say.

## Arc 5 — Wind-down

### 5.1 The trip ends

**GAP** — journey close is a state transition (3.5).

### 5.2 The record of the trip

Attestation and telemetry history remain queryable per journey
(`driverAttestationList`, 4.4's future reads); retention mode
(`ephemeral`, `deletion_time`) is stored but nothing enforces or
exposes it. **GAP (expansion)**: retention policy needs an
operation surface and an enforcement job before the ecosystem can
trust "ephemeral" to mean anything.

## Findings summary

**Feeds #52 execution (design now, with the statements):**

- Relationship teardown — `Release` verb; termination semantics for
  `VehiclePlacement` and `VehicleEngagement`, including what happens
  to a live DriverACL/attestation chain on disengage (2.5, 4.6).
- Vehicle administration grants: acceptance required or unilateral
  (2.3). Lean: acceptance, matching garage ownership.

**Journey-expansion roadmap (the next phase, in dependency order):**

1. Participant lifecycle: journey invites (mirror the garage-invite
   template), join/consent, leave (3.2).
2. Journey state machine: planned → active → closed, with retention
   interaction (3.5, 5.1).
3. Segments: create/list, per-stage vehicle assignment via the
   engagement (3.6).
4. Position reads: latest-per-participant and track queries,
   at-time shaped like `currentDriverGet` (4.4); telemetry sample
   expansion lands with them.
5. Multi-device identity: enroll an additional client app under an
   existing user; lost-device self-revocation (1.3, 1.4).
6. Retention enforcement and its operation surface (5.2).

**Deferred, noted so nothing forecloses it:** vehicle ownership
transfer (2.6).
