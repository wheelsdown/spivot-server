package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opencaravan/opencaravan-go"

	"github.com/wheelsdown/spivot-server/internal/platform/storage"
)

// driverAttestationTrustResolver evaluates the trust outcome for a
// DriverAttestation. The output mirrors the storage layer's
// [storage.DriverAttestationTrust] enum so the resulting flag can
// be persisted directly.
//
// Resolution order:
//
//  1. Load the VehicleACL revision current at attestation.EffectiveTime.
//     If no ACL exists at or before that time, the attestation cannot
//     be evaluated and the resolver returns an error — the caller
//     should reject with 400 because a v=N attestation against a
//     vehicle whose first ACL is v=M > N is structurally impossible.
//  2. If attestation.DriverUserID ∈ revision.AuthorizedDrivers,
//     classify "authorized".
//  3. Otherwise consult the revision's emergency_rule:
//     - kind = "any_journey_participant" AND driver is a journey
//     participant → "emergency_fallback".
//     - else → "acl_violation".
//
// The resolver does NOT verify cryptographic signatures; that is
// the caller's responsibility (or a future verification phase).
type driverAttestationTrustResolver struct {
	store              VehicleStore
	journeyParticipant journeyParticipantLookup
}

// journeyParticipantLookup is the narrow capability the trust
// resolver needs to confirm an emergency-fallback claimant is
// actually a journey participant. Satisfied by
// [*storage.Store] via duck-typing.
type journeyParticipantLookup interface {
	JourneyParticipantByUserAndJourney(ctx context.Context, userID, journeyID string) (storage.JourneyParticipant, error)
}

// classifyDriverAttestation resolves the trust flag for the
// supplied attestation against the vehicle's ACL history.
//
// journeyID identifies the journey the vehicle belongs to; it is
// required for the emergency-fallback path which checks the
// driver is a journey participant. vehicleOwnerUserID is supplied
// so the resolver can short-circuit when the driver IS the owner
// (the owner is implicitly authorized regardless of whether they
// also appear in AuthorizedDrivers).
func (r *driverAttestationTrustResolver) classify(ctx context.Context, journeyID, vehicleOwnerUserID string, attestation opencaravan.DriverAttestation) (storage.DriverAttestationTrust, error) {
	rev, err := r.store.JourneyVehicleACLAt(ctx, string(attestation.VehicleID), attestation.EffectiveTime)
	if err != nil {
		return "", fmt.Errorf("load acl at %s: %w", attestation.EffectiveTime, err)
	}

	driverID := string(attestation.DriverUserID)

	// Owner is implicitly authorized — an owner who omits themselves
	// from AuthorizedDrivers (a user error or a "no driver permission
	// yet" intermediate state) is still authorized to drive their
	// own vehicle. The protocol's owner-signed ACL invariant makes
	// the owner the root of all permission anyway.
	if driverID == vehicleOwnerUserID {
		return storage.DriverAttestationTrustAuthorized, nil
	}

	var authorized []opencaravan.UUID
	if err := json.Unmarshal([]byte(rev.AuthorizedDriversJSON), &authorized); err != nil {
		return "", fmt.Errorf("decode authorized_drivers at v=%d: %w", rev.ACLVersion, err)
	}
	for _, d := range authorized {
		if string(d) == driverID {
			return storage.DriverAttestationTrustAuthorized, nil
		}
	}

	// Driver is NOT in the ACL. Consult emergency_rule.
	if rev.EmergencyRuleKind != string(opencaravan.VehicleEmergencyRuleAnyJourneyParticipant) {
		return storage.DriverAttestationTrustACLViolation, nil
	}
	participant, err := r.journeyParticipant.JourneyParticipantByUserAndJourney(ctx, driverID, journeyID)
	if err != nil {
		if errors.Is(err, storage.ErrJourneyParticipantNotFound) {
			return storage.DriverAttestationTrustACLViolation, nil
		}
		return "", fmt.Errorf("load journey participant for emergency fallback: %w", err)
	}
	// A "left" or "removed" participant is no longer eligible for
	// the emergency path. v0 only treats currently-joined
	// participants as fallback-eligible.
	if participant.State != "joined" {
		return storage.DriverAttestationTrustACLViolation, nil
	}
	return storage.DriverAttestationTrustEmergencyFallback, nil
}
