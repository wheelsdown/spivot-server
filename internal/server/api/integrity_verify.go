package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/opencaravan/opencaravan-go"

	"github.com/wheelsdown/spivot-server/internal/platform/auth/integrity"
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
)

// integrityEnrolledCertLookup is the narrow lookup capability the
// signed-payload handlers need to cross-check that the signer
// named in [opencaravan.Integrity.KeyID] is actually enrolled and
// belongs to the user claimed in the payload. Satisfied by every
// store interface that already exposes EnrolledCertByClientAppID
// (VehicleStore, GarageStore, etc.); the helper accepts the
// narrower type so each handler can pass its own store.
type integrityEnrolledCertLookup interface {
	EnrolledCertByClientAppID(ctx context.Context, clientAppID string) (storage.EnrolledCertRecord, error)
}

// verifySignedPayload runs the full signed-payload verification
// chain a handler needs before persisting:
//
//  1. Confirm the verifier is wired (else 503).
//  2. Resolve the signer's enrolled cert via Integrity.KeyID
//     (else 403 — signer's cert not on file).
//  3. Confirm the resolved cert belongs to the user named in the
//     payload (else 403 — signer doesn't belong to claimed owner).
//  4. Verify the signature against the canonical bytes.
//
// On any failure, the helper writes a Problem response to w and
// returns false. The caller stops further processing on false. On
// success returns true and the caller proceeds to persistence.
//
// The expectedSignerUserID parameter is the payload's claimed
// signer (e.g., vehicle.OwnerUserID, attestation.DriverUserID,
// garage.SignedBy). The check is "the cert that signed this
// payload belongs to that user," which is the protocol's
// cryptographic enforcement of the session-identity check the
// caller already runs.
func verifySignedPayload(
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
	verifier *integrity.Verifier,
	lookup integrityEnrolledCertLookup,
	canonical []byte,
	envelope opencaravan.Integrity,
	expectedSignerUserID string,
	loggerPrefix string,
) bool {
	if verifier == nil {
		writeProblem(w, logger, http.StatusServiceUnavailable, "integrity_unavailable",
			"This server is not configured to verify signed payloads.")
		return false
	}

	certRec, err := lookup.EnrolledCertByClientAppID(r.Context(), envelope.KeyID)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrCertNotEnrolled), errors.Is(err, storage.ErrEnrolledCertMissingPEM):
			logger.Warn(loggerPrefix+": signer cert not enrolled",
				"key_id", envelope.KeyID, "expected_user_id", expectedSignerUserID)
			writeProblem(w, logger, http.StatusForbidden, "signer_not_enrolled",
				"Integrity.key_id does not name an enrolled client app on this server.")
			return false
		default:
			logger.Error(loggerPrefix+": cert lookup failed", "error", err, "key_id", envelope.KeyID)
			writeProblem(w, logger, http.StatusInternalServerError, "internal_error",
				"Could not look up signing certificate.")
			return false
		}
	}
	if certRec.Identity.UserID != expectedSignerUserID {
		logger.Warn(loggerPrefix+": signer/owner mismatch",
			"cert_user_id", certRec.Identity.UserID,
			"payload_user_id", expectedSignerUserID,
			"key_id", envelope.KeyID,
		)
		writeProblem(w, logger, http.StatusForbidden, "signer_owner_mismatch",
			"The signing client app does not belong to the user claimed in the payload.")
		return false
	}

	if err := verifier.VerifyPayload(r.Context(), canonical, envelope); err != nil {
		writeIntegrityVerifyProblem(w, logger, err, loggerPrefix)
		return false
	}
	return true
}

// writeIntegrityVerifyProblem writes the HTTP Problem matching the
// verifier sentinel. Caller has already established that err is
// non-nil.
//
// Status mapping mirrors the precedence list in
// [integrity.Verifier.VerifyPayload]:
//
//   - ErrSignatureMalformed, ErrUnsupportedAlgorithm → 400
//   - ErrKeyIDUnresolved → 403 (already caught earlier by the
//     cert lookup in [verifySignedPayload]; defense in depth here)
//   - ErrSignatureInvalid → 403
//   - ErrEmptyCanonicalPayload, ErrKeyTypeMismatch,
//     ErrResolverTransport → 500 (programmer/config/infra bugs)
//   - anything else → 500
func writeIntegrityVerifyProblem(w http.ResponseWriter, logger *slog.Logger, err error, loggerPrefix string) {
	switch {
	case errors.Is(err, integrity.ErrUnsupportedAlgorithm):
		writeProblem(w, logger, http.StatusBadRequest, "unsupported_algorithm",
			"Integrity.algorithm is not supported by this server.")
	case errors.Is(err, integrity.ErrSignatureMalformed):
		writeProblem(w, logger, http.StatusBadRequest, "signature_malformed",
			"Integrity.signature is not valid base64 or not a well-formed ECDSA signature.")
	case errors.Is(err, integrity.ErrKeyIDUnresolved):
		writeProblem(w, logger, http.StatusForbidden, "signer_not_enrolled",
			"Integrity.key_id does not name an enrolled client app on this server.")
	case errors.Is(err, integrity.ErrSignatureInvalid):
		writeProblem(w, logger, http.StatusForbidden, "signature_invalid",
			"Integrity.signature does not verify against the resolved signing key.")
	default:
		logger.Error(loggerPrefix+": integrity verify failed", "error", err)
		writeProblem(w, logger, http.StatusInternalServerError, "internal_error",
			"Could not verify payload integrity.")
	}
}
