package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/opencaravan/opencaravan-go"
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
)

// leafCertificateLifetime is the validity window the enrollment handler
// asks the CA to issue for every leaf client-app certificate. Short
// enough that revocation reduces to "stop renewing" and a compromised
// device cannot keep talking to the server indefinitely without
// re-enrollment; long enough that a vehicle off-grid for a long weekend
// can still renew without the user noticing.
const leafCertificateLifetime = 7 * 24 * time.Hour

// handleClientAppEnroll implements POST /v1/client-apps/enroll.
//
// The flow:
//
//  1. Decode and protocol-validate the [opencaravan.ClientAppEnrollmentRequest].
//  2. Look up the invite (read-only) to confirm scope and redeemability
//     before doing any CSR parsing — a malformed CSR after consuming
//     the invite would waste the operator's single-use token.
//  3. Parse the PEM-wrapped CSR, verify its self-signature, and reject
//     non-P-256-ECDSA keys at the protocol boundary.
//  4. Mint a new UserID and ClientAppID locally so the response can be
//     constructed before the transaction commits.
//  5. Ask the CA to sign a leaf certificate over the CSR's public key.
//  6. Call [EnrollmentStore.RegisterClientApp] to atomically write the
//     four-table state change (accounts, client_apps, invite consume,
//     issued_certificates).
//  7. Return [opencaravan.ClientAppEnrollmentResponse] with the leaf
//     and the CA chain so the client can pin the CA root.
//
// The Phase 3a handler accepts only server_registration-scoped invites.
// Journey-scoped invites are reserved for a later phase that registers
// a new app under an existing user; they return 422 here.
//
// Failures map to:
//
//   - 400 for malformed JSON, validation errors, malformed CSR, or
//     wrong key algorithm.
//   - 404 when the invite token does not exist.
//   - 409 when the invite has been used.
//   - 410 when the invite has expired.
//   - 422 when the invite scope is not server_registration.
//   - 503 when the EnrollmentStore or CA dependency is not wired
//     (deployment misconfiguration).
//   - 500 for unexpected storage or signing failures, with the
//     underlying error logged but not exposed to the caller.
func (s *Server) handleClientAppEnroll(w http.ResponseWriter, r *http.Request) {
	if s.cfg.EnrollmentStore == nil || s.cfg.CA == nil {
		s.logger.Warn("enroll: handler unavailable; EnrollmentStore or CA not wired")
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "enrollment_unavailable",
			"This server is not configured to accept client app enrollments.")
		return
	}

	var req opencaravan.ClientAppEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode enrollment request body: %s", err))
		return
	}
	if err := req.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Enrollment request did not validate: %s", err))
		return
	}

	invite, err := s.cfg.EnrollmentStore.LookupInvite(r.Context(), req.InviteToken)
	switch {
	case errors.Is(err, storage.ErrInviteNotFound):
		writeProblem(w, s.logger, http.StatusNotFound, "invite_not_found",
			"The provided invite token is not known to this server.")
		return
	case errors.Is(err, storage.ErrInviteAlreadyUsed):
		writeProblem(w, s.logger, http.StatusConflict, "invite_already_used",
			"The provided invite token has already been redeemed.")
		return
	case errors.Is(err, storage.ErrInviteExpired):
		writeProblem(w, s.logger, http.StatusGone, "invite_expired",
			"The provided invite token has expired.")
		return
	case err != nil:
		s.logger.Error("enroll: invite lookup failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not look up the invite.")
		return
	}

	if invite.Scope != opencaravan.InviteScopeServerRegistration {
		writeProblem(w, s.logger, http.StatusUnprocessableEntity, "invite_scope_mismatch",
			fmt.Sprintf("Enrollment requires a server_registration invite; the supplied invite is scoped %q.", invite.Scope))
		return
	}

	csr, err := parseClientAppCSR(req.CSRPEM)
	if err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_csr", err.Error())
		return
	}

	userID, err := opencaravan.NewUUID()
	if err != nil {
		s.logger.Error("enroll: mint user id", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not generate identifiers for the new account.")
		return
	}
	clientAppID, err := opencaravan.NewUUID()
	if err != nil {
		s.logger.Error("enroll: mint client app id", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not generate identifiers for the new client app.")
		return
	}

	leaf, leafPEM, err := s.cfg.CA.Sign(r.Context(), csr, leafCertificateLifetime)
	if err != nil {
		s.logger.Error("enroll: CA sign failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not sign the leaf certificate.")
		return
	}

	reg := storage.ClientAppRegistration{
		UserID:               string(userID),
		UserDisplayName:      req.DisplayName,
		OpenCaravanID:        string(userID),
		ClientAppID:          string(clientAppID),
		ClientAppDisplayName: req.DisplayName,
		InviteTokenValue:     req.InviteToken,
		Certificate:          leaf,
	}
	if _, err := s.cfg.EnrollmentStore.RegisterClientApp(r.Context(), reg); err != nil {
		switch {
		case errors.Is(err, storage.ErrInviteAlreadyUsed):
			writeProblem(w, s.logger, http.StatusConflict, "invite_already_used",
				"The provided invite token was redeemed concurrently with this request.")
		case errors.Is(err, storage.ErrInviteExpired):
			writeProblem(w, s.logger, http.StatusGone, "invite_expired",
				"The provided invite token expired between lookup and redemption.")
		default:
			s.logger.Error("enroll: register client app failed", "error", err)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Could not persist the enrollment.")
		}
		return
	}

	enrollment := opencaravan.ClientAppEnrollment{
		ID:               clientAppID,
		UserID:           userID,
		CertificateChain: []string{string(leafPEM)},
		IssuedTime:       leaf.NotBefore.UTC(),
		NotAfter:         leaf.NotAfter.UTC(),
	}
	caChain := []string{string(s.cfg.CA.CertificatePEM())}

	resp := opencaravan.NewClientAppEnrollmentResponse(enrollment, caChain)

	s.logger.Info("client app enrolled",
		"user_id", userID,
		"client_app_id", clientAppID,
		"display_name", req.DisplayName,
		"cert_serial", leaf.SerialNumber.Text(16),
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
	)

	writeJSONStatus(w, http.StatusCreated, resp, s.logger)
}

// parseClientAppCSR decodes the PEM-wrapped PKCS#10 CSR carried in the
// enrollment request, verifies its self-signature, and rejects keys
// whose algorithm does not match the protocol's P-256 ECDSA
// requirement.
//
// Protocol-level Validate on [opencaravan.ClientAppEnrollmentRequest]
// only confirms the PEM block label. This parser enforces the deeper
// shape: a real PKCS#10 with a valid signature over a P-256 public
// key. Anything weaker is rejected before the CA ever sees it.
func parseClientAppCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr_pem must be a CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature did not verify: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("CSR public key must be ECDSA; got %T", csr.PublicKey)
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("CSR public key must be on curve P-256; got %s", pub.Curve.Params().Name)
	}
	return csr, nil
}

// writeProblem emits a JSON error body following the spirit of RFC 7807
// (application/problem+json) so clients see a structured, parseable
// failure rather than a free-form string. The fields are deliberately
// minimal: status, code, detail. Title can be added per-call if a
// human-readable summary is useful; the code field is the machine
// reading.
func writeProblem(w http.ResponseWriter, logger interface{ Error(string, ...any) }, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{
		"status": status,
		"code":   code,
		"detail": detail,
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// Body already half-written; the logger sees the encode failure
		// for operator diagnostics but the client gets whatever made it
		// onto the wire.
		logger.Error("write problem response", "error", err)
	}
}
