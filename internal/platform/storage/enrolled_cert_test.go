package storage

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// enrollFresh runs the full RegisterClientApp flow used by other
// enrollment tests. Returns the (client_app_id, user_id) pair that
// was enrolled — both as plain strings — so the caller can use
// them in subsequent EnrolledCertByClientAppID lookups and FK
// references.
func enrollFresh(t *testing.T, store *Store) (clientAppID, userID string) {
	t.Helper()
	ctx := context.Background()
	token, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	uid := "user-" + t.Name()
	appID := "client-app-" + t.Name()
	cert := syntheticLeaf(t, appID)
	if _, err := store.RegisterClientApp(ctx, ClientAppRegistration{
		UserID:               uid,
		UserDisplayName:      "Riley",
		OpenCaravanID:        uid,
		ClientAppID:          appID,
		ClientAppDisplayName: "Riley's Device",
		InviteTokenValue:     token.Value,
		Certificate:          cert,
	}); err != nil {
		t.Fatalf("RegisterClientApp: %v", err)
	}
	return appID, uid
}

func TestEnrolledCertByClientAppIDRoundTripsParsedCert(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	appID, userID := enrollFresh(t, store)

	rec, err := store.EnrolledCertByClientAppID(ctx, appID)
	if err != nil {
		t.Fatalf("EnrolledCertByClientAppID: %v", err)
	}
	if rec.Identity.ClientAppID != appID {
		t.Fatalf("client_app_id: got %q want %q", rec.Identity.ClientAppID, appID)
	}
	if rec.Identity.UserID != userID {
		t.Fatalf("user_id: got %q want %q", rec.Identity.UserID, userID)
	}
	if rec.Certificate == nil {
		t.Fatal("parsed certificate is nil")
	}
	if _, ok := rec.Certificate.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("public key type: got %T want *ecdsa.PublicKey", rec.Certificate.PublicKey)
	}
	if rec.Certificate.Subject.CommonName != appID {
		t.Fatalf("subject CN: got %q want %q", rec.Certificate.Subject.CommonName, appID)
	}
}

func TestEnrolledCertByClientAppIDMissingReturnsSentinel(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	_, err := store.EnrolledCertByClientAppID(ctx, "does-not-exist")
	if !errors.Is(err, ErrCertNotEnrolled) {
		t.Fatalf("got %v, want ErrCertNotEnrolled", err)
	}
}

func TestEnrolledCertByClientAppIDMissingPEMReturnsSentinel(t *testing.T) {
	// Pre-migration row simulation: insert a cert row with NULL cert_pem.
	store := openTestStore(t)
	ctx := context.Background()
	uid := "legacy-user"
	appID := "legacy-app"
	seedHostUser(t, store, uid)
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO client_apps (id, user_id, display_name, created_time) VALUES (?, ?, ?, ?)
`, appID, uid, "Legacy Device", formatSQLiteTime(time.Now().UTC())); err != nil {
		t.Fatalf("insert client_app: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO issued_certificates
    (serial, subject_cn, not_before, not_after, issued_at, user_id, client_app_id, cert_pem)
VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
`, "legacy-serial", appID,
		formatSQLiteTime(time.Now().Add(-time.Hour)),
		formatSQLiteTime(time.Now().Add(time.Hour)),
		formatSQLiteTime(time.Now()), uid, appID); err != nil {
		t.Fatalf("insert legacy cert: %v", err)
	}
	_, err := store.EnrolledCertByClientAppID(ctx, appID)
	if !errors.Is(err, ErrEnrolledCertMissingPEM) {
		t.Fatalf("got %v, want ErrEnrolledCertMissingPEM", err)
	}
}

func TestEnrolledCertByClientAppIDIgnoresRevoked(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	appID, _ := enrollFresh(t, store)

	// Mark the row revoked.
	if _, err := store.db.ExecContext(ctx,
		`UPDATE issued_certificates SET revoked_at = ? WHERE client_app_id = ?`,
		formatSQLiteTime(time.Now().UTC()), appID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	_, err := store.EnrolledCertByClientAppID(ctx, appID)
	if !errors.Is(err, ErrCertNotEnrolled) {
		t.Fatalf("got %v, want ErrCertNotEnrolled (revoked rows must not surface)", err)
	}
}
