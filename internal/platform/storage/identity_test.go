package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

func TestIdentityBySerialResolvesEnrolledCert(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	cert := syntheticLeaf(t, "client-app-identity")
	reg := ClientAppRegistration{
		UserID:               "user-identity",
		UserDisplayName:      "Identity Test",
		OpenCaravanID:        "user-identity",
		ClientAppID:          "client-app-identity",
		ClientAppDisplayName: "Test Device",
		InviteTokenValue:     token.Value,
		Certificate:          cert,
	}
	if _, err := store.RegisterClientApp(ctx, reg); err != nil {
		t.Fatalf("RegisterClientApp: %v", err)
	}

	serial := cert.SerialNumber.Text(16)
	got, err := store.IdentityBySerial(ctx, serial)
	if err != nil {
		t.Fatalf("IdentityBySerial: %v", err)
	}
	if got.UserID != "user-identity" {
		t.Fatalf("UserID = %q, want user-identity", got.UserID)
	}
	if got.ClientAppID != "client-app-identity" {
		t.Fatalf("ClientAppID = %q", got.ClientAppID)
	}
	if got.Serial != serial {
		t.Fatalf("Serial = %q, want %q", got.Serial, serial)
	}
	if got.SubjectCN != "client-app-identity" {
		t.Fatalf("SubjectCN = %q", got.SubjectCN)
	}
}

func TestIdentityBySerialRejectsUnknownSerial(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.IdentityBySerial(context.Background(), "deadbeef"); !errors.Is(err, ErrCertNotEnrolled) {
		t.Fatalf("err = %v, want ErrCertNotEnrolled", err)
	}
}

func TestIdentityBySerialRejectsEmptySerial(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.IdentityBySerial(context.Background(), ""); !errors.Is(err, ErrCertNotEnrolled) {
		t.Fatalf("err = %v, want ErrCertNotEnrolled", err)
	}
}

func TestIdentityBySerialRejectsRevokedCert(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	cert := syntheticLeaf(t, "client-app-revoked")
	reg := ClientAppRegistration{
		UserID:           "user-revoked",
		OpenCaravanID:    "user-revoked",
		ClientAppID:      "client-app-revoked",
		InviteTokenValue: token.Value,
		Certificate:      cert,
	}
	if _, err := store.RegisterClientApp(ctx, reg); err != nil {
		t.Fatalf("RegisterClientApp: %v", err)
	}

	serial := cert.SerialNumber.Text(16)
	// Manually mark the cert as revoked. A future RevokeCertificate
	// storage method (Phase 4+) will be the canonical way; for now we
	// poke the column directly to exercise the IdentityBySerial filter.
	if _, err := store.db.ExecContext(ctx, `
UPDATE issued_certificates SET revoked_at = ? WHERE serial = ?
`, formatSQLiteTime(time.Now()), serial); err != nil {
		t.Fatalf("revoke cert: %v", err)
	}

	if _, err := store.IdentityBySerial(ctx, serial); !errors.Is(err, ErrCertNotEnrolled) {
		t.Fatalf("revoked cert lookup err = %v, want ErrCertNotEnrolled", err)
	}
}
