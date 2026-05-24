package storage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

func TestRegisterClientAppHappyPathPersistsEveryRow(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}

	cert := syntheticLeaf(t, "client-app-1")
	reg := ClientAppRegistration{
		UserID:               "user-1",
		UserDisplayName:      "Riley",
		OpenCaravanID:        "user-1",
		ClientAppID:          "client-app-1",
		ClientAppDisplayName: "Riley's iPhone",
		InviteTokenValue:     token.Value,
		Certificate:          cert,
	}

	invite, err := store.RegisterClientApp(ctx, reg)
	if err != nil {
		t.Fatalf("RegisterClientApp: %v", err)
	}
	if invite.UsedTime == nil {
		t.Fatal("invite UsedTime not set after register")
	}
	if invite.UsedByClientAppID != "client-app-1" {
		t.Fatalf("UsedByClientAppID = %q, want client-app-1", invite.UsedByClientAppID)
	}

	if got, err := store.AccountCount(ctx); err != nil || got != 1 {
		t.Fatalf("AccountCount = (%d, %v), want (1, nil)", got, err)
	}
	app, err := store.ClientAppByID(ctx, "client-app-1")
	if err != nil {
		t.Fatalf("ClientAppByID: %v", err)
	}
	if app.UserID != "user-1" {
		t.Fatalf("ClientApp.UserID = %q, want user-1", app.UserID)
	}
	if app.DisplayName != "Riley's iPhone" {
		t.Fatalf("ClientApp.DisplayName = %q", app.DisplayName)
	}
}

func TestRegisterClientAppRollsBackOnInviteAlreadyUsed(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	// Consume the invite via the simpler path first to set up the race.
	if _, err := store.ConsumeInvite(ctx, token.Value, "another-app"); err != nil {
		t.Fatalf("seed-consume: %v", err)
	}

	reg := ClientAppRegistration{
		UserID:               "user-2",
		OpenCaravanID:        "user-2",
		ClientAppID:          "client-app-2",
		ClientAppDisplayName: "second device",
		InviteTokenValue:     token.Value,
		Certificate:          syntheticLeaf(t, "client-app-2"),
	}

	_, err = store.RegisterClientApp(ctx, reg)
	if !errors.Is(err, ErrInviteAlreadyUsed) {
		t.Fatalf("RegisterClientApp error = %v, want ErrInviteAlreadyUsed", err)
	}
	if !errors.Is(err, ErrEnrollmentRolledBack) {
		t.Fatalf("RegisterClientApp error = %v, want chain containing ErrEnrollmentRolledBack", err)
	}

	// Verify rollback: no accounts or client_apps row should have been
	// persisted for the second registration.
	if got, err := store.AccountCount(ctx); err != nil || got != 0 {
		t.Fatalf("AccountCount after rollback = (%d, %v), want (0, nil)", got, err)
	}
	if _, err := store.ClientAppByID(ctx, "client-app-2"); !errors.Is(err, ErrClientAppNotFound) {
		t.Fatalf("ClientAppByID after rollback err = %v, want ErrClientAppNotFound", err)
	}
}

func TestRegisterClientAppRollsBackOnInviteExpired(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Millisecond)
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	reg := ClientAppRegistration{
		UserID:               "user-3",
		OpenCaravanID:        "user-3",
		ClientAppID:          "client-app-3",
		ClientAppDisplayName: "late device",
		InviteTokenValue:     token.Value,
		Certificate:          syntheticLeaf(t, "client-app-3"),
	}

	_, err = store.RegisterClientApp(ctx, reg)
	if !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("RegisterClientApp error = %v, want ErrInviteExpired", err)
	}
	if got, err := store.AccountCount(ctx); err != nil || got != 0 {
		t.Fatalf("AccountCount after rollback = (%d, %v), want (0, nil)", got, err)
	}
}

func TestRegisterClientAppRequiresFields(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	cases := []struct {
		name string
		mod  func(*ClientAppRegistration)
	}{
		{"missing user id", func(r *ClientAppRegistration) { r.UserID = "" }},
		{"missing client app id", func(r *ClientAppRegistration) { r.ClientAppID = "" }},
		{"missing oc id", func(r *ClientAppRegistration) { r.OpenCaravanID = "" }},
		{"missing invite", func(r *ClientAppRegistration) { r.InviteTokenValue = "" }},
		{"missing certificate", func(r *ClientAppRegistration) { r.Certificate = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := ClientAppRegistration{
				UserID:           "u",
				OpenCaravanID:    "u",
				ClientAppID:      "c",
				InviteTokenValue: "tok",
				Certificate:      syntheticLeaf(t, "c"),
			}
			tc.mod(&reg)
			if _, err := store.RegisterClientApp(ctx, reg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestClientAppByIDReturnsNotFound(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.ClientAppByID(context.Background(), "missing"); !errors.Is(err, ErrClientAppNotFound) {
		t.Fatalf("err = %v, want ErrClientAppNotFound", err)
	}
}

// syntheticLeaf produces a self-signed cert that looks enough like a
// CA-issued leaf for the audit-row insert in RegisterClientApp. It does
// not exercise the CA — those tests live in internal/platform/identity.
func syntheticLeaf(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}
