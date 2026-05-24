package storage

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// ClientAppRegistration captures everything the enrollment endpoint must
// persist for a single successful enrollment. The same struct is consumed
// by [Store.RegisterClientApp], which threads the four inserts (accounts,
// client_apps, client_app_invites consume, issued_certificates) through a
// single SQL transaction so a partial failure cannot leave the database
// in a half-enrolled state.
type ClientAppRegistration struct {
	// UserID is the new accounts.id minted by the caller before the
	// transaction begins. The caller chooses the value (typically a
	// UUID) so the same ID can be threaded through any in-flight
	// derived structures (response payloads, audit logs).
	UserID string
	// UserDisplayName is written to accounts.display_name. May be
	// empty; the schema requires the column but not a non-empty value.
	UserDisplayName string
	// OpenCaravanID is written to accounts.open_caravan_id (the
	// protocol-level UUID that other servers will see). Typically
	// equals UserID for now; future federation work may want them
	// distinct.
	OpenCaravanID string

	// ClientAppID is the new client_apps.id, identical to the issued
	// leaf certificate's subject in spivot-server's convention. The
	// caller mints it before the transaction.
	ClientAppID string
	// ClientAppDisplayName is written to client_apps.display_name.
	// Comes from the protocol's ClientAppEnrollmentRequest.DisplayName.
	ClientAppDisplayName string

	// InviteTokenValue is the plaintext invite token the client
	// presented. The transaction hashes it on the fly via
	// hashInviteToken and atomically consumes the row.
	InviteTokenValue string

	// Certificate is the leaf certificate the CA already signed; the
	// transaction inserts an audit row keyed by its serial.
	Certificate *x509.Certificate
}

// ErrEnrollmentRolledBack is returned when one of the inserts inside
// RegisterClientApp fails and the wrapping transaction is rolled back.
// The error chain carries the underlying SQL/storage error; callers
// detect this with [errors.Is] when they need to distinguish a
// transaction failure from individual-step errors that bubble up
// before the transaction begins.
var ErrEnrollmentRolledBack = errors.New("storage: client app enrollment rolled back")

// RegisterClientApp persists a successful client-app enrollment as a
// single atomic operation:
//
//  1. Insert a new accounts row using reg.UserID, reg.OpenCaravanID,
//     reg.UserDisplayName.
//  2. Insert a new client_apps row using reg.ClientAppID, reg.UserID,
//     reg.ClientAppDisplayName.
//  3. Atomically mark the invite identified by reg.InviteTokenValue as
//     used by reg.ClientAppID, using the same WHERE clause that
//     [Store.ConsumeInvite] uses (unused, unexpired). Returns
//     [ErrInviteNotFound], [ErrInviteAlreadyUsed], or
//     [ErrInviteExpired] if the invite is no longer redeemable.
//  4. Insert the issued certificate audit row keyed by serial,
//     populating user_id and client_app_id.
//
// Any failure rolls back all four inserts. The returned Invite
// reflects the post-consume state of the invite row; the consumed
// Invite is useful to the caller for confirmation logging.
//
// RegisterClientApp does not generate the new IDs itself: the caller
// mints them so the same values can be embedded in any in-flight
// response payload before the transaction commits. The caller is also
// responsible for validating the invite scope and the CSR before
// calling RegisterClientApp; this method assumes both have already
// been accepted.
func (s *Store) RegisterClientApp(ctx context.Context, reg ClientAppRegistration) (Invite, error) {
	if s == nil || s.db == nil {
		return Invite{}, errors.New("storage: database is not open")
	}
	if reg.UserID == "" || reg.ClientAppID == "" || reg.OpenCaravanID == "" {
		return Invite{}, errors.New("storage: registration requires UserID, ClientAppID, and OpenCaravanID")
	}
	if reg.InviteTokenValue == "" {
		return Invite{}, errors.New("storage: registration requires InviteTokenValue")
	}
	if reg.Certificate == nil {
		return Invite{}, errors.New("storage: registration requires a signed Certificate")
	}

	now := time.Now().UTC()
	nowStr := formatSQLiteTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invite{}, fmt.Errorf("storage: begin enrollment tx: %w", err)
	}
	rollback := func(cause error) (Invite, error) {
		// %w on every wrapping site (Go 1.20+ multi-wrap) so callers
		// stay able to detect ErrInviteAlreadyUsed / ErrInviteExpired /
		// any other sentinel via errors.Is, even on the rollback-
		// failure path where the rollback error also matters for
		// diagnostics.
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			return Invite{}, fmt.Errorf("%w: %w (rollback failed: %w)", ErrEnrollmentRolledBack, cause, rbErr)
		}
		return Invite{}, fmt.Errorf("%w: %w", ErrEnrollmentRolledBack, cause)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO accounts (id, open_caravan_id, display_name, created_at)
VALUES (?, ?, ?, ?)
`, reg.UserID, reg.OpenCaravanID, reg.UserDisplayName, nowStr); err != nil {
		return rollback(fmt.Errorf("insert account: %w", err))
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO client_apps (id, user_id, display_name, created_time)
VALUES (?, ?, ?, ?)
`, reg.ClientAppID, reg.UserID, reg.ClientAppDisplayName, nowStr); err != nil {
		return rollback(fmt.Errorf("insert client_app: %w", err))
	}

	inviteHash := hashInviteToken(reg.InviteTokenValue)
	res, err := tx.ExecContext(ctx, `
UPDATE client_app_invites
SET used_time = ?, used_by_client_app_id = ?
WHERE token_hash = ?
  AND used_time IS NULL
  AND expiration_time > ?
`, nowStr, reg.ClientAppID, inviteHash, nowStr)
	if err != nil {
		return rollback(fmt.Errorf("consume invite: %w", err))
	}
	updated, err := res.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("consume invite rows: %w", err))
	}
	if updated == 0 {
		// Map the failure to the same sentinel set ConsumeInvite uses
		// so the handler's error mapping stays consistent.
		existing, lookupErr := lookupInviteByHashTx(ctx, tx, inviteHash)
		if lookupErr != nil {
			return rollback(lookupErr)
		}
		if existing.UsedTime != nil {
			return rollback(ErrInviteAlreadyUsed)
		}
		return rollback(ErrInviteExpired)
	}

	// Read the consumed invite back inside the transaction. Doing this
	// pre-Commit means a transient DB error or context cancellation
	// surfaces here (and the transaction rolls back) rather than after
	// Commit, where a failed re-read would turn a successful enrollment
	// into a confusing 500.
	consumed, lookupErr := lookupInviteByHashTx(ctx, tx, inviteHash)
	if lookupErr != nil {
		return rollback(fmt.Errorf("re-read consumed invite: %w", lookupErr))
	}

	cert := reg.Certificate
	serial := cert.SerialNumber.Text(16)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO issued_certificates
    (serial, subject_cn, not_before, not_after, issued_at, user_id, client_app_id)
VALUES (?, ?, ?, ?, ?, ?, ?)
`, serial, cert.Subject.CommonName,
		formatSQLiteTime(cert.NotBefore),
		formatSQLiteTime(cert.NotAfter),
		nowStr, reg.UserID, reg.ClientAppID); err != nil {
		return rollback(fmt.Errorf("insert issued_certificate: %w", err))
	}

	if err := tx.Commit(); err != nil {
		return Invite{}, fmt.Errorf("%w: commit: %w", ErrEnrollmentRolledBack, err)
	}
	return consumed, nil
}

// ClientAppByID returns the ClientApp persisted under id. Used by the
// identity middleware (Phase 3c) to resolve an mTLS client cert back to
// the application record that owns it.
func (s *Store) ClientAppByID(ctx context.Context, id string) (ClientApp, error) {
	if s == nil || s.db == nil {
		return ClientApp{}, errors.New("storage: database is not open")
	}

	row := s.db.QueryRowContext(ctx, `
SELECT id, user_id, display_name, created_time
FROM client_apps
WHERE id = ?
`, id)
	var (
		app         ClientApp
		createdTime string
	)
	if err := row.Scan(&app.ID, &app.UserID, &app.DisplayName, &createdTime); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ClientApp{}, ErrClientAppNotFound
		}
		return ClientApp{}, fmt.Errorf("storage: load client_app %q: %w", id, err)
	}
	created, err := time.Parse(sqliteTimeFormat, createdTime)
	if err != nil {
		return ClientApp{}, fmt.Errorf("storage: parse client_app created_time: %w", err)
	}
	app.CreatedTime = created
	return app, nil
}

// ClientApp is the persisted descriptive record for an enrolled app
// installation. Pairs with an issued_certificates row keyed by the same
// serial-as-of-issuance and with a user it belongs to.
type ClientApp struct {
	ID          string
	UserID      string
	DisplayName string
	CreatedTime time.Time
}

// ErrClientAppNotFound is returned when the requested client_app row
// does not exist. Detected with [errors.Is].
var ErrClientAppNotFound = errors.New("storage: client_app not found")

// lookupInviteByHashTx is the tx-scoped variant of lookupInviteByHash,
// used inside RegisterClientApp's transaction to distinguish
// already-used vs expired without releasing the lock.
func lookupInviteByHashTx(ctx context.Context, tx *sql.Tx, hash string) (Invite, error) {
	row := tx.QueryRowContext(ctx, `
SELECT token_hash, scope, created_time, expiration_time, used_time, used_by_client_app_id
FROM client_app_invites
WHERE token_hash = ?
`, hash)

	var (
		tokenHash      string
		scope          string
		createdTime    string
		expirationTime string
		usedTime       sql.NullString
		usedBy         sql.NullString
	)
	if err := row.Scan(&tokenHash, &scope, &createdTime, &expirationTime, &usedTime, &usedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Invite{}, ErrInviteNotFound
		}
		return Invite{}, fmt.Errorf("storage: load invite in tx: %w", err)
	}
	created, err := time.Parse(sqliteTimeFormat, createdTime)
	if err != nil {
		return Invite{}, fmt.Errorf("storage: parse tx invite created_time: %w", err)
	}
	expiration, err := time.Parse(sqliteTimeFormat, expirationTime)
	if err != nil {
		return Invite{}, fmt.Errorf("storage: parse tx invite expiration_time: %w", err)
	}
	invite := Invite{
		TokenHash:      tokenHash,
		Scope:          opencaravan.InviteScope(scope),
		CreatedTime:    created,
		ExpirationTime: expiration,
	}
	if usedTime.Valid {
		used, err := time.Parse(sqliteTimeFormat, usedTime.String)
		if err != nil {
			return Invite{}, fmt.Errorf("storage: parse tx invite used_time: %w", err)
		}
		invite.UsedTime = &used
	}
	if usedBy.Valid {
		invite.UsedByClientAppID = usedBy.String
	}
	return invite, nil
}
