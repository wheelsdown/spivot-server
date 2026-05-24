package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrCertNotEnrolled is returned by [Store.IdentityBySerial] when no
// active (non-revoked) issued_certificates row matches the supplied
// serial. The middleware that consumes this lookup treats this
// sentinel as "the client presented a cert this server did not issue
// (or no longer recognizes)" and leaves the request unauthenticated:
// the broad AttachIdentity pass never rejects on its own, and any
// handler wrapped in RequireIdentity will subsequently 401. Detected
// via [errors.Is].
var ErrCertNotEnrolled = errors.New("storage: cert serial not enrolled")

// CertIdentity is the resolved identity backing a presented client
// certificate. It is the join product of issued_certificates and the
// client_apps / accounts records the cert points at.
//
// CertIdentity carries the protocol-relevant IDs the identity
// middleware needs (UserID, ClientAppID) plus the cert metadata that
// downstream handlers and audit logs benefit from (Serial, NotAfter,
// SubjectCN).
type CertIdentity struct {
	UserID      string
	ClientAppID string
	Serial      string
	SubjectCN   string
	NotAfter    time.Time
}

// IdentityBySerial looks up the active enrollment that issued the
// certificate with the supplied serial. Only non-revoked rows
// (revoked_at IS NULL) are considered.
//
// Serials must be in the canonical form Spivot Server uses everywhere:
// the lowercase-hex output of [math/big.Int.Text] with base 16, no
// separators, no 0x prefix, no leading zeros. This matches both what
// [RegisterClientApp] stores and what the proxy package's
// canonicalSerial produces from forwarded headers, so the same serial
// string always points at the same row regardless of which extraction
// path the caller came in through.
//
// Returns [ErrCertNotEnrolled] when no matching active row exists
// (unknown serial, or known serial with a non-NULL revoked_at).
// Returns a wrapped SQL error for transport-level failures.
func (s *Store) IdentityBySerial(ctx context.Context, serial string) (CertIdentity, error) {
	if s == nil || s.db == nil {
		return CertIdentity{}, errors.New("storage: database is not open")
	}
	if serial == "" {
		return CertIdentity{}, ErrCertNotEnrolled
	}

	row := s.db.QueryRowContext(ctx, `
SELECT ic.serial, ic.subject_cn, ic.not_after, ic.user_id, ic.client_app_id
FROM issued_certificates ic
WHERE ic.serial = ?
  AND ic.revoked_at IS NULL
  AND ic.user_id IS NOT NULL
  AND ic.client_app_id IS NOT NULL
`, serial)

	var (
		out      CertIdentity
		notAfter string
	)
	if err := row.Scan(&out.Serial, &out.SubjectCN, &notAfter, &out.UserID, &out.ClientAppID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CertIdentity{}, ErrCertNotEnrolled
		}
		return CertIdentity{}, fmt.Errorf("storage: load identity for serial %q: %w", serial, err)
	}
	parsed, err := time.Parse(sqliteTimeFormat, notAfter)
	if err != nil {
		return CertIdentity{}, fmt.Errorf("storage: parse identity not_after: %w", err)
	}
	out.NotAfter = parsed
	return out, nil
}
