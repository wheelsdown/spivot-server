// Package macaroon issues and verifies the session-bound macaroons
// spivot-server hands out in exchange for a successful POST /v1/sessions
// request. It is a thin wrapper around [gopkg.in/macaroon.v2] that pins
// the spivot-server location, embeds a server-side root key identifier
// in every macaroon, and evaluates first-party caveats against the
// canonical OpenCaravan predicate vocabulary defined by the
// [github.com/opencaravan/opencaravan-go] package.
//
// # Two halves
//
// The package is split into an issuer half and a verifier half so
// each side can be wired without the other:
//
//   - [Issuer] holds an active [storage.MacaroonRoot] and mints
//     macaroons with the supplied predicates as first-party caveats.
//     The root id is written into the macaroon's Id field so the
//     verifier can look up the right key without trial decryption.
//   - [Verifier] holds a key-resolving function (typically backed by
//     [storage.Store.MacaroonRootByID]) plus a clock, and validates
//     the binary serialization of a presented macaroon against a
//     supplied [Constraints]. The signature check is delegated to
//     macaroon.v2; the caveat check parses each predicate via
//     [opencaravan.ParseCaveat] and evaluates it against the
//     constraints.
//
// # Caveat semantics
//
// Verification is fail-closed on unknown caveats: a macaroon
// carrying any predicate that does not parse into a known
// [opencaravan.CaveatKind] is rejected. This matches the
// OpenCaravan recommendation ("implementations may preserve unknown
// caveats verbatim and reject the macaroon if any unknown caveat
// blocks the action being attempted") and prevents an upgrade-skew
// caller from silently accepting a macaroon attenuation it cannot
// honor.
//
// Time caveats use the constraints' Now field, not [time.Now], so
// tests can drive expiration boundaries deterministically.
//
// # Wire format
//
// Macaroons are exchanged as the raw binary serialization produced
// by macaroon.v2 — callers transport them as the unpadded-base64url
// macaroon field of [opencaravan.SessionResponse]. This package
// does not perform base64 encoding itself; the [Issuer.Issue] return
// is the raw bytes, and [Verifier.Verify] consumes raw bytes.
package macaroon
