// Package middleware wires the HTTP authentication boundary for
// spivot-server: it lifts whatever client identity the lower layers
// presented (direct mTLS or trusted-proxy-forwarded cert headers,
// extracted by [internal/platform/proxy.RequestInfoFrom]), resolves it
// to a server-side [Identity] via the issued-certificates audit table,
// attaches that Identity to the request context, and provides a
// per-handler guard that 401s when an Identity is required but absent.
//
// # Two-tier shape
//
// The middleware is split into a broad attach pass and a per-handler
// guard so each handler explicitly declares its own authentication
// requirements at the registration site rather than relying on a
// single chain to enforce everything implicitly:
//
//   - [AttachIdentity] runs once at the top of the chain. When the
//     inbound [proxy.RequestInfo.ClientCert] carries a serial that
//     matches a non-revoked row in issued_certificates, the resolved
//     [Identity] is attached to the request context. The attach pass
//     never rejects: unauthenticated requests pass through, and
//     downstream handlers (or [RequireIdentity]) decide what to do.
//   - [RequireIdentity] wraps individual handlers. It reads the
//     context-attached Identity and returns 401 with an
//     application/problem+json body when one is missing. Used at the
//     registration site so the access requirement is visible in the
//     route table.
//
// # Why narrow over wide
//
// Cert validation happens at the layer below this package: Go's TLS
// stack verifies the chain and expiry for direct mTLS, and a trusted
// proxy does the same before forwarding headers. By the time
// AttachIdentity sees a ClientCert it has already been authenticated
// cryptographically. This middleware's job is solely to map "this
// cert was presented" to "these are the enrolled IDs that cert
// authorizes," via the issued_certificates table.
//
// # Revocation
//
// [IdentityStore.IdentityBySerial] filters out rows with non-NULL
// revoked_at, so a revoked cert effectively becomes "no Identity
// attached" and any handler that calls RequireIdentity will 401 the
// request. Short-lived leaf certificates make this the only
// revocation mechanism that's necessary; CRL/OCSP infrastructure is
// not needed.
package middleware
