# Spivot Server behind Traefik with HTTP/3 + mTLS

This example stands up Spivot Server behind Traefik v3 with:

- **HTTP/3 over QUIC** terminated at Traefik (UDP/443).
- **mTLS** terminated at Traefik against the server-local CA.
- **`passTLSClientCert`** middleware forwarding the verified
  client cert to Spivot Server as `X-Forwarded-Tls-Client-Cert*`
  headers.
- Plain HTTP between Traefik and Spivot Server — the application
  stack does not need a QUIC implementation.

The total time from a fresh container host to a working
authenticated request is intended to be under 15 minutes.

## Files

| File | What it is |
| --- | --- |
| `docker-compose.yml` | Traefik + spivot-server services with all routing labels. |
| `dynamic.yml` | Traefik file-provider config: TLS options + `passTLSClientCert` middleware. |
| `README.md` | This walkthrough. |

## Operator quick start

The compose file references `./ca/spivot-ca.crt`, which doesn't
exist yet. The bootstrap order is:

1. Bring up just `spivot-server` (the database needs to apply
   migrations + the CA needs to self-mint before Traefik can
   reference the root cert).

   ```bash
   docker compose up -d spivot-server
   ```

   Wait for the "certificate authority ready" log line. The
   first-run bootstrap invite token is printed in a fenced banner
   on the same stdout — copy it now; you need it in step 3.

2. Extract the CA root cert and place it where Traefik can mount
   it.

   ```bash
   mkdir -p ca
   docker compose exec -T spivot-server spivot-server ca cert > ca/spivot-ca.crt
   ```

3. Bring up Traefik.

   ```bash
   docker compose up -d traefik
   ```

   Wait for the ACME cert. Once Traefik logs `Serving default
   certificate` for the entrypoint, the stack is reachable on
   `https://spivot.example.com` (and HTTP/3 at the same URL —
   browsers and curl `--http3` will discover it via the
   `Alt-Svc` header).

4. Enroll the first device. The enrollment endpoint accepts
   connections without a client cert — the `RequestClientCert`
   mode in `dynamic.yml` is deliberate. See
   [docs/deployment/reverse-proxy.md](../../../../docs/deployment/reverse-proxy.md)
   for the full enrollment walkthrough with `openssl` and `curl`.

## Notes on TLS options

- `clientAuthType: RequestClientCert` (not
  `RequireAndVerifyClientCert`): the server must reach handlers
  for unauthenticated callers so the application layer
  (`RequireIdentity` / `RequireSession`) can decide what to do.
  Requiring the cert at TLS would 401 enrollment requests at the
  wrong layer.
- `caFiles: [/etc/traefik/spivot-ca.crt]`: the Spivot CA is the
  only trust anchor for client certs. Traefik refuses presented
  certs signed by any other CA.
- `minVersion: VersionTLS13`: TLS 1.3 is required because the
  full key exchange happens in one round trip and 1.3 is what
  HTTP/3 mandates anyway.

## Notes on the `passTLSClientCert` middleware

- `pem: true`: the full PEM-encoded leaf is forwarded URL-encoded
  in `X-Forwarded-Tls-Client-Cert`. The proxy package's
  `parseForwardedClientCertPEM` decodes this and re-parses the
  x509 so the server has the same view of the cert it would have
  had under direct mTLS.
- `info.*`: the structured-info header is a fallback for
  deployments where the PEM header gets dropped by a header-size
  limit somewhere in the chain. Both paths converge on the same
  canonical `(subject_cn, serial, fingerprint, not_after)` tuple
  via the `canonicalSerial` round-trip in the proxy package.
