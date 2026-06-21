# Reverse Proxy Deployment

Spivot Server is proxy-native by default: the application listens on plain
HTTP, and a reverse proxy such as Caddy or Traefik owns public HTTPS,
ACME/Let's Encrypt renewal, HTTP-to-HTTPS redirects, and optional HTTP/3.

That keeps the service container small and lets operators use the TLS stack
they already know.

## Application Settings

Set these environment variables on the `spivot-server` container when it runs
behind an edge proxy:

```text
SPIVOT_ADDR=0.0.0.0
SPIVOT_PORT=8080
SPIVOT_PUBLIC_URL=https://spivot.example.com
SPIVOT_TRUST_PROXY=true
```

`SPIVOT_PUBLIC_URL` is the canonical external URL advertised by the service.
It should match the HTTPS URL served by Caddy, Traefik, or another edge proxy.

`SPIVOT_ACCESS_LOG_PATH` (also `--access-log-path`) routes the per-request
"request handled" log line to a file instead of stdout. Application events
(startup, warnings, errors) stay on stdout so `docker logs` or your
journal sink remains focused. The file is opened with `O_APPEND`; external
rotation tools (logrotate copytruncate, container restart, sidecar
shipper) manage size and retention. Leaving the variable unset keeps
the historical behavior — access lines emit on the main logger
alongside application events.

`SPIVOT_TRUST_PROXY=true` allows Spivot Server to use `X-Forwarded-For`,
`X-Forwarded-Proto`, and `X-Forwarded-Host` when the immediate peer is trusted.
By default, trusted proxy CIDRs are loopback, RFC1918 private networks, and
local IPv6 ranges commonly used for container networks:

```text
127.0.0.1/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10
```

Override them when your proxy sits somewhere else:

```text
SPIVOT_TRUSTED_PROXY_CIDRS=127.0.0.1/8,172.18.0.0/16
```

Do not enable proxy trust for a service port that is directly reachable by
untrusted clients. Forwarded headers are caller-controlled unless a trusted
edge proxy strips and rewrites them.

## Docker Compose

See [docs/deployment/docker-compose.md](docker-compose.md) for a minimal
production Compose service that runs Spivot Server behind an existing edge
proxy. That example pins a release image tag and leaves proxy route labels to
the local deployment.

## Caddy

See [examples/deploy/caddy/Caddyfile](../../examples/deploy/caddy/Caddyfile).

Caddy is the simplest default for a single-node deployment because automatic
HTTPS and certificate renewal are on by default for public DNS names.

## Traefik

See
[examples/deploy/traefik/docker-compose.yml](../../examples/deploy/traefik/docker-compose.yml).

Traefik is a good fit when Spivot runs alongside other containerized services
and you want Docker-label-driven routing.

## HTTP/3 + mTLS with Traefik

OpenCaravan's transport story is HTTP/3 over QUIC terminated at the edge proxy
with mTLS for device identity. The application stack itself stays plain HTTP
behind Traefik — Spivot Server does not link a QUIC implementation.

See
[examples/deploy/traefik/mtls/](../../examples/deploy/traefik/mtls/)
for a complete docker-compose + dynamic-config example. The relevant Traefik
pieces:

- HTTP/3 entrypoint: `--entrypoints.websecure.http3=true` on the websecure
  entrypoint, plus the `443/udp` port mapping. Browsers and `curl --http3`
  discover the QUIC endpoint via the `Alt-Svc` header on the first HTTP/1.1
  or HTTP/2 response.
- mTLS termination: a TLS options profile (`spivot-mtls@file`) with
  `caFiles` pointing at the Spivot CA root cert and `clientAuthType:
  VerifyClientCertIfGiven` so the enrollment endpoint stays reachable
  without a client cert AND any cert that IS presented is verified against
  the CA. `RequestClientCert` would request a cert but skip verification,
  letting an attacker forward a self-signed cert through
  `passTLSClientCert`.
- Cert forwarding: a `passTLSClientCert` middleware
  (`spivot-pass-client-cert@file`) emits both `X-Forwarded-Tls-Client-Cert`
  (URL-encoded PEM) and `X-Forwarded-Tls-Client-Cert-Info` (structured
  subject / serial / NotAfter). The application's proxy package consumes
  either path.

The server-side flag that enables consumption of those headers is
`SPIVOT_TRUST_CLIENT_CERT_HEADERS=true`. The headers are honored only when
the immediate peer is in `SPIVOT_TRUSTED_PROXY_CIDRS`, mirroring the
existing forwarded-headers trust model.

### Worked enrollment walkthrough

A clean container host should be able to bring up the stack, enroll the
first device, and exercise an authenticated endpoint in under 15 minutes.

```bash
# 1. Bring up just the server so the CA can self-mint and the first-run
#    bootstrap invite is written to stdout.
docker compose up -d spivot-server
docker compose logs spivot-server | grep -A4 'SPIVOT SERVER FIRST-RUN BOOTSTRAP'
# Copy the printed 43-character token; you'll need it as INVITE below.

# 2. Extract the CA root cert and place it where Traefik can mount it.
mkdir -p ca
docker compose exec -T spivot-server spivot-server ca cert > ca/spivot-ca.crt

# 3. Now bring up Traefik (it needs ca/spivot-ca.crt to start).
docker compose up -d traefik

# 4. Generate a client P-256 keypair + CSR locally. Spivot only signs
#    P-256 ECDSA leaf certs.
openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -out client.csr \
    -subj "/CN=my-first-device"

# 5. Enroll. The endpoint runs over HTTPS but does not require a client
#    cert — that's the whole point of VerifyClientCertIfGiven (optional
#    cert, verified when present). Spivot signs a leaf cert against its
#    CA and returns it inline. The jq invocation builds the JSON body so
#    the multi-line PEM CSR is correctly escaped into a single JSON
#    string.
INVITE=...   # the token from step 1
jq -n \
    --arg invite "$INVITE" \
    --rawfile csr client.csr \
    --arg name "My First Device" \
    '{type: "opencaravan.client_app_enrollment_request",
      version: 1,
      invite_token: $invite,
      csr_pem: $csr,
      display_name: $name}' \
  | curl -s --cacert ca/spivot-ca.crt \
      -H "Content-Type: application/json" --data @- \
      https://spivot.example.com/v1/client-apps/enroll \
  | jq -r '.enrollment.certificate_chain[0]' > client.crt

# 6. Now use the leaf cert for an authenticated request. The mTLS
#    handshake presents client.crt, Traefik verifies it against the
#    Spivot CA, passTLSClientCert forwards the cert to spivot-server,
#    and the identity middleware resolves it to the enrolled user.
curl --cacert ca/spivot-ca.crt --cert client.crt --key client.key \
    -H "Content-Type: application/json" \
    -d '{"title":"My first journey"}' \
    https://spivot.example.com/v1/journeys
```

The same flow with `--http3` works too once the QUIC endpoint is up; curl
will negotiate HTTP/3 after seeing the `Alt-Svc` header on the first
response.

## Tailscale

Tailnet-only deployments may run plain HTTP inside Tailscale because the
tailnet transport is already encrypted. Normal HTTPS is still usually better
for iOS clients and browser tooling, so operators can also put Caddy in front
and use Tailscale HTTPS certificates.

If a reverse proxy reaches Spivot Server over a Tailscale address, set
`SPIVOT_TRUSTED_PROXY_CIDRS` to include that proxy's tailnet range or exact
address.
