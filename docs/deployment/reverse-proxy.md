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

## Tailscale

Tailnet-only deployments may run plain HTTP inside Tailscale because the
tailnet transport is already encrypted. Normal HTTPS is still usually better
for iOS clients and browser tooling, so operators can also put Caddy in front
and use Tailscale HTTPS certificates.

If a reverse proxy reaches Spivot Server over a Tailscale address, set
`SPIVOT_TRUSTED_PROXY_CIDRS` to include that proxy's tailnet range or exact
address.
