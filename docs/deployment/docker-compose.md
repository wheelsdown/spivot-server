# Docker Compose Deployment

This deployment shape runs Spivot Server as a plain HTTP service behind an
existing edge proxy. The edge proxy owns public HTTPS, ACME renewal, redirects,
and route labels.

Copy the example files from
[`examples/deploy/compose`](../../examples/deploy/compose), then set the
environment values for your host:

```bash
cp examples/deploy/compose/.env.example .env
cp examples/deploy/compose/compose.yml compose.yml
```

Edit `.env`:

```text
SPIVOT_IMAGE_TAG=v0.1.0-alpha.1
SPIVOT_PUBLIC_URL=https://spivot.example.com
SPIVOT_EDGE_NETWORK=traefik
SPIVOT_LOG_FORMAT=json
SPIVOT_TRUSTED_PROXY_CIDRS=127.0.0.1/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10
```

`SPIVOT_IMAGE_TAG` should be a released tag, not `latest`, for production.
`SPIVOT_PUBLIC_URL` should match the HTTPS URL served by your proxy.
`SPIVOT_EDGE_NETWORK` should be the Docker network shared with your existing
Traefik, Caddy, or other reverse proxy.

Start or update the service:

```bash
docker compose pull spivot-server
docker compose up -d
```

Check the container:

```bash
docker compose ps
docker compose logs -f spivot-server
docker compose exec spivot-server /usr/local/bin/spivot-server version
```

Add route labels in your own deployment overlay when your reverse proxy uses
Docker labels. Keep the Spivot container reachable only by the trusted edge
proxy network when `SPIVOT_TRUST_PROXY=true`.
