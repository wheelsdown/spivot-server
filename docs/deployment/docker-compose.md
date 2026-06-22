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
mkdir -p config
```

Edit `.env`:

```text
SPIVOT_IMAGE_TAG=latest
SPIVOT_PUBLIC_URL=https://spivot.example.com
SPIVOT_EDGE_NETWORK=traefik
SPIVOT_LOG_FORMAT=json
SPIVOT_TRUSTED_PROXY_CIDRS=127.0.0.1/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10
```

`SPIVOT_IMAGE_TAG=latest` is the recommended default. Spivot Server is meant to
be easy to keep current under Compose, and the release workflow publishes
`latest` from stable release tags. Operators who need stricter change control
can pin a semver tag such as `v0.1.0`.
`SPIVOT_PUBLIC_URL` should match the HTTPS URL served by your proxy.
`SPIVOT_EDGE_NETWORK` should be the Docker network shared with your existing
Traefik, Caddy, or other reverse proxy.

The compose file mounts two stable runtime paths:

- `/etc/spivot` is a read-only bind mount from `./config` for future operator
  configuration files.
- `/var/lib/spivot` is the named `spivot-data` volume for SQLite databases,
  uploaded resources, and other durable server state.

Spivot Server runs as a non-root user, and the image pre-creates those paths
with the right ownership. Keep the in-container paths stable unless you are
also updating `SPIVOT_CONFIG_DIR`, `SPIVOT_DATA_DIR`, and `SPIVOT_DATABASE_PATH`.

> ⚠️ **Common pitfall**: mapping the host volume to the wrong in-container
> path (e.g., `/usr/lib/spivot` instead of `/var/lib/spivot`) silently writes
> SQLite state into the container's writable layer and loses everything on
> the next `docker compose up --force-recreate` or image upgrade. Symptoms:
> the first-run bootstrap banner reappears after a deploy, and previously
> enrolled clients lose their trust path because the CA is regenerated.
> Spivot Server WARNs on startup when `SPIVOT_DATA_DIR` does not appear in
> the container's mount table — watch for `data_dir does not appear to be a
> mount point` in the logs, and check `docker inspect <container>` shows a
> volume at `/var/lib/spivot`.

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
