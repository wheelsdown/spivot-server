# Container Builds

`just container` performs a multi-arch build (defaults to
`linux/amd64,linux/arm64`) via `docker buildx`. Output is a per-arch
`docker save`-compatible tarball under `dist/` plus the host-arch
variant loaded into the local Docker daemon for `just container-run`:

```bash
just container
# → dist/spivot-server-linux-amd64.tar
# → dist/spivot-server-linux-arm64.tar
# → ghcr.io/wheelsdown/spivot-server:dev loaded into the local daemon
```

To smoke-test a release candidate against a remote deploy host, push
the same multi-arch build to GHCR:

```bash
echo "$(gh auth token)" | docker login ghcr.io -u "$(gh api user -q .login)" --password-stdin
just container-push ghcr.io/wheelsdown/spivot-server:dev
```

Tagged releases are intended to be consumed from GitHub Container
Registry:

```bash
docker pull ghcr.io/wheelsdown/spivot-server:latest
```

For production Docker Compose deployments behind an existing reverse
proxy, see [docker-compose.md](docker-compose.md). For the canonical
HTTP/3 + mTLS deployment recipe (Traefik in front, client cert
termination, worked enrollment walkthrough), see
[reverse-proxy.md](reverse-proxy.md) and
[examples/deploy/traefik/mtls/](../../examples/deploy/traefik/mtls/).

## Releases

Release tags use semver with a leading `v` (`v0.1.0`, `v0.1.0-rc.1`).
The process — audits, guarded build, publication, validation — is
[docs/release-checklist.md](../release-checklist.md); the machinery is
`just prepare-release` / `just publish-release` (or the
`just release-github` one-shot). The tag-triggered workflow publishes
multi-architecture OCI images to GHCR. Version data is injected at
build time; release versions are never hardcoded in Go source.
