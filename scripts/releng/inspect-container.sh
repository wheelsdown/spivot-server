#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <image-tag> <expected-version>" >&2
    exit 1
fi

image_tag="$1"
expected_version="$2"

require_label() {
    local label="$1"
    local expected="${2:-}"
    local actual
    actual="$(docker image inspect "$image_tag" --format "{{ index .Config.Labels \"$label\" }}" 2>/dev/null || true)"
    if [[ -z "$actual" || "$actual" == "<no value>" ]]; then
        echo "missing OCI label: $label" >&2
        exit 1
    fi
    if [[ -n "$expected" && "$actual" != "$expected" ]]; then
        echo "label $label = $actual, expected $expected" >&2
        exit 1
    fi
}

require_label "org.opencontainers.image.title" "Spivot Server"
require_label "org.opencontainers.image.description"
require_label "org.opencontainers.image.authors"
require_label "org.opencontainers.image.url" "https://github.com/wheelsdown/spivot-server"
require_label "org.opencontainers.image.documentation"
require_label "org.opencontainers.image.source" "https://github.com/wheelsdown/spivot-server"
require_label "org.opencontainers.image.vendor" "wheelsdown"
require_label "org.opencontainers.image.licenses" "Apache-2.0"
require_label "org.opencontainers.image.version" "$expected_version"
require_label "org.opencontainers.image.ref.name" "$expected_version"
require_label "org.opencontainers.image.revision"
require_label "org.opencontainers.image.created"
require_label "org.opencontainers.image.base.name" "scratch"

docker run --rm "$image_tag" version >/dev/null

container_id="$(docker run -d --health-interval=1s --health-timeout=2s --health-retries=10 "$image_tag")"
cleanup() {
    docker rm -f "$container_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 20); do
    status="$(docker inspect --format '{{.State.Health.Status}}' "$container_id")"
    case "$status" in
        healthy)
            exit 0
            ;;
        unhealthy)
            docker logs "$container_id" >&2 || true
            echo "container became unhealthy" >&2
            exit 1
            ;;
    esac
    sleep 1
done

docker logs "$container_id" >&2 || true
echo "container did not become healthy" >&2
exit 1
