#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
# shellcheck source=./common.sh
source "$script_dir/common.sh"

if [[ $# -lt 1 || $# -gt 2 ]]; then
    die "usage: $0 <version> [platforms]"
fi

version="$(normalize_version "$1")"
platforms="${2:-linux/amd64,linux/arm64}"
platform_csv="$(printf '%s' "$platforms" | tr -d '[:space:]')"
tag="v$version"
image="${SPIVOT_IMAGE:-ghcr.io/wheelsdown/spivot-server}"
image_ref="$image:$tag"
builder_name="${SPIVOT_BUILDX_BUILDER:-spivot-release}"
archive_path="$(release_oci_archive_path "$version" "$platform_csv")"
metadata_path="$(release_buildx_metadata_path "$version" "$platform_csv")"
checksum_path="${archive_path}.sha256"

cd "$repo_root"
validate_release_version "$version"
require_commands git tar tr grep sed date awk
require_docker_buildx

mkdir -p "$(dirname "$archive_path")"
rm -f "$archive_path" "$metadata_path" "$checksum_path"

build_time="${SPIVOT_BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
git_commit="$(git rev-parse HEAD)"
git_branch="$(git rev-parse --abbrev-ref HEAD)"

if ! docker buildx inspect "$builder_name" >/dev/null 2>&1; then
    section "Create Buildx builder"
    run docker buildx create --name "$builder_name" --driver docker-container --bootstrap
else
    docker buildx inspect "$builder_name" --bootstrap >/dev/null
fi

builder_driver="$(docker buildx inspect "$builder_name" | awk -F': ' '/^Driver:/ { print $2; exit }' | tr -d '[:space:]')"
if [[ "$builder_driver" == "docker" ]]; then
    die "Buildx builder $builder_name uses the docker driver; use a docker-container builder for OCI archive export"
fi

attestation_mode="${SPIVOT_BUILDX_ATTESTATIONS:-auto}"
buildx_args=(
    --builder "$builder_name"
    --platform "$platform_csv"
    --build-arg "SPIVOT_VERSION=$tag"
    --build-arg "BUILD_COMMIT=$git_commit"
    --build-arg "BUILD_BRANCH=$git_branch"
    --build-arg "BUILD_TIME=$build_time"
    --metadata-file "$metadata_path"
)

case "$attestation_mode" in
    auto)
        if [[ "$builder_driver" == "docker" ]]; then
            warn "Buildx docker driver does not support SBOM/provenance attestations for this local archive export"
            warn "The GitHub release workflow still publishes registry SBOM/provenance attestations"
        else
            buildx_args+=(--provenance=mode=max --sbom=true)
        fi
        ;;
    true|1|yes)
        buildx_args+=(--provenance=mode=max --sbom=true)
        ;;
    false|0|no)
        ;;
    *)
        die "SPIVOT_BUILDX_ATTESTATIONS must be auto, true, or false"
        ;;
esac

section "Build multi-platform OCI archive"
step "Image: $image_ref"
step "Platforms: $platform_csv"
step "Archive: $archive_path"
step "Buildx builder: $builder_name"
step "Buildx driver: $builder_driver"

buildx_args+=(
    --tag "$image_ref"
    --output "type=oci,dest=$archive_path,name=$image_ref"
    .
)

docker buildx build "${buildx_args[@]}"

section "Validate OCI archive"
tar -tf "$archive_path" oci-layout >/dev/null || die "OCI archive missing oci-layout"
tar -tf "$archive_path" index.json >/dev/null || die "OCI archive missing index.json"

index_json="$(tar -xOf "$archive_path" index.json)"
platform_index_json="$index_json"
while IFS= read -r digest; do
    [[ -n "$digest" ]] || continue
    blob_json="$(tar -xOf "$archive_path" "blobs/sha256/$digest" 2>/dev/null || true)"
    [[ -n "$blob_json" ]] || continue
    platform_index_json+=$'\n'
    platform_index_json+="$blob_json"
done < <(printf '%s' "$index_json" | grep -Eo '"digest"[[:space:]]*:[[:space:]]*"sha256:[0-9a-f]+"' | sed -E 's/.*sha256:([0-9a-f]+).*/\1/')

IFS=',' read -r -a platform_list <<< "$platform_csv"
for platform in "${platform_list[@]}"; do
    platform="${platform# }"
    platform="${platform% }"
    os_name="${platform%%/*}"
    arch_name="${platform#*/}"

    if [[ -z "$os_name" || -z "$arch_name" || "$os_name" == "$arch_name" ]]; then
        die "invalid platform: $platform"
    fi

    printf '%s' "$platform_index_json" | grep -Eq "\"os\"[[:space:]]*:[[:space:]]*\"$os_name\"" || \
        die "OCI archive missing OS platform: $os_name"
    printf '%s' "$platform_index_json" | grep -Eq "\"architecture\"[[:space:]]*:[[:space:]]*\"$arch_name\"" || \
        die "OCI archive missing architecture platform: $arch_name"
done

sha256_file "$archive_path" > "$checksum_path"

step "Metadata: $metadata_path"
step "Checksum: $checksum_path"
