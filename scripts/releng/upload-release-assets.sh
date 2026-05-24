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
archive_path="$(release_oci_archive_path "$version" "$platform_csv")"
metadata_path="$(release_buildx_metadata_path "$version" "$platform_csv")"
checksum_path="${archive_path}.sha256"

cd "$repo_root"
validate_release_version "$version"
require_commands gh tr

[[ -f "$archive_path" ]] || die "missing OCI archive: $archive_path"
[[ -f "$checksum_path" ]] || die "missing OCI archive checksum: $checksum_path"
[[ -f "$metadata_path" ]] || die "missing buildx metadata: $metadata_path"

section "Upload release artifacts"
run gh release upload "$tag" "$archive_path" "$checksum_path" "$metadata_path" --clobber
