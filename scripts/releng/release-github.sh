#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
# shellcheck source=./common.sh
source "$script_dir/common.sh"

if [[ $# -lt 1 || $# -gt 2 ]]; then
    die "usage: $0 <version> [release-kind]"
fi

version="$(normalize_version "$1")"
release_kind="${2:-auto}"

cd "$repo_root"
require_commands just docker gh git
validate_release_version "$version"
validate_release_kind "$release_kind"
require_clean_worktree "cutting a GitHub release"
require_main_branch
require_origin_main_match

prerelease="$(resolve_prerelease_bool "$version" "$release_kind")"

section "Cut GitHub release"
step "Version: v$version"
step "Release kind: $release_kind (prerelease=${prerelease})"
step "Primary image: ghcr.io/wheelsdown/spivot-server"

section "Prepare release"
run just prepare-release "v$version"

section "Publish release"
run just publish-release "v$version" "$release_kind"

section "Release complete"
step "GitHub release v$version is published with a local multi-arch OCI archive attached"
step "Tag push will also build and publish the multi-arch GHCR image"
