module := "github.com/wheelsdown/spivot-server"
pkg := module + "/internal/platform/buildinfo"
binary := "spivot-server"
version := env("SPIVOT_VERSION", `git describe --tags --always --dirty 2>/dev/null || echo "dev"`)
git_commit := `git rev-parse --short HEAD 2>/dev/null || echo "unknown"`
git_branch := `git symbolic-ref --quiet --short HEAD 2>/dev/null || echo "unknown"`
build_time := `date -u '+%Y-%m-%dT%H:%M:%SZ'`
ldflags := "-X " + pkg + ".Version=" + version + " -X " + pkg + ".GitCommit=" + git_commit + " -X " + pkg + ".GitBranch=" + git_branch + " -X " + pkg + ".BuildTime=" + build_time

host_os := if os() == "macos" { "darwin" } else { os() }
host_arch := if arch() == "aarch64" { "arm64" } else if arch() == "x86_64" { "amd64" } else { arch() }
image := env("SPIVOT_IMAGE", "ghcr.io/wheelsdown/spivot-server")
dev_image := image + ":dev"
ci_image := image + ":ci"
container_platforms := env("SPIVOT_CONTAINER_PLATFORMS", "linux/amd64,linux/arm64")
container_tarball_dir := env("SPIVOT_CONTAINER_TARBALL_DIR", "dist")
container_builder := env("SPIVOT_BUILDX_LOCAL_BUILDER", "spivot-local")
release-dir := "dist/release"

# List available recipes
default:
    @echo "Common workflows:"
    @echo "  just ci                                      # full local validation gate"
    @echo "  just container                              # build multi-arch per-platform tarballs + load host arch locally"
    @echo "  just container-archive <version>            # build a multi-arch OCI archive (release flow)"
    @echo "  just release-github <version> [kind]        # tag and publish a GHCR-backed release"
    @echo ""
    @just --list

# --- Build ---

[group('build')]
generate:
    go generate ./...

[group('build')]
build target_os=host_os target_arch=host_arch: generate
    @mkdir -p dist
    CGO_ENABLED=0 GOOS={{target_os}} GOARCH={{target_arch}} go build -trimpath -ldflags "{{ldflags}}" -o dist/{{binary}}-{{target_os}}-{{target_arch}} ./cmd/{{binary}}
    @echo "Built dist/{{binary}}-{{target_os}}-{{target_arch}}"

[group('build')]
build-linux:
    just build linux amd64
    just build linux arm64

[group('build')]
version: build
    dist/{{binary}}-{{host_os}}-{{host_arch}} version

[group('build')]
clean:
    rm -rf dist

# --- Container ---

[group('container')]
container tag=dev_image platforms=container_platforms tarball_dir=container_tarball_dir:
    #!/usr/bin/env bash
    set -euo pipefail
    # Always produce a deployable image for every requested
    # platform — not just the host arch. The historical
    # `docker build` single-arch behavior surprised an operator
    # who built on arm64 and then could not deploy on amd64.
    #
    # Per-platform `docker save`-compatible tarballs land in
    # $tarball_dir, one per requested arch. They are the
    # standard interchange format for "scp to a deploy host and
    # docker load" workflows. The host-arch variant is also
    # imported into the local Docker daemon so the
    # container-check / container-run recipes (which need a
    # daemon-resident image) keep working unchanged.
    #
    # buildx with a docker-container driver is required for
    # cross-platform builds; the managed `spivot-local` builder
    # is created on first use and reused across invocations so
    # the build cache survives.
    mkdir -p '{{tarball_dir}}'
    if ! docker buildx inspect '{{container_builder}}' >/dev/null 2>&1; then
        docker buildx create --name '{{container_builder}}' \
            --driver docker-container --bootstrap
    fi
    common_args=(
        --builder '{{container_builder}}'
        --build-arg "SPIVOT_VERSION={{version}}"
        --build-arg "BUILD_COMMIT={{git_commit}}"
        --build-arg "BUILD_BRANCH={{git_branch}}"
        --build-arg "BUILD_TIME={{build_time}}"
        -t '{{tag}}'
    )
    declare -a built
    for platform in $(echo '{{platforms}}' | tr ',' ' '); do
        arch="${platform##*/}"
        tarball="{{tarball_dir}}/{{binary}}-${platform//\//-}.tar"
        docker buildx build "${common_args[@]}" \
            --platform "$platform" \
            --output "type=docker,dest=${tarball}" .
        built+=("$arch:$tarball")
    done
    # Load the host-arch tarball into the local Docker daemon.
    host_tarball="{{tarball_dir}}/{{binary}}-linux-{{host_arch}}.tar"
    if [ -f "$host_tarball" ]; then
        docker load -i "$host_tarball" >/dev/null
        echo
        echo "Host-arch image loaded into local Docker daemon: {{tag}}"
        echo "  inspect with: docker image inspect {{tag}}"
        echo "  run with:     just container-run {{tag}}"
    fi
    echo
    echo "Per-platform tarballs (each a docker save-compatible image of {{tag}}):"
    for entry in "${built[@]}"; do
        arch="${entry%%:*}"; tarball="${entry#*:}"
        echo "  $arch  →  $tarball"
    done
    echo
    echo "Deploy on a remote host (substitute the target hostname for <host>):"
    for entry in "${built[@]}"; do
        arch="${entry%%:*}"; tarball="${entry#*:}"
        base="$(basename "$tarball")"
        echo "  $arch:  scp $tarball <host>:/tmp/ && ssh <host> docker load -i /tmp/$base"
    done

[group('container')]
container-check tag=ci_image:
    just container "{{tag}}"
    scripts/releng/inspect-container.sh "{{tag}}" "{{version}}"

[group('container')]
container-archive version platforms=container_platforms:
    scripts/releng/build-container-archive.sh "{{version}}" "{{platforms}}"

[group('container')]
container-run tag=dev_image port="8080":
    docker run --rm -p {{port}}:8080 {{tag}}

# --- Test ---

[group('test')]
test: generate
    go test -race ./...

[group('test')]
fmt-check:
    @test -z "$(gofmt -l .)" || (echo "Files need formatting:" && gofmt -l . && exit 1)

[group('test')]
lint: generate
    golangci-lint run ./...

[group('test')]
mod-tidy-check:
    go mod tidy
    @test -z "$(git diff --name-only -- go.mod go.sum)" || (echo "go.mod/go.sum not tidy - run 'go mod tidy'" && git diff -- go.mod go.sum && exit 1)

[group('test')]
ci: fmt-check mod-tidy-check lint test container-check

# --- Operations ---

[group('operations')]
serve: build
    dist/{{binary}}-{{host_os}}-{{host_arch}} serve

[group('operations')]
healthcheck url="http://127.0.0.1:8080/health":
    go run ./cmd/{{binary}} healthcheck -url "{{url}}"

# --- Release ---

[group('release-engineering')]
prepare-release version:
    #!/usr/bin/env bash
    set -euo pipefail
    version="{{version}}"
    version="${version#v}"
    container_platforms="{{container_platforms}}"

    if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
        echo "Version must look like 0.1.0 or 0.1.0-rc.1" >&2
        exit 1
    fi

    test -z "$(git status --short)" || { echo "Worktree must be clean before a prepare-release run"; exit 1; }
    mkdir -p "{{release-dir}}"

    SPIVOT_VERSION="v${version}" just ci
    scripts/releng/build-container-archive.sh "v${version}" "$container_platforms"

    metadata_path="{{release-dir}}/.spivot_${version}_prepared.env"
    printf 'SPIVOT_RELEASE_PREPARED_VERSION=%s\n' "$version" > "$metadata_path"
    printf 'SPIVOT_RELEASE_PREPARED_COMMIT=%s\n' "$(git rev-parse HEAD)" >> "$metadata_path"
    printf 'SPIVOT_RELEASE_PREPARED_BRANCH=%s\n' "$(git rev-parse --abbrev-ref HEAD)" >> "$metadata_path"
    printf 'SPIVOT_RELEASE_PREPARED_AT=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$metadata_path"
    printf 'SPIVOT_RELEASE_CONTAINER_PLATFORMS=%s\n' "$container_platforms" >> "$metadata_path"

    echo ""
    echo "Local release preparation complete."
    echo "  Release metadata: $metadata_path"
    echo "  OCI archive directory: {{release-dir}}"
    echo "  Container smoke tag: {{ci_image}}"
    echo "  Nothing was tagged, pushed, or uploaded to GitHub."

[group('release-engineering')]
publish-release version release_kind="auto":
    #!/usr/bin/env bash
    set -euo pipefail
    version="{{version}}"
    version="${version#v}"
    tag="v${version}"
    release_kind="{{release_kind}}"
    metadata_path="{{release-dir}}/.spivot_${version}_prepared.env"
    head_commit="$(git rev-parse HEAD)"
    prerelease=false

    if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
        echo "Version must look like 0.1.0 or 0.1.0-rc.1" >&2
        exit 1
    fi

    case "$release_kind" in
        auto)
            if printf '%s' "$version" | grep -q -- '-'; then prerelease=true; fi
            ;;
        prerelease) prerelease=true ;;
        release) ;;
        *) echo "release_kind must be one of: auto, prerelease, release" >&2; exit 1 ;;
    esac

    test -z "$(git status --short)" || { echo "Worktree must be clean before publishing a release"; exit 1; }
    test -f "$metadata_path" || { echo "Missing release metadata: $metadata_path. Run 'just prepare-release ${version}' first." >&2; exit 1; }
    . "$metadata_path"
    test "${SPIVOT_RELEASE_PREPARED_VERSION:-}" = "$version" || { echo "Prepared version mismatch; run 'just prepare-release ${version}' again." >&2; exit 1; }
    test "${SPIVOT_RELEASE_PREPARED_COMMIT:-}" = "$head_commit" || { echo "Prepared commit mismatch; run 'just prepare-release ${version}' again." >&2; exit 1; }
    release_platforms="${SPIVOT_RELEASE_CONTAINER_PLATFORMS:-{{container_platforms}}}"
    release_platform_label="$(printf '%s' "$release_platforms" | tr -d '[:space:]' | tr '/,' '-_')"
    archive_path="{{release-dir}}/spivot-server_v${version}_${release_platform_label}.oci.tar"
    checksum_path="${archive_path}.sha256"
    buildx_metadata_path="{{release-dir}}/spivot-server_v${version}_${release_platform_label}.buildx.json"
    test -f "$archive_path" || { echo "Missing OCI archive: $archive_path. Run 'just prepare-release ${version}' again." >&2; exit 1; }
    test -f "$checksum_path" || { echo "Missing OCI archive checksum: $checksum_path. Run 'just prepare-release ${version}' again." >&2; exit 1; }
    test -f "$buildx_metadata_path" || { echo "Missing Buildx metadata: $buildx_metadata_path. Run 'just prepare-release ${version}' again." >&2; exit 1; }

    git fetch origin main --tags
    test "$(git rev-parse --abbrev-ref HEAD)" = "main" || { echo "Release tags must be cut from main" >&2; exit 1; }
    test "$head_commit" = "$(git rev-parse origin/main)" || { echo "Local main must match origin/main before release" >&2; exit 1; }

    if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
        test "$(git rev-list -n 1 "$tag")" = "$head_commit" || { echo "Local tag $tag points at a different commit" >&2; exit 1; }
    else
        git tag -a "$tag" -m "$tag"
    fi

    if git ls-remote --exit-code --tags origin "$tag" >/dev/null 2>&1; then
        remote_tag_commit="$(git ls-remote --tags origin "$tag^{}" | awk '{print $1}')"
        if [ -z "$remote_tag_commit" ]; then
            remote_tag_commit="$(git ls-remote --tags origin "$tag" | awk '{print $1}')"
        fi
        test "$remote_tag_commit" = "$head_commit" || { echo "Remote tag $tag points at a different commit" >&2; exit 1; }
        echo "Remote tag $tag already exists at the current commit."
    else
        git push origin "$tag"
    fi

    if gh release view "$tag" >/dev/null 2>&1; then
        echo "GitHub release $tag already exists."
        scripts/releng/upload-release-assets.sh "v${version}" "$release_platforms"
    else
        if [ "$prerelease" = true ]; then
            gh release create "$tag" "$archive_path" "$checksum_path" "$buildx_metadata_path" --title "$tag" --generate-notes --prerelease --latest=false
        else
            gh release create "$tag" "$archive_path" "$checksum_path" "$buildx_metadata_path" --title "$tag" --generate-notes
        fi
    fi

    echo "Published $tag. GitHub Actions will publish OCI tags for {{image}}; the local OCI archive was uploaded to the GitHub release."

[group('release-engineering')]
release-github version release_kind="auto":
    scripts/releng/release-github.sh "{{version}}" "{{release_kind}}"
