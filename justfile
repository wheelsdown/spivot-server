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
release-dir := "dist/release"

# List available recipes
default:
    @echo "Common workflows:"
    @echo "  just ci                                      # full local validation gate"
    @echo "  just container                              # build a local OCI image"
    @echo "  just container-archive <version>            # build a multi-arch OCI archive"
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
container tag=dev_image:
    docker build \
        --build-arg SPIVOT_VERSION="{{version}}" \
        --build-arg BUILD_COMMIT="{{git_commit}}" \
        --build-arg BUILD_BRANCH="{{git_branch}}" \
        --build-arg BUILD_TIME="{{build_time}}" \
        -t {{tag}} .

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
    prerelease_flag=()

    if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
        echo "Version must look like 0.1.0 or 0.1.0-rc.1" >&2
        exit 1
    fi

    case "$release_kind" in
        auto)
            if printf '%s' "$version" | grep -q -- '-'; then prerelease_flag=(--prerelease --latest=false); fi
            ;;
        prerelease) prerelease_flag=(--prerelease --latest=false) ;;
        release) ;;
        *) echo "release_kind must be one of: auto, prerelease, release" >&2; exit 1 ;;
    esac

    test -z "$(git status --short)" || { echo "Worktree must be clean before publishing a release"; exit 1; }
    test -f "$metadata_path" || { echo "Missing release metadata: $metadata_path. Run 'just prepare-release ${version}' first." >&2; exit 1; }
    . "$metadata_path"
    test "${SPIVOT_RELEASE_PREPARED_VERSION:-}" = "$version" || { echo "Prepared version mismatch; run 'just prepare-release ${version}' again." >&2; exit 1; }
    test "${SPIVOT_RELEASE_PREPARED_COMMIT:-}" = "$head_commit" || { echo "Prepared commit mismatch; run 'just prepare-release ${version}' again." >&2; exit 1; }
    release_platforms="${SPIVOT_RELEASE_CONTAINER_PLATFORMS:-{{container_platforms}}}"

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
    else
        gh release create "$tag" --title "$tag" --generate-notes "${prerelease_flag[@]}"
    fi

    scripts/releng/upload-release-assets.sh "v${version}" "$release_platforms"

    echo "Published $tag. GitHub Actions will publish OCI tags for {{image}}; the local OCI archive was uploaded to the GitHub release."

[group('release-engineering')]
release-github version release_kind="auto":
    scripts/releng/release-github.sh "{{version}}" "{{release_kind}}"
