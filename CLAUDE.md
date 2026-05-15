# CLAUDE.md

For project conventions, build commands, architecture, and contribution
guidelines, see [AGENTS.md](AGENTS.md). Everything below is specific to
the Claude Code operator experience on this repo.

## Commit Signing

Use the repo's configured signing identity. Verify signing is active
before your first commit:

```bash
git config commit.gpgsign   # should return true
```

## CI Gate

**MANDATORY: `just ci` must pass locally before every `git push`. No
exceptions.** Do not rely on GitHub Actions; run the full gate locally
and fix failures before pushing.

## Release Work

This project releases through OCI images. Keep release work focused on
the Dockerfile, `just` recipes, GHCR publication, OCI labels, SBOM and
provenance settings, and healthcheck behavior. Do not add macOS package,
codesign, notarization, or installer workflows.

`just release-github <version> [kind]` requires Docker Buildx. It builds
and uploads a multi-architecture OCI archive, checksum, and Buildx
metadata to the GitHub release, then relies on the tag-triggered workflow
for GHCR publication. The archive builder defaults to a managed
`docker-container` Buildx builder named `spivot-release`; override it with
`SPIVOT_BUILDX_BUILDER` if needed.

## GitHub Collaboration

Be a good GitHub collaborator. Review threads left open signal
unfinished work; always close the loop.

When addressing review feedback:

1. Fix the issue in a commit.
2. Reply to the thread with the fixing commit hash and a one-line
   explanation.
3. Resolve the conversation.
4. If deferring out of scope, say so explicitly before resolving.

After a round of fixes, request re-review so the reviewer knows the ball
is back in their court.

Resolving threads via CLI:

```bash
gh api graphql -f query='mutation { resolveReviewThread(input: {threadId: "THREAD_ID"}) { thread { isResolved } } }'
```

PR hygiene:

- Check off test plan items as they are verified.
- Use `Refs #NNN` or `Closes #NNN` in commit bodies.
- Keep the PR description accurate as scope evolves.
