#!/usr/bin/env bash
#
# release.sh - Verify, commit, tag and release a new version.
#
# All quality gates live in ./pre-release.sh, which is run first. Nothing is
# committed, tagged or pushed unless every check passes.
#
# Usage:
#   ./release.sh v1.2.3            # release a specific version
#   ./release.sh patch             # bump the patch component of the latest tag
#   ./release.sh minor             # bump the minor component
#   ./release.sh major             # bump the major component
#
# Environment variables:
#   DRY_RUN=1        Run every check and print what would happen, changing nothing
#   ALLOW_DIRTY=1    Commit any uncommitted changes as part of the release
#   REMOTE=origin    Git remote to push to (default: origin)
#   SKIP_LINT / SKIP_RACE / AUTO_INSTALL / MIN_COVERAGE  -> passed to pre-release.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

REMOTE="${REMOTE:-origin}"
DRY_RUN="${DRY_RUN:-0}"
ALLOW_DIRTY="${ALLOW_DIRTY:-0}"

if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
  BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; RESET=""
fi

info() { printf '\n%s==> %s%s\n' "${BLUE}${BOLD}" "$1" "$RESET"; }
ok()   { printf '%s    ✓ %s%s\n' "$GREEN" "$1" "$RESET"; }
warn() { printf '%s    ! %s%s\n' "$YELLOW" "$1" "$RESET"; }
fail() { printf '\n%s    ✗ %s%s\n' "${RED}${BOLD}" "$1" "$RESET" >&2; exit 1; }

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '%s    [dry-run] %s%s\n' "$YELLOW" "$*" "$RESET"
  else
    "$@"
  fi
}

usage() {
  sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

[[ $# -eq 1 ]] || usage

# ---------------------------------------------------------------------------
# Resolve the target version
# ---------------------------------------------------------------------------
LATEST_TAG="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n1)"

bump() {
  local component="$1" base="${LATEST_TAG:-v0.0.0}"
  local major minor patch
  IFS='.' read -r major minor patch <<<"${base#v}"
  case "$component" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
  esac
  printf 'v%s.%s.%s' "$major" "$minor" "$patch"
}

case "$1" in
  major|minor|patch) VERSION="$(bump "$1")" ;;
  *)                 VERSION="$1" ;;
esac

if [[ ! $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  fail "Version must be of the form vMAJOR.MINOR.PATCH (got '${VERSION}')."
fi

printf '%sdnsaudit release%s\n' "$BOLD" "$RESET"
printf '    previous: %s\n' "${LATEST_TAG:-<none>}"
printf '    releasing: %s%s%s\n' "$BOLD" "$VERSION" "$RESET"
[[ "$DRY_RUN" == "1" ]] && warn "DRY_RUN=1 - no changes will be made"

# ---------------------------------------------------------------------------
info "Repository preflight"
# ---------------------------------------------------------------------------
git rev-parse --git-dir >/dev/null 2>&1 || fail "Not inside a git repository."

if git rev-parse -q --verify "refs/tags/${VERSION}" >/dev/null; then
  fail "Tag ${VERSION} already exists locally."
fi
if git ls-remote --exit-code --tags "$REMOTE" "refs/tags/${VERSION}" >/dev/null 2>&1; then
  fail "Tag ${VERSION} already exists on ${REMOTE}."
fi
ok "Tag ${VERSION} is available"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
ok "On branch ${BRANCH}"

DIRTY="$(git status --porcelain)"
if [[ -n "$DIRTY" ]]; then
  if [[ "$ALLOW_DIRTY" != "1" ]]; then
    printf '%s\n' "$DIRTY" >&2
    fail "Working directory is not clean. Commit/stash the changes above, or re-run with ALLOW_DIRTY=1 to include them in the release commit."
  fi
  warn "Working directory is dirty; changes will be committed with the release"
else
  ok "Working directory is clean"
fi

# ---------------------------------------------------------------------------
info "Pre-release verification"
# ---------------------------------------------------------------------------
[[ -x ./pre-release.sh ]] || fail "./pre-release.sh is missing or not executable."
./pre-release.sh || fail "Pre-release verification failed. Nothing has been committed, tagged or pushed."

# ---------------------------------------------------------------------------
info "Commit"
# ---------------------------------------------------------------------------
if [[ -n "$DIRTY" ]]; then
  run git add -A
  run git commit -m "Release ${VERSION}"
  ok "Committed working tree changes"
else
  ok "Nothing to commit"
fi

# ---------------------------------------------------------------------------
info "Tag"
# ---------------------------------------------------------------------------
# Annotate the tag with the commit subjects since the previous release.
if [[ -n "$LATEST_TAG" ]]; then
  CHANGELOG="$(git log --pretty=format:'  - %s' "${LATEST_TAG}..HEAD" || true)"
else
  CHANGELOG="$(git log --pretty=format:'  - %s' || true)"
fi
TAG_MESSAGE="Release ${VERSION}"
[[ -n "$CHANGELOG" ]] && TAG_MESSAGE+=$'\n\nChanges:\n'"$CHANGELOG"

run git tag -a "$VERSION" -m "$TAG_MESSAGE"
ok "Created annotated tag ${VERSION}"

# ---------------------------------------------------------------------------
info "Push"
# ---------------------------------------------------------------------------
run git push "$REMOTE" "$BRANCH"
run git push "$REMOTE" "$VERSION"
ok "Pushed ${BRANCH} and ${VERSION} to ${REMOTE}"

# ---------------------------------------------------------------------------
info "Publish"
# ---------------------------------------------------------------------------
if command -v goreleaser >/dev/null 2>&1 && [[ -f .goreleaser.yml || -f .goreleaser.yaml ]]; then
  GORELEASER_ARGS=(release --clean)
  # SBOM generation requires syft; skip it locally rather than failing the
  # release. CI installs syft, so released artefacts still get an SBOM.
  if ! command -v syft >/dev/null 2>&1; then
    warn "syft not found; skipping SBOM generation for this local release"
    GORELEASER_ARGS+=(--skip=sbom)
  fi
  run goreleaser "${GORELEASER_ARGS[@]}"
  ok "goreleaser finished"
elif command -v gh >/dev/null 2>&1; then
  run gh release create "$VERSION" --title "$VERSION" --generate-notes
  ok "GitHub release created via gh"
else
  warn "Neither goreleaser (with config) nor gh found; CI should handle publication on tag push."
fi

printf '\n%s%s %s released.%s\n\n' "${GREEN}${BOLD}" "✓" "$VERSION" "$RESET"
