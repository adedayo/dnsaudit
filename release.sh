#!/usr/bin/env bash

# release.sh - Tag a new version and push for CI automation.
# Usage: ./release.sh vX.Y.Z

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <tag> (e.g., $0 v1.2.1)"
  exit 1
fi

VERSION="$1"

# Ensure the tag is in proper semantic version format
if [[ ! $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: Version must be of the form vMAJOR.MINOR.PATCH"
  exit 1
fi

# Verify we are on a clean git tree
if [[ -n $(git status --porcelain) ]]; then
  echo "Error: Working directory not clean. Commit or stash changes before releasing."
  exit 1
fi

# Run tests and lint before releasing
echo "Running tests..."
go test ./... -cover

echo "Running golangci-lint..."
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run ./...
else
  echo "golangci-lint not installed; skipping lint step."
fi

# Create and push the tag
git tag -a "$VERSION" -m "Release $VERSION"

git push origin "$VERSION"

echo "Tag $VERSION pushed."

# Trigger GoReleaser if available (CI will also run on tag push)
if command -v goreleaser >/dev/null 2>&1; then
  echo "Running goreleaser locally..."
  goreleaser release --rm-dist
else
  echo "goreleaser not installed. CI will handle the release on tag push."
fi
