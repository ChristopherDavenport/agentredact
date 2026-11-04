#!/usr/bin/env bash
# The second step of a release (AGENTS.md, Releases): once make release
# has tagged the root and its libraries at VERSION and the proxy serves
# them, release each command module at the same version, with no
# replace, so go install takes it.
#
#   scripts/release-command.sh v0.1.0 cmd/agentredact
#
# For each command it drops the replace directives, points every
# first-party require at VERSION, tidies against the proxy, builds and
# tests, commits, guards and tags <dir>/VERSION from that commit; then
# it restores the replaces in a second commit, so the tree builds the
# command against itself again, and pushes the branch and the tags in
# one atomic push. Nothing is pushed if any step fails: git reset --hard
# to the commit before, and git tag -d the tags written.
set -euo pipefail

die() { echo "release-command: $*" >&2; exit 1; }

VERSION="${1:-}"; shift || true
[ -n "$VERSION" ] && [ $# -gt 0 ] || die "usage: $0 <version> <command-dir>..."
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -z "$(git status --porcelain)" ] || die "working tree is not clean"
git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null || die "the root is not tagged $VERSION: run make release first"
MODULE="$(GOWORK=off go list -m)"
err="$(cd "$(mktemp -d)" && GOWORK=off GOFLAGS= go list -m -e -f '{{with .Error}}{{.Err}}{{end}}' "$MODULE@$VERSION" 2>&1)"
[ -z "$err" ] || die "$MODULE@$VERSION is not on the proxy yet: $err"

# Each dropped replace, as dir|old=new, to restore after the tag; a list
# rather than an associative array, which the bash macOS ships lacks.
restore=""
for c in "$@"; do
  [ -f "$c/go.mod" ] || die "no module at $c"
  pairs="$(cd "$c" && GOWORK=off go mod edit -json | awk '
    /"Replace"/ { in_r = 1 }
    in_r && /"Old"/ { want = "old" }
    in_r && /"New"/ { want = "new" }
    in_r && /"Path"/ && want != "" {
      gsub(/[",]/, "", $2); if (want == "old") o = $2; else { print o "=" $2 }; want = ""
    }')"
  for p in $pairs; do restore="$restore $c|$p"; done
  for p in $pairs; do
    (cd "$c" && GOWORK=off go mod edit -dropreplace="${p%%=*}")
  done
  "$HERE/versions.sh" set "$VERSION" "$c"
  (cd "$c" && GOWORK=off GOFLAGS=-mod=mod go mod tidy && GOWORK=off GOFLAGS=-mod=readonly go build ./... && GOWORK=off GOFLAGS=-mod=readonly go test ./...)
done
git add -A
git commit -q -m "Release $* $VERSION"

tags=""
for c in "$@"; do
  "$HERE/release-guard.sh" "$c/$VERSION"
  notes="$("$HERE/release-notes.sh" "$VERSION")"
  git tag -a "$c/$VERSION" -m "$notes"
  tags="$tags $c/$VERSION"
done

for r in $restore; do
  (cd "${r%%|*}" && GOWORK=off go mod edit -replace="${r#*|}")
done
for c in "$@"; do
  (cd "$c" && GOWORK=off GOFLAGS=-mod=mod go mod tidy)
done
git add -A
git commit -q -m "Point $* at the tree again after $VERSION"

# shellcheck disable=SC2086
git push origin --atomic HEAD $tags
