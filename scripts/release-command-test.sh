#!/usr/bin/env bash
# Tests of scripts/release-command.sh's refusals, against throwaway
# repositories and a file proxy: each refusal must come before anything
# is changed, the tree clean and HEAD where it was.
#
#   scripts/release-command-test.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
M=example.com/m
fails=0

# refuse <name> <setup: tagged|unserved-lib|behind-origin> <what it says>
refuse() {
  name="$1"; setup="$2"; says="$3"
  d="$(mktemp -d)"
  git init -q --bare "$d/origin.git"
  git init -q -b main "$d/work"
  mkdir -p "$d/proxy/$M/@v" "$d/proxy/$M/lib/@v"
  serve() {
    echo v0.0.2 > "$d/proxy/$1/@v/list"
    printf '{"Version":"v0.0.2","Time":"2026-01-01T00:00:00Z"}\n' > "$d/proxy/$1/@v/v0.0.2.info"
    printf 'module %s\n\ngo 1.25\n' "$1" > "$d/proxy/$1/@v/v0.0.2.mod"
  }
  serve "$M"
  if [ "$setup" = unserved-lib ]; then : > "$d/proxy/$M/lib/@v/list"; else serve "$M/lib"; fi
  (
    cd "$d/work" || exit 1
    mkdir -p scripts lib cmd/x
    cp "$HERE/release-command.sh" "$HERE/versions.sh" "$HERE/release-guard.sh" "$HERE/release-notes.sh" "$HERE/check-extracted.sh" scripts/
    printf 'module %s\n\ngo 1.25\n' "$M" > go.mod
    printf 'module %s/lib\n\ngo 1.25\n' "$M" > lib/go.mod
    printf 'module %s/cmd/x\n\ngo 1.25\n\nrequire %s v0.0.2\n\nreplace %s => ../..\n' "$M" "$M" "$M" > cmd/x/go.mod
    printf '# Changelog\n\n## v0.0.2 - 2026-01-01\n\n- x\n' > CHANGELOG.md
    git add . && git -c user.email=t@t -c user.name=t commit -qm init
    git tag v0.0.2 && git tag lib/v0.0.2
    git remote add origin "$d/origin.git"
    git push -q origin main --tags 2>/dev/null
    case "$setup" in
      tagged) git tag cmd/x/v0.0.2 ;;
      behind-origin)
        git -c user.email=t@t -c user.name=t commit -q --allow-empty -m later
        git push -q origin main 2>/dev/null
        git reset -q --hard HEAD~1 ;;
    esac
    before="$(git rev-parse HEAD)"
    GOMODCACHE="$d/modcache" GOFLAGS=-modcacherw RELEASE_PROXY="file://$d/proxy" GONOSUMDB="$M" GOSUMDB=off GOWORK=off \
      bash scripts/release-command.sh v0.0.2 cmd/x >/dev/null 2>"$d/err" && exit 10
    [ "$(git rev-parse HEAD)" = "$before" ] || exit 11
    [ -z "$(git status --porcelain)" ] || exit 12
    grep -qF -- "$says" "$d/err" || exit 13
    exit 0
  )
  rc=$?
  chmod -R u+w "$d" 2>/dev/null; rm -rf "$d"
  if [ "$rc" != 0 ]; then
    echo "FAIL: release-command $name: rc $rc (10 ran through, 11 committed, 12 left the tree dirty, 13 refused for another reason)"
    fails=$((fails + 1))
  fi
}

refuse "a command tag that exists" tagged "cmd/x/v0.0.2 is tagged already"
refuse "a library the proxy does not serve" unserved-lib "$M/lib@v0.0.2 is not on the proxy"
refuse "HEAD behind origin/main" behind-origin "does not contain origin/main"

[ "$fails" = 0 ] && echo "release-command tests passed"
exit "$fails"
