#!/usr/bin/env bash
# Tests of scripts/release-command.sh's refusals, against throwaway
# repositories and a file proxy: each refusal must come before anything
# is changed, the tree clean and HEAD where it was. Then a whole
# release, and one refused for a file the build left in the tree.
#
#   scripts/release-command-test.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
M=example.com/m
fails=0

# refuse <name> <setup: tagged|unserved-lib|behind-origin|no-test-flag|path-origin|branch> <what it says>
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
    if [ "$setup" = path-origin ]; then
      git remote add origin "$d/origin.git"
    else
      git remote add origin "file://$d/origin.git"
    fi
    git push -q origin main --tags 2>/dev/null
    case "$setup" in
      tagged) git tag cmd/x/v0.0.2 ;;
      behind-origin)
        git -c user.email=t@t -c user.name=t commit -q --allow-empty -m later
        git push -q origin main 2>/dev/null
        git reset -q --hard HEAD~1 ;;
      branch) git checkout -q -b topic ;;
    esac
    flag=1; [ "$setup" = no-test-flag ] && flag=
    before="$(git rev-parse HEAD)"
    GOMODCACHE="$d/modcache" GOFLAGS=-modcacherw RELEASE_COMMAND_TEST="$flag" RELEASE_PROXY="file://$d/proxy" GONOSUMDB="$M" GOSUMDB=off GOWORK=off \
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
refuse "RELEASE_PROXY outside a test" no-test-flag "RELEASE_PROXY"
refuse "RELEASE_PROXY with an origin not file://" path-origin "RELEASE_PROXY"
refuse "a branch other than main" branch "not on main"

# published <dir> [stray]: a repository at <dir>/work whose root and
# lib were tagged v0.0.2, pushed to a file:// origin at <dir>/origin.git
# and served by a file proxy at <dir>/proxy with real module zips,
# written with python3; cmd/x requires both and replaces them with the
# tree. With stray, cmd/x's test writes a file into the command's
# directory, a product of the build the release commit must not take in.
published() {
  d="$1"
  git init -q --bare "$d/origin.git"
  git init -q -b main "$d/work"
  cd "$d/work" || return 1
  mkdir -p scripts lib cmd/x
  cp "$HERE/release-command.sh" "$HERE/versions.sh" "$HERE/release-guard.sh" "$HERE/release-notes.sh" "$HERE/check-extracted.sh" scripts/
  printf 'module %s\n\ngo 1.25\n' "$M" > go.mod
  printf 'package m\n\nfunc Root() int { return 1 }\n' > m.go
  printf 'module %s/lib\n\ngo 1.25\n' "$M" > lib/go.mod
  printf 'package lib\n\nfunc Lib() int { return 2 }\n' > lib/lib.go
  printf 'module %s/cmd/x\n\ngo 1.25\n\nrequire (\n\t%s v0.0.2\n\t%s/lib v0.0.2\n)\n\nreplace (\n\t%s => ../..\n\t%s/lib => ../../lib\n)\n' "$M" "$M" "$M" "$M" "$M" > cmd/x/go.mod
  : > cmd/x/go.sum
  printf 'package main\n\nimport (\n\t"fmt"\n\n\tm "%s"\n\t"%s/lib"\n)\n\nfunc main() { fmt.Println(m.Root() + lib.Lib()) }\n' "$M" "$M" > cmd/x/main.go
  if [ "${2:-}" = stray ]; then
    printf 'package main\n\nimport (\n\t"os"\n\t"testing"\n)\n\nfunc TestStray(t *testing.T) {\n\tif err := os.WriteFile("stray.txt", nil, 0o644); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n' > cmd/x/main_test.go
  fi
  printf '# Changelog\n\n## v0.0.2 - 2026-01-01\n\n- x\n' > CHANGELOG.md
  git add . && git -c user.email=t@t -c user.name=t commit -qm "Release v0.0.2"
  git tag -a v0.0.2 -m v0.0.2 && git tag -a lib/v0.0.2 -m v0.0.2
  git remote add origin "file://$d/origin.git"
  git push -q origin main --tags 2>/dev/null
  for p in "$M:.:m.go" "$M/lib:lib:lib.go"; do
    mod="${p%%:*}"; rest="${p#*:}"; dir="${rest%%:*}"; src="${rest#*:}"
    mkdir -p "$d/proxy/$mod/@v"
    echo v0.0.2 > "$d/proxy/$mod/@v/list"
    printf '{"Version":"v0.0.2","Time":"2026-01-01T00:00:00Z"}\n' > "$d/proxy/$mod/@v/v0.0.2.info"
    cp "$dir/go.mod" "$d/proxy/$mod/@v/v0.0.2.mod"
    python3 -I -c '
import sys, zipfile
mod, out, files = sys.argv[1], sys.argv[2], sys.argv[3:]
with zipfile.ZipFile(out, "w") as z:
    for f in files:
        src, name = f.split("=")
        z.write(src, mod + "@v0.0.2/" + name)
' "$mod" "$d/proxy/$mod/@v/v0.0.2.zip" "$dir/go.mod=go.mod" "$dir/$src=$src" || return 1
  done
}

run_release() {
  GOMODCACHE="$d/modcache" GOFLAGS=-modcacherw RELEASE_COMMAND_TEST=1 RELEASE_PROXY="file://$d/proxy" GONOSUMDB="$M" GOSUMDB=off GOWORK=off \
    bash scripts/release-command.sh v0.0.2 cmd/x
}

# The whole second step, on a release the root and lib were tagged at:
# the command is tagged from a commit whose go.mod holds no replace,
# tidied against the proxy, and holding nothing beside go.mod, go.sum
# and the source (go build of a main package writes its binary into the
# directory, which v0.0.2 of this repository committed); the commit
# after it puts the replaces back, so the tree builds the command
# against itself again. Branch and tag reach origin.
release_ok() {
  d="$(mktemp -d)"
  (
    published "$d" || exit 1
    start="$(git rev-parse HEAD)"
    run_release >"$d/out" 2>&1 || { cat "$d/out"; exit 10; }
    tagged="$(git rev-parse cmd/x/v0.0.2^{commit})" || exit 11
    [ "$tagged" = "$(git rev-parse HEAD~1)" ] || exit 11
    ! git show "$tagged:cmd/x/go.mod" | grep -q replace || exit 12
    git show "$tagged:cmd/x/go.sum" | grep -qF "$M/lib v0.0.2 h1:" || exit 12
    extra="$(git ls-tree -r --name-only "$tagged" | grep -vxE 'cmd/x/(go\.mod|go\.sum|main\.go)' | grep -vxF -f <(git ls-tree -r --name-only "$start"))"
    [ -z "$extra" ] || { echo "the tagged commit adds: $extra"; exit 16; }
    git show HEAD:cmd/x/go.mod | grep -qF "$M => ../.." || exit 13
    git show HEAD:cmd/x/go.mod | grep -qF "$M/lib => ../../lib" || exit 13
    [ "$(git ls-remote origin refs/heads/main | cut -f1)" = "$(git rev-parse HEAD)" ] || exit 14
    git ls-remote --tags origin | grep -q 'refs/tags/cmd/x/v0.0.2$' || exit 14
    [ -z "$(git status --porcelain)" ] || exit 15
    exit 0
  )
  rc=$?
  chmod -R u+w "$d" 2>/dev/null; rm -rf "$d"
  if [ "$rc" != 0 ]; then
    echo "FAIL: release-command on a published release: rc $rc (10 refused, 11 tag not on the release commit, 12 tagged go.mod has a replace or was not tidied against the proxy, 13 replaces not restored, 14 not pushed, 15 tree dirty, 16 tagged commit holds a file beside go.mod, go.sum and the source)"
    fails=$((fails + 1))
  fi
}

# A file the build or tests leave in the tree is refused, not
# committed: release-command stops before its first commit, tags and
# pushes nothing, and prints the undo line.
release_stray() {
  d="$(mktemp -d)"
  (
    published "$d" stray || exit 1
    start="$(git rev-parse HEAD)"
    run_release >"$d/out" 2>&1 && exit 10
    [ "$(git rev-parse HEAD)" = "$start" ] || exit 11
    ! git rev-parse -q --verify refs/tags/cmd/x/v0.0.2 >/dev/null || exit 11
    [ "$(git ls-remote origin refs/heads/main | cut -f1)" = "$start" ] || exit 11
    grep -qF "cmd/x/stray.txt" "$d/out" || { cat "$d/out"; exit 13; }
    grep -qF "undo with: git reset --hard $start" "$d/out" || { cat "$d/out"; exit 13; }
    exit 0
  )
  rc=$?
  chmod -R u+w "$d" 2>/dev/null; rm -rf "$d"
  if [ "$rc" != 0 ]; then
    echo "FAIL: release-command with a stray file in the tree: rc $rc (10 ran through, 11 committed, tagged or pushed, 13 refused for another reason or printed no undo)"
    fails=$((fails + 1))
  fi
}

release_ok
release_stray

[ "$fails" = 0 ] && echo "release-command tests passed"
exit "$fails"
