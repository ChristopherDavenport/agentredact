GO ?= go
STATICCHECK ?= $(GO) run honnef.co/go/tools/cmd/staticcheck@latest
GOVULNCHECK ?= $(GO) run golang.org/x/vuln/cmd/govulncheck@latest

# Nested modules, tested alongside the root and released with it at one
# version. secrets is the streaming secret redactor, standard library
# only, which programs that never read a session import without the
# rest of this module; the root requires it, at exactly the version the
# whole repository is released at, through a replace pointing at the
# tree (see replaces below).
SUBMODULES = secrets

# Every module here: the root and the nested ones. The version bump,
# the replace check and the extracted build go over all of them, since
# here it is the root that requires a nested module.
MODULES = . $(SUBMODULES)

.PHONY: build deps replaces test vet fmt tidy tidy-check lint vuln check \
	extracted guard-test release-guard release release-commit clean

build:
	$(GO) build ./...
	@for m in $(SUBMODULES); do (cd $$m && $(GO) build ./...) || exit 1; done

# The root must build from the standard library, its own secrets
# module, agentsession, openresponses and agentpolicy alone, and reach
# no module beyond those but the agentturn and agenttool agentpolicy
# brings in: no third-party module, since every dependency sees
# unredacted sessions. secrets, which sees the secrets themselves,
# imports the standard library alone.
deps:
	@GO="$(GO)" scripts/check-deps.sh
	@deps=$$(cd secrets && $(GO) list -deps -test -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... \
	  | grep -Ev '^github.com/ChristopherDavenport/agentredact/secrets( |$$|\.test$$)' || true); \
	  test -z "$$deps" || { echo "secrets depends on: $$deps"; exit 1; }

# Every first-party module a module requires must also be replaced, at a
# path that exists: go mod tidy ignores go.work, so a require naming the
# version being released resolves from the proxy, where that version
# does not exist until the tag is pushed. The replace is what lets a
# release name its own version. Consumers ignore a replace and get the
# require, which names the commit the module is tagged from;
# release-guard is what proves it.
replaces:
	@scripts/check-replaces.sh $(MODULES)

test:
	$(GO) test -race ./...
	@for m in $(SUBMODULES); do (cd $$m && $(GO) test -race ./...) || exit 1; done

vet:
	$(GO) vet ./...
	@for m in $(SUBMODULES); do (cd $$m && $(GO) vet ./...) || exit 1; done

tidy:
	$(GO) mod tidy
	@for m in $(SUBMODULES); do (cd $$m && $(GO) mod tidy) || exit 1; done

# Fails when go mod tidy would change any go.mod or go.sum, without
# writing, so a stray dependency shows up in make check and not only in
# CI's diff.
tidy-check:
	$(GO) mod tidy -diff
	@for m in $(SUBMODULES); do (cd $$m && $(GO) mod tidy -diff) || exit 1; done

fmt:
	gofmt -l . && test -z "$$(gofmt -l .)"

lint:
	$(STATICCHECK) ./...
	@for m in $(SUBMODULES); do (cd $$m && $(STATICCHECK) ./...) || exit 1; done

vuln:
	$(GOVULNCHECK) ./...
	@for m in $(SUBMODULES); do (cd $$m && $(GOVULNCHECK) ./...) || exit 1; done

# Everything CI runs. In this workspace run it as
# GOWORK=off GOFLAGS=-mod=readonly make check.
check: fmt tidy-check vet deps replaces lint vuln test guard-test

# Builds, vets and tests each module the way a consumer gets it:
# extracted to a directory with no parent go.mod, with the in-tree
# replace dropped, so its require lines are answered by the proxy (see
# scripts/check-extracted.sh). Needs the network, so it is not part of
# check; CI runs it.
extracted:
	@scripts/check-extracted.sh $(MODULES)

# The release guard's own tests, against throwaway repositories.
guard-test:
	@scripts/release-guard-test.sh

# Checks one tag is safe to push, before it is pushed. A pushed tag is
# permanent — the proxy and the checksum database keep the version
# forever — so this is the last point at which a mistake is free:
#   make release-guard TAG=v0.1.0
#   make release-guard TAG=secrets/v0.1.0
release-guard:
	@test -n "$(TAG)" || { echo "usage: make release-guard TAG=<tag>"; exit 1; }
	@scripts/release-guard.sh "$(TAG)"

# Every tag a release writes: the root and one per nested module, all at
# the same version, all from the one commit below.
RELEASE_TAGS = $(VERSION) $(patsubst %,%/$(VERSION),$(SUBMODULES))

# Cut a release:
#
#   make release VERSION=v0.1.0
#
# Every module is released at one version, from one commit, and the
# root requires secrets at exactly that version, so a consumer who takes
# the root at vX.Y.Z gets secrets vX.Y.Z, the commit it was built and
# tested against. The first thing this does is point every first-party
# require at VERSION, a version that does not exist yet; the replace
# makes that resolve to the tree.
#
# The guard runs after the commit and before each tag, which is the last
# moment everything is still local: if it refuses, undo with git reset
# --hard HEAD~1 and git tag -d the tags written. The root is guarded and
# tagged first, then each nested module, because a nested module's guard
# proves the root tag of that version names this commit. --atomic lands
# the branch and every tag in one transaction, so no window exists in
# which a tag is visible without the commit it names.
release: release-commit
	@scripts/release-guard.sh "$(VERSION)"
	@notes="$$(scripts/release-notes.sh $(VERSION))" || exit 1; \
	 git tag -a $(VERSION) -m "$$notes"
	@notes="$$(scripts/release-notes.sh $(VERSION))" || exit 1; \
	 for m in $(SUBMODULES); do \
	   scripts/release-guard.sh "$$m/$(VERSION)" || exit 1; \
	   git tag -a $$m/$(VERSION) -m "$$notes" || exit 1; \
	 done
	git push origin --atomic HEAD $(RELEASE_TAGS)

# Bump every first-party requirement to VERSION, date the changelog,
# check everything, commit. Nothing here is pushed, so a failure costs a
# git reset and no more. TRAILER, when set, is appended to the commit
# message. go mod tidy is free to move a requirement the bump just set,
# so what landed is read back and asserted before anything is committed.
#
# The changelog is dated through a temp file rather than sed -i, which is
# a GNU-ism: BSD sed reads the argument after -i as a backup suffix, so
# the GNU spelling fails outright on macOS, where these releases are cut.
# The temp file is removed if sed dies, so a failed run leaves nothing
# untracked behind for the clean-tree gate to trip over next time.
#
# GitHub creates no events for a push of more than three tags, so the
# release workflow would silently never run; a third nested module means
# choosing between the atomic push and creating the releases with gh.
release-commit:
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=vX.Y.Z"; exit 1; }
	@test $(words $(RELEASE_TAGS)) -le 3 || { echo "$(words $(RELEASE_TAGS)) tags would be pushed at once, and GitHub creates no events for a push of more than three"; exit 1; }
	@test "$(origin SUBMODULES)" = file || { echo "do not override SUBMODULES here: the override would reach the bump, tidy and check, so a module would be tagged having checked a subset."; exit 1; }
	@grep -q '^## Unreleased$$' CHANGELOG.md || { echo "CHANGELOG.md has no Unreleased section"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "working tree is not clean"; exit 1; }
	@scripts/versions.sh set $(VERSION) $(MODULES)
	sed 's/^## Unreleased$$/## $(VERSION) - '"$$(date +%F)"'/' CHANGELOG.md > CHANGELOG.md.tmp \
	  && mv CHANGELOG.md.tmp CHANGELOG.md \
	  || { rm -f CHANGELOG.md.tmp; exit 1; }
	$(MAKE) tidy
	$(MAKE) check
	@scripts/versions.sh check $(VERSION) $(MODULES)
	git add -A && git commit -q -m "Release $(VERSION)" $(if $(TRAILER),-m "$(TRAILER)")

clean:
	rm -rf .cache
