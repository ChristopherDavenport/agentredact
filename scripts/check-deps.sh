#!/usr/bin/env bash
# Holds the module to its dependency rule. Every package imports the
# standard library, this module, agentsession, openresponses and
# agentpolicy alone. At any depth the build may reach only those
# modules and the two agentpolicy brings in from the same family,
# agentturn and agenttool (agentpolicy/guard imports both): no
# third-party module, and not agentsession's nested modules
# (agentsession/sqlite brings a driver, agentsession/otel an SDK).
#
# agentredact reads unredacted sessions, so every dependency is code
# that sees them before the gates do. A dependency outside the rule
# needs a decision in docs/plans/agentredact.md first, and a change here
# in the same commit. TruffleHog is run as a binary through os/exec for
# this reason, not linked.
#
#   GO=go scripts/check-deps.sh
#
# Exits non-zero, naming each offence, or when go list fails.
set -euo pipefail
GO=${GO:-go}

module=$($GO list -m)
family=github.com/ChristopherDavenport

# Modules a package of this module may import directly, and the ones
# the build may reach at any depth. Matched against module paths, not
# import paths, so a nested module such as agentsession/sqlite is its
# own module and refused.
direct=" $module $family/agentsession $family/openresponses $family/agentpolicy "
reach="$direct$family/agentturn $family/agenttool "

# Every package the build reaches outside the standard library, with
# its module, and every package's direct imports. A package with no
# module is one go list could not resolve, which go build would refuse
# too. awk joins the two, since bash 3.2, which macOS ships, has no
# associative arrays.
#
# -test takes in what the tests import, which run on the same unredacted
# sessions. It lists a package's test variant as "pkg [pkg.test]", so the
# module is printed first and the import path second, and the bracketed
# variant name is a field no package is keyed by.
pkgs=$($GO list -deps -test -f '{{if not .Standard}}{{with .Module}}{{.Path}}{{else}}?{{end}} {{.ImportPath}}{{end}}' ./...)
imports=$($GO list -test -f '{{.ImportPath}}{{range .Imports}} {{.}}{{end}}' ./...)

# Direct imports, by module, from the direct set alone; then every
# module the build reaches, from the reach set.
awk -v direct="$direct" -v reach="$reach" '
  FNR == NR { if (NF) mod[$2] = $1; next }
  {
    for (i = 2; i <= NF; i++) {
      if (!($i in mod)) continue # the standard library
      m = mod[$i]
      if (index(direct, " " m " ") == 0) { print $1 " imports " $i " (module " m ")"; bad = 1 }
    }
  }
  END {
    for (p in mod) if (index(reach, " " mod[p] " ") == 0) extra[mod[p]] = 1
    for (m in extra) { print "module depends on: " m; bad = 1 }
    exit bad
  }
' <(printf '%s\n' "$pkgs") <(printf '%s\n' "$imports")
