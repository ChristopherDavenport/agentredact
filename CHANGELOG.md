# Changelog

All user-visible changes to this library. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/); before v1.0.0 minor
versions may break the API.

## Unreleased

- Added: the repository scaffold. `docs/plans/agentredact.md` is the
  design, written against agentsession v0.0.28 (format 0.13): the
  redactors (#2), the store-wide pass (#3), the scan (#4), the review
  (#5), and the manifest and publish (#6). The `agentredact` package
  holds its documentation alone; no API yet. `make deps` holds the
  module to the standard library, agentsession, openresponses and
  agentpolicy.
- Added: `Profile`, a named, versioned redactor set, and
  `ValidateProfileName` (`<name>@<version>`, version an integer from 1).
- Added: the string redactors `Secrets` (exact values, longest first),
  `HomePaths` (paths under home become `~`-relative, `/` and `\`
  separators), `Patterns` and `DefaultPatterns` (agentpolicy's
  `guard.DefaultSecrets`, each match written `[REDACTED <name>]`), and
  `ParseRules`, git-filter-repo's `--replace-text` format, `glob:`
  included, with errors naming the line.
- Added: the `EntryRedactor` and `HeaderRedactor` interfaces;
  `Environment`, which blanks an env entry's cwd, vcs, files, tools and
  harness members, keeps workspace substitutions as numbered
  placeholders, and blanks the header's cwd; and `Images`, which
  replaces inline images with a placeholder data URL and reports
  sidecar ones as `Finding`s.
- Added: `Redact`, which applies a profile to one session in memory:
  a new header with `redacted`, `redacted_from` and the derived ID, one
  redacted entry per original entry marked `[n]`, references re-pointed,
  request hashes recomputed (cleared where the original's did not
  verify), a fork written without a base, and resuming an existing
  redaction by appending only the entries past its highest position.
- Added: a profile's joined string function (`Profile.StringFunc`,
  `Chain`) passes a string that is wholly a base64 data URL untouched,
  so a pattern matching an inline image's payload by chance no longer
  corrupts it when a profile has no `Images`.
- Added: `Redact` reports, as a `Finding` with the part's id, each
  instruction part that keeps the original's hash because its text is in
  no entry the redaction was given.
