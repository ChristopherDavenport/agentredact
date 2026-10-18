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
- Added: the string redactors `Secrets` (exact values, longest first);
  `HomePaths` (paths under home become `~`-relative, home bounded on
  both sides, any of `/`, `\`, `\\` and `\/` between segments, a drive
  letter in either case); `Patterns` and `DefaultPatterns`, each match
  written `[REDACTED <name>]`, over `DefaultSecretPatterns`, a copy of
  agentpolicy v0.0.17's `guard.DefaultSecrets` that a test pins; and
  `ParseRules`, git-filter-repo's `--replace-text` format, `glob:`
  included, refusing what filter-repo would silently misread, with
  errors naming the line.
- Added: a profile's joined string function (`Profile.StringFunc`,
  `Chain`) keeps a base64 data URL's payload as it is and gives its
  media type and parameters to the redactors, so a pattern matching an
  inline image's payload by chance does not corrupt it.
- Added: the `EntryRedactor` and `HeaderRedactor` interfaces;
  `Environment`, which blanks an env entry's cwd, vcs, files, tools and
  harness members, keeps workspace substitutions as placeholders
  numbered along the entry's path, and blanks the header's cwd; and
  `Images`, which replaces whole-string inline images with a placeholder
  data URL and reports sidecar ones.
- Added: `Redact`, which applies a profile to one session in memory: a
  new header with `redacted`, `redacted_from` and the derived ID, its
  unknown members' names renamed; one redacted entry per original entry
  marked `[n]`, references re-pointed, request hashes recomputed
  (cleared where the original's did not verify); an entry holding a
  member name the redactors would change refused with
  `ErrKeyNotRedacted`; and resuming an existing redaction by appending
  only the entries past its highest position. A fork is written without
  a base; writing a fork of a redaction is the store pass's (#3), which
  adds that mode.
- Added: `Finding`, local reports of what `Redact` kept: sidecar
  references, inline non-image media, image data URLs inside longer
  strings, references into other sessions, extension entries, and
  instruction parts that keep the original's hash.
- Changed: `make deps` checks what the tests import too.
