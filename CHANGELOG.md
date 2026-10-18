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
