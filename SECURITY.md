# Security policy

Tidewatch opens files that may come from compromised machines, so we treat parsing bugs as
security bugs.

## Reporting a vulnerability

Please **don't open a public issue**. Report it privately through GitHub instead:
**Security → Report a vulnerability** on this repository.

Include the Tidewatch version, what you did, and, if possible, a file that reproduces the
problem (a minimal `.evtx` or Sigma rule). Please strip any real customer data first.

We aim to acknowledge reports within a few days and to fix confirmed issues in the next
release.

## Hardening in place

- Malformed EVTX chunks are skipped instead of crashing the app; parser panics are contained.
- Records are bounded: field values over 1 MiB are truncated, nesting depth and the number of
  distinct field names per file are capped.
- Imported Sigma rules are untrusted input: YAML size and alias expansion are capped,
  conditions have a nesting limit, regexes have size limits, symlinks and special files are
  never followed, and a crashed import is not retried automatically on the next launch.
- Only `http`/`https` links from rule files are clickable.
- CSV exports neutralise spreadsheet formulas (cells starting with `=`, `+`, `-`, `@`).
- Release builds use the hardened runtime, pinned GitHub Actions and `--locked` dependencies,
  and signing secrets are only available to release-tag builds.
