# ADR 0006: Route files to servers by extension with rootDir longest-match tie-breaker

## Status

Accepted

## Context

Multi-language repos may run multiple servers for overlapping extensions or nested project roots. A simple “first match by extension” becomes ambiguous in monorepos.

## Decision

- Select servers by file extension.
- If multiple servers match, choose the server whose `rootDir` is the most specific container of the file (longest path match).
- If no `rootDir` contains the file, fall back to the first match.

## Consequences

- Predictable routing in nested repos.
- Requires path normalization and correct Windows path handling.
- Config authors can disambiguate by setting `rootDir` appropriately.

