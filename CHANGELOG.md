# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-01

### Added

- Core analysis engine (`src/lib/`): dependency-free base64url codec, JWT
  decoder that reports structural errors per-segment instead of throwing,
  and an `explainToken()` rule set covering `alg` header abuse (`none` in
  any casing, missing/non-string `alg`, HS/RS confusion), embedded key
  material (`jwk`/`jku`/`x5c`), suspicious `kid` values, unenforced `crit`
  headers, the full `exp`/`iat`/`nbf` lifecycle (missing, non-numeric,
  expired, far-future, implausible units), and missing `aud`/`iss`/`sub`.
- HS256/384/512 and RS256/384/512 signature verification via Web Crypto,
  plus a built-in dictionary attack against common weak HMAC secrets
  (`crackWeakHmacSecret`) and a secret-strength heuristic
  (`assessSecretStrength`).
- A live decode-as-you-type React + Vite workbench with light/dark theme,
  empty/error/loading states, five bundled example tokens generated fresh
  relative to load time, and inline signature verification against a typed
  secret or PEM public key.
- A CLI (`tokenpit <token>`) exposing the same engine headlessly: JSON
  output, `--secret`/`--now` flags, exit code 1 iff a critical/high finding
  is present.
- Test suite (Vitest + Testing Library): 129 tests, 99.72% line / 100%
  function coverage across the engine, CLI, and UI.
- CI: multi-OS/multi-Node test matrix, a typed-lint + typecheck + coverage
  quality job, and a dogfood job that builds the CLI and asserts its exact
  JSON output and exit code against three bundled fixture tokens.
