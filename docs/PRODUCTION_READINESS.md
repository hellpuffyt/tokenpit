# Production readiness — tokenpit

Tested commit: `21ba48a` (audit/production-readiness, code changes; this file
was added in the following docs-only commit). Date: 2026-10-22.

## Scope and architecture

tokenpit decodes a compact JWS (three-segment JWT), verifies HS256/384/512 and
RS256/384/512 signatures with Web Crypto, tries a small dictionary of
known-weak HMAC secrets, and explains every header field and claim as a
severity-ranked finding. One engine (`src/lib/`, zero runtime dependencies) is
shared by a React + Vite workbench (`src/App.tsx`) and a Node CLI
(`src/cli.ts`). It is a diagnostic tool, not a JWT library, and it does not
decide whether a token should be accepted by your system.

## Platforms and prerequisites

- Node `^22.22.2 || ^24.15.0 || >=26` (from `package.json` `engines`), npm.
- Verified locally on macOS 27 (Apple M5), Node 24.19.0, npm 11.17.0.
- The default-branch CI runs the test/build matrix on ubuntu, macOS and
  Windows with Node 22 and 24. Windows was not run locally for this audit.

## Clean-clone verification

Fresh `git clone` of the audit branch into a scratch directory, then the
README commands literally:

| Command | Exit | Result |
|---|---|---|
| `npm install` | 0 | |
| `npm test` | 0 | 13 files, 172 passed, 0 failed, 0 skipped |
| `npm run coverage` | 0 | thresholds met |
| `npm run lint` | 0 | |
| `npm run typecheck` | 0 | |
| `npm run build` | 0 | |
| `npm run build:cli` | 0 | |
| `node dist-cli/cli.js <weak-secret example> --now 1735689600` | 1 | `hmac-secret-weak` critical, as documented |
| `npm run dev` + HTTP GET `/` | — | 200, server stopped afterwards |

## Commands and results (working clone)

| Check | Command | Before audit | After audit |
|---|---|---|---|
| Install | `npm ci` | 0 | 0 |
| Tests | `npm test` | 0 — 12 files, 129 passed | 0 — 13 files, 172 passed, 0 failed, 0 skipped |
| Tests after `build:cli` | `npm run build:cli && npm test` | 0 — but 266 tests (compiled duplicates collected from `dist-cli/`) | 0 — 172 |
| Coverage | `npm run coverage` | 0 — lines 99.72%, branches 94.7% | 0 — lines 99.73%, branches 95.1% |
| Lint | `npm run lint` | 0 | 0 |
| Typecheck | `npm run typecheck` | 0 | 0 |
| Web build | `npm run build` | 0 | 0 |
| CLI build | `npm run build:cli` | 0 (shipped compiled tests) | 0 (engine + CLI only) |
| CI dogfood replay | the three exact-output CLI checks from `ci.yml` | — | all three outputs identical, exit codes 1/1/0 |
| Browser render | `vite preview` + headless Chromium, load the weak-secret example | — | renders, critical finding shown, no console errors, no requests to other origins |
| Runtime dependency audit | `npm audit --omit=dev` | 0 vulnerabilities | 0 vulnerabilities |
| Full audit | `npm audit` | 7 (4 high, 3 moderate), all dev-only | 3 moderate, dev-only (vitest; fix requires vitest 5) |

## CI status

Default branch: success (latest `main` run). Audit branch: pending until pushed.

## Bugs found and fixed

1. **Algorithm-confusion forgery shown as authentic (security).** An HS256
   token HMAC-signed with an RSA public key verified and was reported as
   `signature-valid` (info), with a green "Signature verifies" line, when that
   PEM was pasted as the key. Fix: `looksLikePublicKey()` plus a critical
   `alg-confusion-forged` finding in the CLI and workbench. Regression tests:
   `src/lib/adversarial.test.ts` (engine + CLI, real generated RSA key),
   `src/App.test.tsx` (workbench).
2. **kid injection probes missed.** `/dev/null`, `/etc/passwd`, `C:\...`,
   `key|whoami`, `key && id`, `k$(id)`, NUL bytes were not flagged. Fix: broader
   `SUSPICIOUS_KID_PATTERN` + NUL check. Regression: `kid injection probes` in
   `adversarial.test.ts`, including benign kids that must stay unflagged.
3. **CLI build shipped tests; tests ran twice.** `tsconfig.cli.json` compiled
   `*.test.ts` into `dist-cli/`, and vitest then collected them. Fix: exclude
   tests from the CLI build and build output from vitest. Regression:
   `CLI build configuration` test in `src/cli.test.ts`.
4. **Dev-dependency advisories** (vite dev server, undici, brace-expansion,
   source-map-js) resolved with `npm audit fix` inside existing ranges.

## Security review

- Secret scan of the tree and of all history (token/key patterns, private
  keys, local paths): no hits. The HMAC secrets in tests/CI are deliberately
  public example values.
- No HTML injection surface: React renders all token content as text; no
  `dangerouslySetInnerHTML` / `innerHTML`.
- No network I/O in the engine; the browser render made no requests to other
  origins while analysing a token.
- Resource use: a 2 MB token is decoded and analysed in well under 5 s
  (regression test). The weak-secret dictionary is a fixed short list.
- Workflow permissions: `contents: read`. Actions are pinned to tags, not
  SHAs (unchanged; not broken).

## Known limitations and risks

- Verification covers HS256/384/512 and RS256/384/512 only. ES*, PS*, EdDSA
  tokens get claim analysis but no signature check.
- `header-kid-suspicious` and `looksLikePublicKey()` are heuristics. An
  unflagged `kid` is not proven safe.
- The weak-secret check is a short dictionary, not a cracking session; "not
  cracked" says nothing about secret strength.
- `exp-expired` / `nbf-future` are `info`, so the CLI exits 0 for an expired
  token with no other high findings (documented in the README).
- RSA key import failures in the workbench show as "does not match the
  provided key" rather than "key could not be parsed".
- Remaining dev-only advisory: vitest <= 4.1.11 (moderate; mock-registration
  in vitest's server/browser mode, which this project does not use). Fixing it
  needs a major vitest upgrade.

## Acceptance checklist

| # | Item | Expected behaviour | Command / test | Result | Actual | Reference |
|---|---|---|---|---|---|---|
| 1 | Malformed segments | Per-segment `header-malformed`/`payload-malformed` (high), never a crash; wrong segment count throws `TokenFormatError` | `npm test` — `malformed segments` | pass | 10 cases pass | `src/lib/decode.ts`, `adversarial.test.ts` |
| 2 | `alg: none` | Critical in any casing / surrounding whitespace | `alg=none variants` | pass | 5 variants flagged | `rules.ts` |
| 3 | RS256→HS256 confusion | Forged token verified with a public key is critical, not valid | `RS256 -> HS256 algorithm confusion` + App test | pass | `alg-confusion-forged`, CLI exit 1 | `rules.ts`, `verify.ts`, `cli.ts`, `App.tsx` |
| 4 | Weak HMAC secret | Dictionary secret cracked without `--secret`, exit 1 | CI dogfood replay | pass | exact output match | `verify.ts` |
| 5 | Signature verification | Correct key verifies, wrong key → `signature-invalid` | `verify.test.ts`, App RS256 tests | pass | | `verify.ts` |
| 6 | Time claims | `exp <= now` expired, `nbf > now` future, non-numeric flagged | `time-claim boundaries` | pass | boundary seconds correct | `rules.ts` |
| 7 | kid probes | Path traversal / SQLi / shell / NUL flagged; ordinary kids not | `kid injection probes` | pass | 12 flagged, 5 benign clean | `rules.ts` |
| 8 | CLI contract | Exit 1 iff critical/high; documented JSON shape | `cli.test.ts`, dogfood replay | pass | | `cli.ts` |
| 9 | Workbench renders locally only | Real browser render, no third-party requests | Playwright headless render | pass | no errors, no other-origin requests | `App.tsx` |
| 10 | Runtime deps clean | No production advisories | `npm audit --omit=dev` | pass | 0 | `package-lock.json` |

## Further testing needs

- Audit-branch CI (Windows, Node 22) after push.
- No external services, credentials or hardware are required.

## Classification proposal

**READY FOR DOCUMENTED SCOPE** (proposal; pending audit-branch CI and the
lead's independent verification).
