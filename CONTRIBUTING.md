# Contributing to tokenpit

## Setup

```
git clone https://github.com/hellpuffyt/tokenpit.git
cd tokenpit
npm install
npm run dev
```

Requires Node 22.22+ (jsdom 30, used in tests, dropped Node 20 support; the
engine itself only needs Web Crypto's `crypto.subtle` and global
`atob`/`btoa`, which are older than that — CI tests against Node 22/24).

## Before opening a PR

Run everything CI runs, locally:

```
npm test              # vitest
npm run coverage        # vitest with coverage thresholds enforced (90%/85%)
npm run lint              # eslint (typed — this is not fast, that's expected)
npm run typecheck          # tsc --noEmit, both the app and CLI tsconfig projects
npm run build                # production web build
npm run build:cli             # CLI build
```

All five must pass clean. There is no `--fix`-and-hope step in CI.

## Ground rules specific to this project

- **New findings belong in `src/lib/rules.ts`, with a test in
  `src/lib/rules.test.ts`.** Every finding needs: a stable, kebab-case `id`
  that won't get renamed later (other tests and any downstream tooling key
  off it), a `severity` that's honest about actual impact (don't inflate to
  `critical` for style issues), a `detail` that explains the *mechanism* of
  the problem (not just "this is bad"), and a `recommendation` that's
  actionable. Add both a positive test (the finding fires) and, where it's
  not obvious, a negative test (it doesn't fire on a clean token).
- **The engine (`src/lib/`) stays dependency-free.** It's the one part of
  this repo explicitly designed to run anywhere with `crypto.subtle` —
  don't reach for a base64/JWT/crypto npm package for something this file
  can do natively. The UI is allowed React; test-only tooling (Vitest,
  Testing Library, `jose` for generating RSA test fixtures) stays in
  `devDependencies`.
- **The UI and the CLI must call the same functions.** Don't duplicate
  decode/verify/explain logic in `src/App.tsx` or `src/cli.ts` — both
  should be thin callers of `src/lib/`. If you need the CLI to do something
  the UI can't, that's a sign the capability belongs in the library, not
  in `cli.ts` alone.
- **New/changed CLI output is a breaking-output change.** The CLI's JSON
  shape is meant to be scriptable; if you change field names or add
  required fields, call it out in the CHANGELOG and update the CI dogfood
  fixtures in `.github/workflows/ci.yml` (they assert the CLI's exact
  stdout, not just its exit code).
- **Never commit a real secret or private key**, even a fake-looking one
  meant as an example — use the existing bundled/example patterns in
  `src/lib/examples.ts` / `src/lib/liveExamples.ts` as a template.
- Keep coverage above the thresholds in `vitest.config.ts` (currently 90%
  lines/statements/functions, 85% branches). If you add an intentionally
  unreachable defensive branch, mark it with a `/* v8 ignore */` comment
  and say why in a comment next to it, rather than silently letting
  coverage drift down.
