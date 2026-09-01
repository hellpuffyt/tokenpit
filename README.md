# tokenpit

Decode, verify and explain JSON Web Tokens — with a threat model attached to
every claim. Paste a token and tokenpit doesn't just show you the JSON
inside it; it names, for every header field and claim, the exact way that
combination has historically gone wrong (`alg: "none"`, a missing `exp`, an
HS256 secret that's really just `"secret"`, an embedded `jwk` a lazy
verifier trusts) and what to do about it.

It ships two things built on one shared, dependency-free core:

- **A live decode-as-you-type workbench** (React + Vite) — paste a token,
  optionally a secret or public key, and watch the decoded header/payload
  and a severity-ranked findings list update as you type.
- **A CLI** (`tokenpit <token>`) that runs the same analysis headlessly and
  prints JSON, for scripting a JWT into a CI check or a terminal.

Everything — decoding, HMAC/RSA verification, the weak-secret dictionary
check — runs client-side / locally. No token, secret, or key this tool
touches is ever sent anywhere.

## Why this and not the 1,000 other JWT decoders

jwt.io and its many clones will show you the decoded header and payload.
That's necessary but it's the easy 20%. The interesting, useful part of
looking at a JWT is knowing what each field *means for security* — and
that's exactly what a generic "base64url decoder with a pretty UI" doesn't
do. tokenpit is built specifically to do that part:

- **A named threat model, not a decoder.** Every finding has a stable id
  (`alg-none`, `header-jwk`, `exp-missing`, `hmac-secret-weak`, …), a
  severity, and — critically — an explanation of *why* it matters that
  references the actual historical vulnerability class (e.g. `alg-none`'s
  finding explicitly calls out the case-insensitive `"none"`-comparison bug
  behind CVE-2015-9235 and similar advisories, not just "this is
  unsigned").
- **It doesn't just decode a weak secret's signature — it cracks it.** If a
  token is HS256-signed, tokenpit tries a short dictionary of secrets that
  actually show up in breaches and tutorials (`secret`, `changeme`,
  `your-256-bit-secret`, …) and tells you outright if your token was
  forgeable with the first thing an attacker would try.
- **It checks the header, not just the payload.** `jwk`/`jku`/`x5c` embedded
  in the header, a `kid` that looks like a path-traversal or SQL-injection
  probe, an unenforced `crit` list — these are where real JWT library CVEs
  keep coming from, and most decoders don't look at the header at all.
- **A real CLI with a real contract**, not a demo afterthought: exit code 1
  iff a critical/high finding exists, JSON output, `--secret`/`--now`
  flags — scriptable in a pre-commit hook or a CI job that scans fixture
  tokens.

## The workbench

```
npm install
npm run dev
```

Paste a JWT into the **JWT** field. Load one of the five bundled examples
from the dropdown to see the range of what tokenpit flags without needing a
token of your own:

| Example | What it demonstrates |
|---|---|
| Healthy HS256 token | Short-lived, `exp`/`iat`/`iss`/`aud` all present, strong secret — mostly clean |
| HS256 signed with a weak secret | Grants `role: "admin"`, cracked live in the browser against the built-in dictionary |
| `"alg": "none"` | The classic unsecured-JWT bypass |
| Missing `exp` claim | Validly signed, but a leaked copy never expires |
| Embedded `jwk` in header | The token supplies its own "trusted" key |

Every example is built fresh at load time (real `iat`/`exp` relative to
*now*), so "healthy" is actually healthy no matter when you open the page —
not a demo token permanently expired from the day it was written.

Typing or pasting your own secret / PEM public key into the second field
attempts real signature verification (`crypto.subtle`, HS256/384/512 and
RS256/384/512) live, with the result folded straight into the findings
list — a verified-against-a-weak-secret signature becomes its own
**critical** finding, not a footnote.

## The CLI

```
npm run build:cli
node dist-cli/cli.js <token> [--secret <hmac-secret>] [--now <unix-seconds>]
```

Real output, run against tokenpit's own bundled "weak secret" example, no
`--secret` supplied (it was cracked from the dictionary):

```
$ node dist-cli/cli.js "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTczNTY4OTYwMCwiZXhwIjoxNzM1NjkzMjAwfQ.2_X7D_KnlrOE9jHZnIBmirQi4MovMFnvYPnbaZ88c2A" --now 1735689600
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "admin",
    "role": "admin",
    "iat": 1735689600,
    "exp": 1735693200
  },
  "signatureVerified": true,
  "findings": [
    {
      "id": "hmac-secret-weak",
      "severity": "critical",
      "title": "Signature verifies against a known weak/example secret"
    },
    {
      "id": "alg-confusion-hs-rs",
      "severity": "medium",
      "title": "HMAC algorithm — verify the key really is a shared secret"
    },
    {
      "id": "aud-missing",
      "severity": "low",
      "title": "\"aud\" (audience) claim is missing"
    },
    {
      "id": "iss-missing",
      "severity": "low",
      "title": "\"iss\" (issuer) claim is missing"
    }
  ]
}
$ echo $?
1
```

Exit code is `1` if any `critical`/`high` finding is present, `0` otherwise
— so `tokenpit some.jwt.here` is a one-liner CI gate.

## The threat model, in full

Every finding `explainToken()` can produce, grouped by what it looks at:

**`alg` header**
- `alg-none` (critical) — `"alg": "none"` in any casing (`nOnE`, `NONE`, …)
- `alg-missing` (high), `alg-empty` (high), `alg-not-string` (high)
- `alg-confusion-hs-rs` (medium) — HS256 used where an RS256→HS256 key-confusion attack is possible

**Header key material**
- `header-jwk` (critical) — the token embeds its own verification key
- `header-jku` (high) — the token points the verifier at a URL for the key
- `header-x5c` (high) — the token embeds its own certificate chain
- `header-kid-suspicious` (high) — `kid` looks like a path-traversal/SQLi probe
- `header-crit` (medium) — `crit` header parameters most libraries don't actually enforce
- `header-typ-unexpected` (low) — non-`JWT` `typ`, a cross-token-type replay vector

**Signature**
- `signature-empty` (critical) — a real `alg` declared, but zero signature bytes
- `signature-valid` / `signature-invalid` / `hmac-secret-weak` — outcome of an attempted verification

**Time-based claims (`exp`/`iat`/`nbf`)**
- `exp-missing` (high), `exp-not-numeric` / `iat-not-numeric` / `nbf-not-numeric` (medium/low)
- `exp-expired` (info), `exp-far-future` (medium, >1yr lifetime)
- `iat-missing` (low), `iat-future` (medium, beyond clock-skew tolerance)
- `nbf-future` (info)
- `exp-implausible` / `iat-implausible` / `nbf-implausible` (low — likely a milliseconds-not-seconds bug)

**Audience / identity claims**
- `aud-missing`, `iss-missing` (low), `sub-missing` (info)

**Shape**
- `header-malformed` / `payload-malformed` (high) — undecodable segments
- `token-oversized` (low) — >8KB encoded

See `src/lib/rules.ts` for the exact wording and reasoning behind each one.

## How it's built

- `src/lib/` — the entire analysis engine: base64url codec, decoder,
  HS/RS signature verification (Web Crypto), the weak-secret dictionary
  cracker, secret-strength heuristic, and the rule set above. Zero runtime
  dependencies — everything is native `crypto.subtle`/`atob`/`TextDecoder`.
- `src/App.tsx` + `src/components/` — the workbench UI (React 19, hand-written
  CSS with a light/dark theme driven by CSS custom properties).
- `src/cli.ts` — a thin Node wrapper around the same `src/lib/` engine.

The UI and the CLI call the exact same `decodeToken()` / `explainToken()` /
`verifyHmacSignature()` functions — there is one threat model, not a UI
version and a separate CLI version that could drift apart.

## Development

```
npm install
npm run dev          # the workbench, at http://localhost:5173
npm test              # vitest, 129 tests
npm run coverage       # vitest with coverage thresholds enforced
npm run lint            # eslint (typed)
npm run typecheck        # tsc --noEmit, app project + CLI project
npm run build              # production web build -> dist/
npm run build:cli           # CLI build -> dist-cli/
```

Real numbers from this repository as shipped:

```
Test Files  12 passed (12)
     Tests  129 passed (129)

Statements   : 98.24% ( 392/399 )
Branches     : 95%    ( 323/340 )
Functions    : 100%   ( 60/60 )
Lines        : 99.72% ( 363/364 )
```

## Security note

tokenpit is a *diagnostic* tool for looking at tokens, not a JWT library —
`src/lib/encode.ts`'s signing helpers exist only to build the bundled
example tokens and test fixtures. Don't use it to issue tokens in
production; use a maintained JWT library for that, and use tokenpit to
sanity-check what it's giving you.

## License

MIT — see [LICENSE](./LICENSE).
