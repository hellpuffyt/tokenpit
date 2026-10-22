# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's advisory form:
https://github.com/hellpuffyt/tokenpit/security/advisories/new

Do not open a public issue for a suspected vulnerability. Include the token
(with any real secrets removed), the command or workbench steps, and what you
expected versus what tokenpit reported.

## Scope

tokenpit is a diagnostic tool, not a JWT library. In scope:

- a token shape or attack class that tokenpit reports as clean or verified when
  it should not (for example a forged signature shown as valid);
- anything that causes the workbench or CLI to send token, secret or key
  material off the machine;
- crashes or unbounded resource use on crafted input.

Out of scope: the example signing helpers in `src/lib/encode.ts` being used to
issue production tokens (they exist for fixtures only, see the README).

## Supported versions

Only the latest commit on `main` is supported. There are no released versions.
