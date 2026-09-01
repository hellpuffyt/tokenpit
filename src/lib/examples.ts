/**
 * Bundled example tokens for the workbench's "load an example" menu and for
 * the CLI dogfood check in CI. Generated once with scripts/gen-examples.mjs
 * against the fixed reference instant 2025-01-01T00:00:00Z (unix 1735689600)
 * and then frozen here as literals, so every finding they produce is
 * reproducible without a live signing step.
 */
export interface ExampleToken {
  id: string;
  label: string;
  description: string;
  token: string;
  /** Secret to try in the verifier field, if relevant to the example. */
  suggestedSecret?: string;
}

export const EXAMPLE_TOKENS: readonly ExampleToken[] = [
  {
    id: "healthy",
    label: "Healthy HS256 token",
    description: "Short-lived, has exp/iat/iss/aud, signed with a strong secret.",
    token:
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzhmMmMxIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iLCJpYXQiOjE3MzU2ODk2MDAsImV4cCI6MTczNTY5MDUwMH0.tNfdMO7auMYe-SkPsiUIyc12NZKQs9V1AbpzN3fhxww",
    suggestedSecret: "a-sufficiently-long-random-signing-key-32bytes+",
  },
  {
    id: "weak-secret",
    label: "HS256 signed with a weak secret",
    description: 'Grants role:"admin"; signed with the literal secret "secret".',
    token:
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTczNTY4OTYwMCwiZXhwIjoxNzM1NjkzMjAwfQ.2_X7D_KnlrOE9jHZnIBmirQi4MovMFnvYPnbaZ88c2A",
  },
  {
    id: "alg-none",
    label: '"alg": "none" — unsecured token',
    description: "No signature at all; grants role:\"admin\" with nothing checking it.",
    token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTczNTY4OTYwMH0.",
  },
  {
    id: "no-expiry",
    label: "Missing exp claim",
    description: "Validly signed, but never expires — a leak becomes permanent.",
    token:
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEiLCJpYXQiOjE3MzU2ODk2MDB9.R4tU8eTyOlhlhuaE4BJMiYR7VMbGxy8FhJeqzyQFufI",
    suggestedSecret: "a-sufficiently-long-random-signing-key-32bytes+",
  },
  {
    id: "embedded-jwk",
    label: 'Embedded "jwk" in header',
    description: "The token supplies its own public key for a verifier to (wrongly) trust.",
    token:
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiYXR0YWNrZXItc3VwcGxpZWQtbW9kdWx1cyIsImUiOiJBUUFCIn19.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTczNTY4OTYwMCwiZXhwIjoxNzM1NjkzMjAwfQ.forged-signature-not-checked-by-vulnerable-verifiers",
  },
];

/** The reference instant every bundled example was generated relative to. */
export const EXAMPLES_REFERENCE_UNIX_SECONDS = 1735689600;
