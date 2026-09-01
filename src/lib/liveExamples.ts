import { signHmacToken, buildUnsecuredToken } from "./encode";

/**
 * The workbench's "load an example" menu builds these fresh, relative to
 * the moment they're loaded, so the "healthy" example is actually healthy
 * (not expired) no matter when someone opens the page. The frozen,
 * timestamp-pinned tokens in examples.ts exist separately for
 * reproducible tests and the CLI dogfood check.
 */
export interface LiveExample {
  id: string;
  label: string;
  description: string;
  suggestedSecret?: string;
  build(now: Date): Promise<string>;
}

const STRONG_SECRET = "a-sufficiently-long-random-signing-key-32bytes+";

export const LIVE_EXAMPLES: readonly LiveExample[] = [
  {
    id: "healthy",
    label: "Healthy HS256 token",
    description: "Short-lived, has exp/iat/iss/aud, signed with a strong secret.",
    suggestedSecret: STRONG_SECRET,
    async build(now) {
      const iat = Math.floor(now.getTime() / 1000);
      return signHmacToken(
        { alg: "HS256", typ: "JWT" },
        { sub: "user_8f2c1", iss: "https://auth.example.com", aud: "https://api.example.com", iat, exp: iat + 900 },
        "HS256",
        STRONG_SECRET,
      );
    },
  },
  {
    id: "weak-secret",
    label: "HS256 signed with a weak secret",
    description: 'Grants role:"admin"; signed with the literal secret "secret".',
    async build(now) {
      const iat = Math.floor(now.getTime() / 1000);
      return signHmacToken(
        { alg: "HS256", typ: "JWT" },
        { sub: "admin", role: "admin", iat, exp: iat + 3600 },
        "HS256",
        "secret",
      );
    },
  },
  {
    id: "alg-none",
    label: '"alg": "none" — unsecured token',
    description: 'No signature at all; grants role:"admin" with nothing checking it.',
    build(now) {
      const iat = Math.floor(now.getTime() / 1000);
      return Promise.resolve(buildUnsecuredToken({ typ: "JWT" }, { sub: "admin", role: "admin", iat }));
    },
  },
  {
    id: "no-expiry",
    label: "Missing exp claim",
    description: "Validly signed, but never expires — a leak becomes permanent.",
    suggestedSecret: STRONG_SECRET,
    async build(now) {
      const iat = Math.floor(now.getTime() / 1000);
      return signHmacToken({ alg: "HS256", typ: "JWT" }, { sub: "user_1", iat }, "HS256", STRONG_SECRET);
    },
  },
  {
    id: "embedded-jwk",
    label: 'Embedded "jwk" in header',
    description: "The token supplies its own public key for a verifier to (wrongly) trust.",
    build(now) {
      const iat = Math.floor(now.getTime() / 1000);
      const header = {
        alg: "RS256",
        typ: "JWT",
        jwk: { kty: "RSA", n: "attacker-supplied-modulus", e: "AQAB" },
      };
      const headerSeg = btoa(JSON.stringify(header)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const payloadSeg = btoa(JSON.stringify({ sub: "admin", iat, exp: iat + 3600 }))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
      return Promise.resolve(`${headerSeg}.${payloadSeg}.forged-signature-not-checked-by-vulnerable-verifiers`);
    },
  },
];
