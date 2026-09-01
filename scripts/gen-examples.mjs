// One-off generator: prints ready-to-paste JWTs for src/lib/examples.ts.
// Not part of the build; run manually with `node scripts/gen-examples.mjs`.
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return Buffer.from(binary, "binary").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlUtf8(s) {
  return b64url(new TextEncoder().encode(s));
}

async function sign(header, payload, alg, secret) {
  const hash = { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" }[alg];
  const h = b64urlUtf8(JSON.stringify(header));
  const p = b64urlUtf8(JSON.stringify(payload));
  const input = `${h}.${p}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input)));
  return `${input}.${b64url(sig)}`;
}

function unsecured(header, payload) {
  const h = b64urlUtf8(JSON.stringify({ ...header, alg: "none" }));
  const p = b64urlUtf8(JSON.stringify(payload));
  return `${h}.${p}.`;
}

const now = 1_735_689_600; // fixed reference instant, 2025-01-01T00:00:00Z

const healthy = await sign(
  { alg: "HS256", typ: "JWT" },
  { sub: "user_8f2c1", iss: "https://auth.example.com", aud: "https://api.example.com", iat: now, exp: now + 900 },
  "HS256",
  "a-sufficiently-long-random-signing-key-32bytes+",
);

const weakSecret = await sign(
  { alg: "HS256", typ: "JWT" },
  { sub: "admin", role: "admin", iat: now, exp: now + 3600 },
  "HS256",
  "secret",
);

const algNone = unsecured({ typ: "JWT" }, { sub: "admin", role: "admin", iat: now });

const noExpiry = await sign(
  { alg: "HS256", typ: "JWT" },
  { sub: "user_1", iat: now },
  "HS256",
  "a-sufficiently-long-random-signing-key-32bytes+",
);

const embeddedJwk = (() => {
  const header = {
    alg: "RS256",
    typ: "JWT",
    jwk: { kty: "RSA", n: "attacker-supplied-modulus", e: "AQAB" },
  };
  const h = b64urlUtf8(JSON.stringify(header));
  const p = b64urlUtf8(JSON.stringify({ sub: "admin", iat: now, exp: now + 3600 }));
  return `${h}.${p}.forged-signature-not-checked-by-vulnerable-verifiers`;
})();

console.log(JSON.stringify({ healthy, weakSecret, algNone, noExpiry, embeddedJwk }, null, 2));
