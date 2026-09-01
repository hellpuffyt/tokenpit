import { base64UrlDecodeBytes } from "./base64url.js";
import type { DecodedToken } from "./decode.js";
import { COMMON_JWT_SECRETS } from "./commonSecrets.js";

export type HmacAlg = "HS256" | "HS384" | "HS512";
export type RsaAlg = "RS256" | "RS384" | "RS512";

const HMAC_HASH: Record<HmacAlg, string> = {
  HS256: "SHA-256",
  HS384: "SHA-384",
  HS512: "SHA-512",
};

const RSA_HASH: Record<RsaAlg, string> = {
  RS256: "SHA-256",
  RS384: "SHA-384",
  RS512: "SHA-512",
};

export function isHmacAlg(alg: string): alg is HmacAlg {
  return alg === "HS256" || alg === "HS384" || alg === "HS512";
}

export function isRsaAlg(alg: string): alg is RsaAlg {
  return alg === "RS256" || alg === "RS384" || alg === "RS512";
}

function getSubtle() {
  const subtle = globalThis.crypto?.subtle;
  /* v8 ignore next 4 -- every supported runtime (Node 20+, evergreen browsers) has crypto.subtle; this only guards genuinely unsupported hosts. */
  if (!subtle) {
    throw new Error(
      "Web Crypto (crypto.subtle) is not available in this runtime; verification requires it.",
    );
  }
  return subtle;
}

/** Verify an HS256/HS384/HS512 signature against a UTF-8 secret. */
export async function verifyHmacSignature(
  decoded: DecodedToken,
  alg: HmacAlg,
  secret: string,
): Promise<boolean> {
  const subtle = getSubtle();
  const key = await subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: HMAC_HASH[alg] },
    false,
    ["verify"],
  );
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecodeBytes(decoded.signature);
  } catch {
    return false;
  }
  return subtle.verify(
    "HMAC",
    key,
    toArrayBuffer(signatureBytes),
    new TextEncoder().encode(decoded.signingInput),
  );
}

/** Compute the base64url HMAC signature tokenpit would produce for a given secret (used for re-signing / demos). */
export async function computeHmacSignature(
  signingInput: string,
  alg: HmacAlg,
  secret: string,
): Promise<Uint8Array> {
  const subtle = getSubtle();
  const key = await subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: HMAC_HASH[alg] },
    false,
    ["sign"],
  );
  const sig = await subtle.sign("HMAC", key, new TextEncoder().encode(signingInput));
  return new Uint8Array(sig);
}

/** PEM -> DER bytes, stripping the `-----BEGIN ...-----` / `-----END ...-----` armor. */
function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  return base64UrlDecodeBytes(b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

/** Verify an RS256/RS384/RS512 signature against a PEM-encoded SPKI public key. */
export async function verifyRsaSignature(
  decoded: DecodedToken,
  alg: RsaAlg,
  publicKeyPem: string,
): Promise<boolean> {
  const subtle = getSubtle();
  const der = pemToDer(publicKeyPem);
  const key = await subtle.importKey(
    "spki",
    toArrayBuffer(der),
    { name: "RSASSA-PKCS1-v1_5", hash: RSA_HASH[alg] },
    false,
    ["verify"],
  );
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecodeBytes(decoded.signature);
  } catch {
    return false;
  }
  return subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    toArrayBuffer(signatureBytes),
    new TextEncoder().encode(decoded.signingInput),
  );
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

/**
 * Try a short dictionary of known-weak secrets against an HMAC-signed
 * token. Returns the first secret that verifies, or null if none did.
 * This is the client-side analogue of what an attacker's first move
 * against an HS256 token looks like — it is deliberately cheap and small,
 * not a substitute for a real cracking session.
 */
export async function crackWeakHmacSecret(
  decoded: DecodedToken,
  alg: HmacAlg,
  wordlist: readonly string[] = COMMON_JWT_SECRETS,
): Promise<string | null> {
  for (const candidate of wordlist) {
    if (await verifyHmacSignature(decoded, alg, candidate)) {
      return candidate;
    }
  }
  return null;
}

export interface SecretStrength {
  /** 0 (trivial) through 4 (strong). */
  score: 0 | 1 | 2 | 3 | 4;
  label: "very weak" | "weak" | "fair" | "strong" | "very strong";
  reasons: string[];
}

/**
 * A deliberately simple, dependency-free secret-strength heuristic for
 * HMAC keys: length and character-class variety, with an instant floor
 * for anything in the common-secrets list. It is not a replacement for
 * zxcvbn — it exists to give the workbench an honest, explainable signal
 * without pulling in a password-strength library for one field.
 */
export function assessSecretStrength(secret: string): SecretStrength {
  const reasons: string[] = [];

  if (secret.length === 0) {
    return { score: 0, label: "very weak", reasons: ["secret is empty"] };
  }
  if (COMMON_JWT_SECRETS.includes(secret.toLowerCase())) {
    return {
      score: 0,
      label: "very weak",
      reasons: ["matches a widely known example/tutorial secret"],
    };
  }

  let classes = 0;
  if (/[a-z]/.test(secret)) classes++;
  if (/[A-Z]/.test(secret)) classes++;
  if (/[0-9]/.test(secret)) classes++;
  if (/[^a-zA-Z0-9]/.test(secret)) classes++;

  // HMAC-SHA256 wants a key at least as long as the hash output (32 bytes /
  // ~43 base64/ASCII chars) to avoid the effective key space being smaller
  // than the digest itself (RFC 2104 §3).
  const RECOMMENDED_MIN_LENGTH = 32;

  if (secret.length < 8) reasons.push("shorter than 8 characters");
  else if (secret.length < RECOMMENDED_MIN_LENGTH) {
    reasons.push(`shorter than the recommended ${RECOMMENDED_MIN_LENGTH} characters for HS256`);
  }
  if (classes <= 1) reasons.push("uses only one character class");

  let score: SecretStrength["score"];
  if (secret.length < 8 || classes <= 1) {
    score = 1;
  } else if (secret.length < 16) {
    score = 2;
  } else if (secret.length < RECOMMENDED_MIN_LENGTH || classes < 3) {
    score = 3;
  } else {
    score = 4;
  }

  const labels: Record<SecretStrength["score"], SecretStrength["label"]> = {
    0: "very weak",
    1: "weak",
    2: "fair",
    3: "strong",
    4: "very strong",
  };

  if (reasons.length === 0) reasons.push("meets length and character-variety guidance");

  return { score, label: labels[score], reasons };
}
