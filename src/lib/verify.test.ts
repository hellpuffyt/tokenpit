import { describe, expect, it } from "vitest";
import { decodeToken } from "./decode";
import { signHmacToken } from "./encode";
import {
  assessSecretStrength,
  computeHmacSignature,
  crackWeakHmacSecret,
  isHmacAlg,
  isRsaAlg,
  verifyHmacSignature,
  verifyRsaSignature,
} from "./verify";
import { generateKeyPair, exportSPKI, SignJWT } from "jose";

describe("isHmacAlg / isRsaAlg", () => {
  it("recognizes exactly the HS* family", () => {
    expect(isHmacAlg("HS256")).toBe(true);
    expect(isHmacAlg("HS384")).toBe(true);
    expect(isHmacAlg("HS512")).toBe(true);
    expect(isHmacAlg("RS256")).toBe(false);
    expect(isHmacAlg("none")).toBe(false);
  });

  it("recognizes exactly the RS* family", () => {
    expect(isRsaAlg("RS256")).toBe(true);
    expect(isRsaAlg("RS384")).toBe(true);
    expect(isRsaAlg("RS512")).toBe(true);
    expect(isRsaAlg("HS256")).toBe(false);
  });
});

describe("HMAC sign/verify round trip", () => {
  it("verifies a signature made with the correct secret", async () => {
    const token = await signHmacToken({ alg: "HS256", typ: "JWT" }, { sub: "u1" }, "HS256", "correct-horse-battery");
    const decoded = decodeToken(token);
    expect(await verifyHmacSignature(decoded, "HS256", "correct-horse-battery")).toBe(true);
  });

  it("rejects a signature checked against the wrong secret", async () => {
    const token = await signHmacToken({ alg: "HS256", typ: "JWT" }, { sub: "u1" }, "HS256", "correct-horse-battery");
    const decoded = decodeToken(token);
    expect(await verifyHmacSignature(decoded, "HS256", "wrong-secret")).toBe(false);
  });

  it("rejects a signature checked against the wrong algorithm's hash", async () => {
    const token = await signHmacToken({ alg: "HS256", typ: "JWT" }, { sub: "u1" }, "HS256", "shared-secret-value");
    const decoded = decodeToken(token);
    expect(await verifyHmacSignature(decoded, "HS384", "shared-secret-value")).toBe(false);
  });

  it("supports HS384 and HS512", async () => {
    for (const alg of ["HS384", "HS512"] as const) {
      const token = await signHmacToken({ alg, typ: "JWT" }, { sub: "u1" }, alg, "a-reasonably-long-secret-value");
      const decoded = decodeToken(token);
      expect(await verifyHmacSignature(decoded, alg, "a-reasonably-long-secret-value")).toBe(true);
    }
  });

  it("computeHmacSignature is deterministic for the same input/secret", async () => {
    const sig1 = await computeHmacSignature("header.payload", "HS256", "secret-value");
    const sig2 = await computeHmacSignature("header.payload", "HS256", "secret-value");
    expect(sig1).toEqual(sig2);
  });

  it("returns false rather than throwing when the signature segment isn't valid base64url", async () => {
    const decoded = decodeToken("aGVhZGVy.cGF5bG9hZA.not-valid-base64!!");
    expect(await verifyHmacSignature(decoded, "HS256", "anything")).toBe(false);
  });
});

describe("crackWeakHmacSecret", () => {
  it("finds a token signed with a common weak secret", async () => {
    const token = await signHmacToken({ alg: "HS256", typ: "JWT" }, { sub: "admin" }, "HS256", "secret");
    const decoded = decodeToken(token);
    expect(await crackWeakHmacSecret(decoded, "HS256")).toBe("secret");
  });

  it("returns null when the secret isn't in the dictionary", async () => {
    const token = await signHmacToken(
      { alg: "HS256", typ: "JWT" },
      { sub: "admin" },
      "HS256",
      "a-genuinely-strong-random-secret-value-32b",
    );
    const decoded = decodeToken(token);
    expect(await crackWeakHmacSecret(decoded, "HS256")).toBeNull();
  });

  it("accepts a custom wordlist", async () => {
    const token = await signHmacToken({ alg: "HS256", typ: "JWT" }, { sub: "admin" }, "HS256", "my-custom-word");
    const decoded = decodeToken(token);
    expect(await crackWeakHmacSecret(decoded, "HS256", ["nope", "my-custom-word"])).toBe("my-custom-word");
    expect(await crackWeakHmacSecret(decoded, "HS256", ["nope", "still-nope"])).toBeNull();
  });
});

describe("RSA verify", () => {
  it("verifies an RS256 token against its real public key, and rejects a wrong one", async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
    const jwt = await new SignJWT({ sub: "u1" })
      .setProtectedHeader({ alg: "RS256", typ: "JWT" })
      .sign(privateKey);
    const decoded = decodeToken(jwt);
    const pem = await exportSPKI(publicKey);
    expect(await verifyRsaSignature(decoded, "RS256", pem)).toBe(true);

    const { publicKey: otherPublicKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
    const otherPem = await exportSPKI(otherPublicKey);
    expect(await verifyRsaSignature(decoded, "RS256", otherPem)).toBe(false);
  });

  it("returns false rather than throwing when the signature segment isn't valid base64url", async () => {
    const { publicKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
    const pem = await exportSPKI(publicKey);
    const decoded = decodeToken("aGVhZGVy.cGF5bG9hZA.not-valid-base64!!");
    expect(await verifyRsaSignature(decoded, "RS256", pem)).toBe(false);
  });
});

describe("assessSecretStrength", () => {
  it("scores an empty secret as very weak", () => {
    expect(assessSecretStrength("").score).toBe(0);
  });

  it("scores a known common secret as very weak regardless of casing", () => {
    expect(assessSecretStrength("SECRET").score).toBe(0);
    expect(assessSecretStrength("secret").score).toBe(0);
  });

  it("scores a short single-character-class secret as weak", () => {
    const result = assessSecretStrength("abc");
    expect(result.score).toBe(1);
    expect(result.reasons.some((r) => r.includes("8 characters"))).toBe(true);
  });

  it("scores a medium-length mixed secret as fair", () => {
    const result = assessSecretStrength("Password123");
    expect(result.score).toBe(2);
  });

  it("scores a long-ish secret under the recommended length as strong but not very strong", () => {
    const result = assessSecretStrength("Reasonably-Long-1");
    expect(result.score).toBe(3);
  });

  it("scores a long high-entropy secret as very strong", () => {
    const result = assessSecretStrength("Tr0ub4dor&3-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    expect(result.score).toBe(4);
    expect(result.reasons).toEqual(["meets length and character-variety guidance"]);
  });
});
