import { describe, expect, it } from "vitest";
import { decodeToken } from "./decode";
import { explainToken } from "./rules";
import { crackWeakHmacSecret, isHmacAlg, verifyHmacSignature } from "./verify";
import { EXAMPLE_TOKENS, EXAMPLES_REFERENCE_UNIX_SECONDS } from "./examples";

describe("bundled example tokens", () => {
  it("every example decodes structurally without error", () => {
    for (const ex of EXAMPLE_TOKENS) {
      const decoded = decodeToken(ex.token);
      expect(decoded.header.json, `${ex.id} header`).toBeDefined();
      expect(decoded.payload.json, `${ex.id} payload`).toBeDefined();
    }
  });

  it("has no duplicate ids", () => {
    const ids = EXAMPLE_TOKENS.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("healthy example verifies with its suggested secret and has no critical/high findings", async () => {
    const ex = EXAMPLE_TOKENS.find((e) => e.id === "healthy")!;
    const decoded = decodeToken(ex.token);
    const alg = decoded.header.json!["alg"] as string;
    expect(isHmacAlg(alg)).toBe(true);
    const verified = await verifyHmacSignature(decoded, alg as "HS256", ex.suggestedSecret!);
    expect(verified).toBe(true);
    const findings = explainToken(decoded, {
      now: new Date(EXAMPLES_REFERENCE_UNIX_SECONDS * 1000),
      signatureVerified: verified,
    });
    const severe = findings.filter((f) => f.severity === "critical" || f.severity === "high");
    expect(severe).toEqual([]);
  });

  it("weak-secret example is crackable with the built-in dictionary", async () => {
    const ex = EXAMPLE_TOKENS.find((e) => e.id === "weak-secret")!;
    const decoded = decodeToken(ex.token);
    const cracked = await crackWeakHmacSecret(decoded, "HS256");
    expect(cracked).toBe("secret");
  });

  it("alg-none example is flagged critical for alg-none", () => {
    const ex = EXAMPLE_TOKENS.find((e) => e.id === "alg-none")!;
    const decoded = decodeToken(ex.token);
    const findings = explainToken(decoded, { now: new Date(EXAMPLES_REFERENCE_UNIX_SECONDS * 1000) });
    expect(findings.some((f) => f.id === "alg-none" && f.severity === "critical")).toBe(true);
  });

  it("no-expiry example is flagged high for exp-missing", () => {
    const ex = EXAMPLE_TOKENS.find((e) => e.id === "no-expiry")!;
    const decoded = decodeToken(ex.token);
    const findings = explainToken(decoded, { now: new Date(EXAMPLES_REFERENCE_UNIX_SECONDS * 1000) });
    expect(findings.some((f) => f.id === "exp-missing" && f.severity === "high")).toBe(true);
  });

  it("embedded-jwk example is flagged critical for header-jwk", () => {
    const ex = EXAMPLE_TOKENS.find((e) => e.id === "embedded-jwk")!;
    const decoded = decodeToken(ex.token);
    const findings = explainToken(decoded, { now: new Date(EXAMPLES_REFERENCE_UNIX_SECONDS * 1000) });
    expect(findings.some((f) => f.id === "header-jwk" && f.severity === "critical")).toBe(true);
  });
});
