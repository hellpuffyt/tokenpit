import { describe, expect, it } from "vitest";
import { decodeToken } from "./decode";
import { explainToken } from "./rules";
import { crackWeakHmacSecret, isHmacAlg, verifyHmacSignature } from "./verify";
import { LIVE_EXAMPLES } from "./liveExamples";

const NOW = new Date();

describe("LIVE_EXAMPLES", () => {
  it("has no duplicate ids", () => {
    const ids = LIVE_EXAMPLES.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every example builds a structurally decodable token", async () => {
    for (const ex of LIVE_EXAMPLES) {
      const token = await ex.build(NOW);
      const decoded = decodeToken(token);
      expect(decoded.header.json, ex.id).toBeDefined();
    }
  });

  it("healthy example is currently valid and has no critical/high findings, freshly built", async () => {
    const ex = LIVE_EXAMPLES.find((e) => e.id === "healthy")!;
    const token = await ex.build(NOW);
    const decoded = decodeToken(token);
    const alg = decoded.header.json!["alg"] as "HS256";
    const verified = await verifyHmacSignature(decoded, alg, ex.suggestedSecret!);
    expect(verified).toBe(true);
    const findings = explainToken(decoded, { now: NOW, signatureVerified: verified });
    expect(findings.filter((f) => f.severity === "critical" || f.severity === "high")).toEqual([]);
  });

  it("weak-secret example is crackable and grants role: admin", async () => {
    const ex = LIVE_EXAMPLES.find((e) => e.id === "weak-secret")!;
    const token = await ex.build(NOW);
    const decoded = decodeToken(token);
    expect(decoded.payload.json?.role).toBe("admin");
    expect(await crackWeakHmacSecret(decoded, "HS256")).toBe("secret");
  });

  it("alg-none example has alg: none and no usable signature", async () => {
    const ex = LIVE_EXAMPLES.find((e) => e.id === "alg-none")!;
    const token = await ex.build(NOW);
    const decoded = decodeToken(token);
    expect(decoded.header.json?.alg).toBe("none");
    expect(decoded.signature).toBe("");
  });

  it("no-expiry example verifies but has no exp claim", async () => {
    const ex = LIVE_EXAMPLES.find((e) => e.id === "no-expiry")!;
    const token = await ex.build(NOW);
    const decoded = decodeToken(token);
    expect(decoded.payload.json?.exp).toBeUndefined();
    expect(isHmacAlg(decoded.header.json!["alg"] as string)).toBe(true);
    expect(await verifyHmacSignature(decoded, "HS256", ex.suggestedSecret!)).toBe(true);
    const findings = explainToken(decoded, { now: NOW });
    expect(findings.some((f) => f.id === "exp-missing")).toBe(true);
  });

  it("embedded-jwk example carries a jwk header the verifier should never trust", async () => {
    const ex = LIVE_EXAMPLES.find((e) => e.id === "embedded-jwk")!;
    const token = await ex.build(NOW);
    const decoded = decodeToken(token);
    expect(decoded.header.json?.jwk).toBeDefined();
    const findings = explainToken(decoded, { now: NOW });
    expect(findings.some((f) => f.id === "header-jwk" && f.severity === "critical")).toBe(true);
  });
});
