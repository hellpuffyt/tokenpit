import { describe, expect, it } from "vitest";
import { base64UrlEncodeUtf8 } from "./base64url";
import { decodeToken } from "./decode";
import { explainToken, type Finding } from "./rules";

const NOW = new Date(1735689600 * 1000); // 2025-01-01T00:00:00Z

function token(header: unknown, payload: unknown, signature = "sig"): string {
  return `${base64UrlEncodeUtf8(JSON.stringify(header))}.${base64UrlEncodeUtf8(JSON.stringify(payload))}.${signature}`;
}

function ids(findings: Finding[]): string[] {
  return findings.map((f) => f.id);
}

describe("explainToken", () => {
  it("flags alg: none (exact case) as critical", () => {
    const decoded = decodeToken(token({ alg: "none" }, { sub: "x" }, ""));
    const findings = explainToken(decoded, { now: NOW });
    const finding = findings.find((f) => f.id === "alg-none");
    expect(finding?.severity).toBe("critical");
    expect(finding?.title).toContain('"alg" is "none"');
  });

  it("flags a case-variant of none (e.g. nOnE) distinctly from exact none", () => {
    const decoded = decodeToken(token({ alg: "nOnE" }, { sub: "x" }, ""));
    const findings = explainToken(decoded, { now: NOW });
    const finding = findings.find((f) => f.id === "alg-none");
    expect(finding?.severity).toBe("critical");
    expect(finding?.title).toContain("case-variant");
  });

  it("flags a missing alg claim", () => {
    const decoded = decodeToken(token({ typ: "JWT" }, { sub: "x" }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("alg-missing");
  });

  it("flags alg that is not a string", () => {
    const decoded = decodeToken(token({ alg: 5 }, { sub: "x" }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("alg-not-string");
  });

  it("flags an empty-string alg", () => {
    const decoded = decodeToken(token({ alg: "" }, { sub: "x" }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("alg-empty");
  });

  it("flags HS* algorithms with the alg-confusion note", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", exp: 9999999999, iat: 1 }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("alg-confusion-hs-rs");
  });

  it("flags an empty signature on a token that declares a real algorithm", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x" }, ""));
    const finding = explainToken(decoded, { now: NOW }).find((f) => f.id === "signature-empty");
    expect(finding?.severity).toBe("critical");
  });

  it("does not flag signature-empty when alg is none (that's expected)", () => {
    const decoded = decodeToken(token({ alg: "none" }, { sub: "x" }, ""));
    expect(ids(explainToken(decoded, { now: NOW }))).not.toContain("signature-empty");
  });

  it("flags an embedded jwk header", () => {
    const decoded = decodeToken(token({ alg: "RS256", jwk: { kty: "RSA" } }, { sub: "x" }));
    const finding = explainToken(decoded, { now: NOW }).find((f) => f.id === "header-jwk");
    expect(finding?.severity).toBe("critical");
  });

  it("flags a jku header", () => {
    const decoded = decodeToken(token({ alg: "RS256", jku: "https://evil.example/keys" }, { sub: "x" }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("header-jku");
  });

  it("flags an x5c header", () => {
    const decoded = decodeToken(token({ alg: "RS256", x5c: ["MIIC..."] }, { sub: "x" }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("header-x5c");
  });

  it("flags a kid containing path traversal", () => {
    const decoded = decodeToken(token({ alg: "HS256", kid: "../../etc/passwd" }, { sub: "x" }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("header-kid-suspicious");
  });

  it("flags a kid containing SQL-injection-like content", () => {
    const decoded = decodeToken(token({ alg: "HS256", kid: "1' OR '1'='1" }, { sub: "x" }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("header-kid-suspicious");
  });

  it("does not flag an ordinary opaque kid", () => {
    const decoded = decodeToken(token({ alg: "HS256", kid: "2024-prod-key-01" }, { sub: "x", exp: 9999999999 }));
    expect(ids(explainToken(decoded, { now: NOW }))).not.toContain("header-kid-suspicious");
  });

  it("flags a non-empty crit header", () => {
    const decoded = decodeToken(token({ alg: "HS256", crit: ["exp"] }, { sub: "x" }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("header-crit");
  });

  it("does not flag an empty crit array", () => {
    const decoded = decodeToken(token({ alg: "HS256", crit: [] }, { sub: "x", exp: 9999999999 }));
    expect(ids(explainToken(decoded, { now: NOW }))).not.toContain("header-crit");
  });

  it("flags a non-JWT typ", () => {
    const decoded = decodeToken(token({ alg: "HS256", typ: "at+jwt" }, { sub: "x", exp: 9999999999 }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("header-typ-unexpected");
  });

  it("treats typ: JWT case-insensitively as fine", () => {
    const decoded = decodeToken(token({ alg: "HS256", typ: "jwt" }, { sub: "x", exp: 9999999999 }));
    expect(ids(explainToken(decoded, { now: NOW }))).not.toContain("header-typ-unexpected");
  });

  it("flags a missing exp claim", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", iat: 1735689600 }));
    const finding = explainToken(decoded, { now: NOW }).find((f) => f.id === "exp-missing");
    expect(finding?.severity).toBe("high");
  });

  it("flags exp that isn't a NumericDate", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", exp: "tomorrow" }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("exp-not-numeric");
  });

  it("flags an expired token as info", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", exp: 1735689600 - 3600 }));
    const finding = explainToken(decoded, { now: NOW }).find((f) => f.id === "exp-expired");
    expect(finding?.severity).toBe("info");
    expect(finding?.detail).toMatch(/1h/);
  });

  it("does not flag exp-expired for a token that still has time left", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", exp: 1735689600 + 3600 }));
    expect(ids(explainToken(decoded, { now: NOW }))).not.toContain("exp-expired");
  });

  it("flags a token lifetime longer than a year", () => {
    const decoded = decodeToken(
      token({ alg: "HS256" }, { sub: "x", iat: 1735689600, exp: 1735689600 + 60 * 60 * 24 * 400 }),
    );
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("exp-far-future");
  });

  it("does not flag exp-far-future for a normal short-lived token", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", iat: 1735689600, exp: 1735689600 + 900 }));
    expect(ids(explainToken(decoded, { now: NOW }))).not.toContain("exp-far-future");
  });

  it("flags a missing iat claim", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", exp: 9999999999 }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("iat-missing");
  });

  it("flags iat that isn't a NumericDate", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", iat: "yesterday", exp: 9999999999 }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("iat-not-numeric");
  });

  it("flags iat set in the future beyond clock-skew tolerance", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", iat: 1735689600 + 3600, exp: 9999999999 }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("iat-future");
  });

  it("does not flag iat within the small clock-skew tolerance", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", iat: 1735689600 + 30, exp: 9999999999 }));
    expect(ids(explainToken(decoded, { now: NOW }))).not.toContain("iat-future");
  });

  it("flags nbf that isn't a NumericDate", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", nbf: "later", iat: 1735689600, exp: 9999999999 }));
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("nbf-not-numeric");
  });

  it("flags nbf in the future", () => {
    const decoded = decodeToken(
      token({ alg: "HS256" }, { sub: "x", nbf: 1735689600 + 3600, iat: 1735689600, exp: 9999999999 }),
    );
    const finding = explainToken(decoded, { now: NOW }).find((f) => f.id === "nbf-future");
    expect(finding?.severity).toBe("info");
  });

  it("does not flag nbf that has already passed", () => {
    const decoded = decodeToken(
      token({ alg: "HS256" }, { sub: "x", nbf: 1735689600 - 3600, iat: 1735689600, exp: 9999999999 }),
    );
    expect(ids(explainToken(decoded, { now: NOW }))).not.toContain("nbf-future");
  });

  it("flags missing aud, iss, sub", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { iat: 1735689600, exp: 9999999999 }));
    const found = ids(explainToken(decoded, { now: NOW }));
    expect(found).toContain("aud-missing");
    expect(found).toContain("iss-missing");
    expect(found).toContain("sub-missing");
  });

  it("does not flag aud/iss/sub when present", () => {
    const decoded = decodeToken(
      token({ alg: "HS256" }, { sub: "u1", aud: "api", iss: "auth", iat: 1735689600, exp: 9999999999 }),
    );
    const found = ids(explainToken(decoded, { now: NOW }));
    expect(found).not.toContain("aud-missing");
    expect(found).not.toContain("iss-missing");
    expect(found).not.toContain("sub-missing");
  });

  it("flags an implausible far-future date claim (likely a milliseconds bug)", () => {
    const decoded = decodeToken(
      token({ alg: "HS256" }, { sub: "x", iat: 1735689600, exp: 1735689600000 }), // ms, not seconds
    );
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("exp-implausible");
  });

  it("flags an oversized token", () => {
    const decoded = decodeToken(
      token({ alg: "HS256" }, { sub: "x", exp: 9999999999, blob: "x".repeat(9000) }),
    );
    expect(ids(explainToken(decoded, { now: NOW }))).toContain("token-oversized");
  });

  it("does not flag token-oversized for a normal-sized token", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", exp: 9999999999 }));
    expect(ids(explainToken(decoded, { now: NOW }))).not.toContain("token-oversized");
  });

  it("reports header/payload malformed findings from decode errors", () => {
    const decoded = decodeToken("not valid!!.also invalid!!.sig");
    const found = ids(explainToken(decoded, { now: NOW }));
    expect(found).toContain("header-malformed");
    expect(found).toContain("payload-malformed");
  });

  describe("signature verification outcomes", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", exp: 9999999999 }));

    it("reports a critical finding when a weak secret cracked the signature", () => {
      const finding = explainToken(decoded, { now: NOW, crackedSecret: "secret" }).find(
        (f) => f.id === "hmac-secret-weak",
      );
      expect(finding?.severity).toBe("critical");
      expect(finding?.detail).toContain("secret");
    });

    it("reports signature-invalid when verification explicitly failed", () => {
      const finding = explainToken(decoded, { now: NOW, signatureVerified: false }).find(
        (f) => f.id === "signature-invalid",
      );
      expect(finding?.severity).toBe("high");
    });

    it("reports signature-valid (info) when verification explicitly succeeded", () => {
      const finding = explainToken(decoded, { now: NOW, signatureVerified: true }).find(
        (f) => f.id === "signature-valid",
      );
      expect(finding?.severity).toBe("info");
    });

    it("reports nothing signature-related when verification wasn't attempted", () => {
      const found = ids(explainToken(decoded, { now: NOW }));
      expect(found).not.toContain("signature-valid");
      expect(found).not.toContain("signature-invalid");
      expect(found).not.toContain("hmac-secret-weak");
    });
  });

  it("sorts findings by descending severity", () => {
    const decoded = decodeToken(token({ alg: "none" }, {}, ""));
    const findings = explainToken(decoded, { now: NOW });
    const order = ["critical", "high", "medium", "low", "info"];
    const positions = findings.map((f) => order.indexOf(f.severity));
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it("defaults `now` to the current time when not provided", () => {
    const decoded = decodeToken(token({ alg: "HS256" }, { sub: "x", exp: Math.floor(Date.now() / 1000) - 10 }));
    expect(ids(explainToken(decoded))).toContain("exp-expired");
  });
});
