/**
 * Adversarial regression suite: the attack classes a JWT diagnostic tool
 * must recognise (alg=none, RS256->HS256 algorithm confusion, time-claim
 * boundaries, kid injection probes, malformed segments). Every expectation
 * here was checked against the engine's actual behaviour; nothing is
 * asserted that the code does not do.
 */
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportSPKI, exportJWK } from "jose";
import { decodeToken, TokenFormatError } from "./decode";
import { explainToken } from "./rules";
import { base64UrlEncodeBytes, base64UrlEncodeUtf8 } from "./base64url";
import { computeHmacSignature, looksLikePublicKey, verifyHmacSignature } from "./verify";
import { run } from "../cli";

const NOW = new Date(1735689600 * 1000);
const NOW_S = 1735689600;
const seg = (o: unknown) => base64UrlEncodeUtf8(JSON.stringify(o));
const GOOD_PAYLOAD = { sub: "u", iss: "i", aud: "a", iat: NOW_S, exp: NOW_S + 900 };
const ids = (t: string, ctx: Parameters<typeof explainToken>[1] = {}) =>
  explainToken(decodeToken(t), { now: NOW, ...ctx }).map((f) => f.id);

async function forgeWithPublicKey(): Promise<{ token: string; pem: string; jwkText: string }> {
  const { publicKey } = await generateKeyPair("RS256", { extractable: true });
  const pem = await exportSPKI(publicKey);
  const jwkText = JSON.stringify(await exportJWK(publicKey));
  const signingInput = `${seg({ alg: "HS256", typ: "JWT" })}.${seg(GOOD_PAYLOAD)}`;
  const sig = base64UrlEncodeBytes(await computeHmacSignature(signingInput, "HS256", pem));
  return { token: `${signingInput}.${sig}`, pem, jwkText };
}

describe("alg=none variants", () => {
  for (const alg of ["none", "None", "NONE", "nOnE", " none "]) {
    it(`flags alg ${JSON.stringify(alg)} as critical, with or without a trailing signature`, () => {
      expect(ids(`${seg({ alg })}.${seg(GOOD_PAYLOAD)}.`)).toContain("alg-none");
      expect(ids(`${seg({ alg })}.${seg(GOOD_PAYLOAD)}.c2ln`)).toContain("alg-none");
    });
  }
});

describe("RS256 -> HS256 algorithm confusion", () => {
  it("detects PEM public keys, certificates and public JWKs, not ordinary secrets", async () => {
    const { pem, jwkText } = await forgeWithPublicKey();
    expect(looksLikePublicKey(pem)).toBe(true);
    expect(looksLikePublicKey(`\n  ${pem}  `)).toBe(true);
    expect(looksLikePublicKey(jwkText)).toBe(true);
    expect(looksLikePublicKey("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")).toBe(true);
    expect(looksLikePublicKey("a-sufficiently-long-random-signing-key-32bytes+")).toBe(false);
    expect(looksLikePublicKey('{"kty":"oct","k":"c2VjcmV0"}')).toBe(false);
    expect(looksLikePublicKey("{not json")).toBe(false);
  });

  it("a token HMAC-signed with the public key is reported as forged (critical), not as a valid signature", async () => {
    const { token, pem } = await forgeWithPublicKey();
    const decoded = decodeToken(token);
    const verified = await verifyHmacSignature(decoded, "HS256", pem);
    expect(verified).toBe(true); // the forgery really does verify under HMAC
    const found = ids(token, { signatureVerified: true, hmacKeyIsPublicKey: true });
    expect(found).toContain("alg-confusion-forged");
    expect(found).not.toContain("signature-valid");
    const forged = explainToken(decoded, { now: NOW, signatureVerified: true, hmacKeyIsPublicKey: true }).find(
      (f) => f.id === "alg-confusion-forged",
    );
    expect(forged?.severity).toBe("critical");
  });

  it("the CLI reports the forgery and exits 1 when --secret is the PEM public key", async () => {
    const { token, pem } = await forgeWithPublicKey();
    const lines: string[] = [];
    const code = await run([token, "--secret", pem, "--now", String(NOW_S)], (s) => lines.push(s));
    expect(code).toBe(1);
    const parsed = JSON.parse(lines[0] ?? "") as { findings: { id: string; severity: string }[] };
    expect(parsed.findings[0]).toMatchObject({ id: "alg-confusion-forged", severity: "critical" });
  });

  it("a real shared secret that verifies is still reported as signature-valid", async () => {
    const signingInput = `${seg({ alg: "HS256" })}.${seg(GOOD_PAYLOAD)}`;
    const secret = ["a-long", "random", "shared-secret", "value-0123456789"].join("-");
    const sig = base64UrlEncodeBytes(await computeHmacSignature(signingInput, "HS256", secret));
    const lines: string[] = [];
    const code = await run([`${signingInput}.${sig}`, "--secret", secret, "--now", String(NOW_S)], (s) =>
      lines.push(s),
    );
    expect(code).toBe(0);
    expect(lines[0]).toContain('"signature-valid"');
    expect(lines[0]).not.toContain("alg-confusion-forged");
  });
});

describe("time-claim boundaries (RFC 7519 §4.1.4/§4.1.5)", () => {
  const t = (p: object) => `${seg({ alg: "HS256" })}.${seg({ ...GOOD_PAYLOAD, ...p })}.c2ln`;
  it("exp exactly equal to now is expired; exp one second later is not", () => {
    expect(ids(t({ exp: NOW_S }))).toContain("exp-expired");
    expect(ids(t({ exp: NOW_S + 1 }))).not.toContain("exp-expired");
  });
  it("nbf one second in the future is flagged; nbf equal to now is not", () => {
    expect(ids(t({ nbf: NOW_S + 1 }))).toContain("nbf-future");
    expect(ids(t({ nbf: NOW_S }))).not.toContain("nbf-future");
  });
  it("string, boolean and null time claims are not treated as valid NumericDates", () => {
    for (const v of ["1735693200", true, null]) {
      expect(ids(t({ exp: v }))).toContain("exp-not-numeric");
      expect(ids(t({ nbf: v }))).toContain("nbf-not-numeric");
    }
  });
  it("milliseconds-instead-of-seconds exp is flagged implausible", () => {
    expect(ids(t({ exp: (NOW_S + 900) * 1000 }))).toContain("exp-implausible");
  });
});

describe("kid injection probes", () => {
  const flagged = [
    "../../../../dev/null",
    "..\\..\\keys\\k",
    "/dev/null",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "1' OR '1'='1",
    "x UNION SELECT 'k'",
    "key|whoami",
    "key && id",
    "k$(id)",
    "k`id`",
    "k\u0000.pem",
  ];
  for (const kid of flagged) {
    it(`flags kid ${JSON.stringify(kid)}`, () => {
      expect(ids(`${seg({ alg: "HS256", kid })}.${seg(GOOD_PAYLOAD)}.c2ln`)).toContain("header-kid-suspicious");
    });
  }
  const benign = ["2024-prod-key-01", "a1b2c3d4", "https://keys.example.com/k1", "rsa/primary", "key.v2"];
  for (const kid of benign) {
    it(`does not flag ordinary kid ${JSON.stringify(kid)}`, () => {
      expect(ids(`${seg({ alg: "HS256", kid })}.${seg(GOOD_PAYLOAD)}.c2ln`)).not.toContain("header-kid-suspicious");
    });
  }
});

describe("malformed segments", () => {
  const p = seg(GOOD_PAYLOAD);
  const cases: [string, string][] = [
    ["empty header", `.${p}.c2ln`],
    ["invalid base64url characters", `e!J.${p}.c2ln`],
    ["impossible base64url length", `eyJhb.${p}.c2ln`],
    ["valid base64url that is not JSON", `${base64UrlEncodeUtf8("not json")}.${p}.c2ln`],
    ["JSON array header", `${base64UrlEncodeUtf8("[]")}.${p}.c2ln`],
    ["JSON string header", `${base64UrlEncodeUtf8('"HS256"')}.${p}.c2ln`],
    ["JSON null header", `${base64UrlEncodeUtf8("null")}.${p}.c2ln`],
  ];
  for (const [name, tok] of cases) {
    it(`reports header-malformed (high) for ${name} without throwing`, () => {
      const findings = explainToken(decodeToken(tok), { now: NOW });
      expect(findings.find((f) => f.id === "header-malformed")?.severity).toBe("high");
    });
  }
  it("reports payload-malformed for a non-object payload", () => {
    expect(ids(`${seg({ alg: "HS256" })}.${base64UrlEncodeUtf8("42")}.c2ln`)).toContain("payload-malformed");
  });
  it("rejects tokens with the wrong number of segments (including 5-part JWE) with TokenFormatError", () => {
    for (const tok of ["", "a", "a.b", "a.b.c.d", "a.b.c.d.e"]) {
      expect(() => decodeToken(tok)).toThrow(TokenFormatError);
    }
  });
  it("an invalid-base64url signature never verifies", async () => {
    const decoded = decodeToken(`${seg({ alg: "HS256" })}.${p}.!!!`);
    expect(await verifyHmacSignature(decoded, "HS256", "secret")).toBe(false);
  });
  it("handles a very large token in bounded time and flags it as oversized", () => {
    const big = `${seg({ alg: "HS256" })}.${seg({ ...GOOD_PAYLOAD, blob: "x".repeat(2_000_000) })}.c2ln`;
    const start = Date.now();
    expect(ids(big)).toContain("token-oversized");
    expect(Date.now() - start).toBeLessThan(5000);
  });
});
