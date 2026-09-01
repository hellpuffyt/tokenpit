import { describe, expect, it } from "vitest";
import { base64UrlEncodeUtf8 } from "./base64url";
import { decodeToken, decodeSignatureBytes, TokenFormatError } from "./decode";
import { EXAMPLE_TOKENS } from "./examples";

function seg(obj: unknown): string {
  return base64UrlEncodeUtf8(JSON.stringify(obj));
}

describe("decodeToken", () => {
  it("decodes a well-formed token's header and payload", () => {
    const token = EXAMPLE_TOKENS.find((e) => e.id === "healthy")!.token;
    const decoded = decodeToken(token);
    expect(decoded.header.json).toEqual({ alg: "HS256", typ: "JWT" });
    expect(decoded.payload.json?.sub).toBe("user_8f2c1");
    expect(decoded.signature.length).toBeGreaterThan(0);
    expect(decoded.signingInput).toBe(`${decoded.parts[0]}.${decoded.parts[1]}`);
  });

  it("throws TokenFormatError when the token doesn't have exactly 3 segments", () => {
    expect(() => decodeToken("only.two")).toThrow(TokenFormatError);
    expect(() => decodeToken("a.b.c.d")).toThrow(TokenFormatError);
    expect(() => decodeToken("nodots")).toThrow(TokenFormatError);
  });

  it("trims surrounding whitespace before splitting", () => {
    const token = EXAMPLE_TOKENS.find((e) => e.id === "healthy")!.token;
    const decoded = decodeToken(`  ${token}\n`);
    expect(decoded.header.json).toBeDefined();
  });

  it("tolerates an empty signature segment (alg: none)", () => {
    const decoded = decodeToken(`${seg({ alg: "none" })}.${seg({ sub: "x" })}.`);
    expect(decoded.signature).toBe("");
    expect(decodeSignatureBytes(decoded)).toEqual(new Uint8Array(0));
  });

  it("reports a per-segment error for invalid base64url in the header", () => {
    const decoded = decodeToken(`not valid!!.${seg({ sub: "x" })}.sig`);
    expect(decoded.header.json).toBeUndefined();
    expect(decoded.header.error).toMatch(/base64url/i);
  });

  it("reports a per-segment error for JSON that doesn't parse", () => {
    const decoded = decodeToken(`${base64UrlEncodeUtf8("not json")}.${seg({ sub: "x" })}.sig`);
    expect(decoded.header.json).toBeUndefined();
    expect(decoded.header.error).toMatch(/not valid JSON/i);
  });

  it("reports a per-segment error when JSON parses but isn't an object", () => {
    const decoded = decodeToken(`${base64UrlEncodeUtf8("[1,2,3]")}.${seg({ sub: "x" })}.sig`);
    expect(decoded.header.json).toBeUndefined();
    expect(decoded.header.error).toMatch(/must be an object/i);

    const decodedNum = decodeToken(`${base64UrlEncodeUtf8("42")}.${seg({ sub: "x" })}.sig`);
    expect(decodedNum.header.json).toBeUndefined();
  });

  it("reports an empty-segment error when a segment is the empty string", () => {
    const decoded = decodeToken(`.${seg({ sub: "x" })}.sig`);
    expect(decoded.header.error).toMatch(/empty/i);
  });

  it("decodes header and payload independently — one being broken doesn't block the other", () => {
    const decoded = decodeToken(`${seg({ alg: "HS256" })}.not valid!!.sig`);
    expect(decoded.header.json).toEqual({ alg: "HS256" });
    expect(decoded.payload.json).toBeUndefined();
    expect(decoded.payload.error).toBeDefined();
  });
});
