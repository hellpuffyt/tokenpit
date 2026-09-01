import { describe, expect, it } from "vitest";
import { decodeToken } from "./decode";
import { buildUnsecuredToken, signHmacToken } from "./encode";
import { verifyHmacSignature } from "./verify";

describe("signHmacToken", () => {
  it("produces a token that verifies with the same secret it was signed with", async () => {
    const token = await signHmacToken({ alg: "HS256", typ: "JWT" }, { sub: "u1", exp: 9999999999 }, "HS256", "s3cret-value");
    const decoded = decodeToken(token);
    expect(decoded.header.json).toEqual({ alg: "HS256", typ: "JWT" });
    expect(decoded.payload.json).toEqual({ sub: "u1", exp: 9999999999 });
    expect(await verifyHmacSignature(decoded, "HS256", "s3cret-value")).toBe(true);
  });
});

describe("buildUnsecuredToken", () => {
  it("produces a 3-part token with alg forced to none and an empty signature", () => {
    const token = buildUnsecuredToken({ typ: "JWT" }, { sub: "admin" });
    const decoded = decodeToken(token);
    expect(decoded.header.json).toEqual({ typ: "JWT", alg: "none" });
    expect(decoded.payload.json).toEqual({ sub: "admin" });
    expect(decoded.signature).toBe("");
    expect(token.endsWith(".")).toBe(true);
  });
});
