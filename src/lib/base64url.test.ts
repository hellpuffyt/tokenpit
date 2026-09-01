import { describe, expect, it } from "vitest";
import {
  Base64UrlError,
  base64UrlDecodeBytes,
  base64UrlDecodeUtf8,
  base64UrlEncodeBytes,
  base64UrlEncodeUtf8,
} from "./base64url";

describe("base64url round-trip", () => {
  it("encodes and decodes UTF-8 text, including multi-byte characters", () => {
    const cases = ["", "a", "hello world", '{"alg":"HS256"}', "emoji: 🔥🚀", "line\nbreak\ttab"];
    for (const text of cases) {
      const encoded = base64UrlEncodeUtf8(text);
      expect(encoded).not.toMatch(/[+/=]/);
      expect(base64UrlDecodeUtf8(encoded)).toBe(text);
    }
  });

  it("encodes and decodes raw bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const encoded = base64UrlEncodeBytes(bytes);
    expect(base64UrlDecodeBytes(encoded)).toEqual(bytes);
  });

  it("produces no padding characters even when input length needs it", () => {
    // 1, 2, and 3 raw bytes exercise every base64 padding case (==, =, none).
    expect(base64UrlEncodeBytes(new Uint8Array([1]))).not.toContain("=");
    expect(base64UrlEncodeBytes(new Uint8Array([1, 2]))).not.toContain("=");
    expect(base64UrlEncodeBytes(new Uint8Array([1, 2, 3]))).not.toContain("=");
  });

  it("decodes an empty string to zero bytes", () => {
    expect(base64UrlDecodeBytes("")).toEqual(new Uint8Array(0));
    expect(base64UrlDecodeUtf8("")).toBe("");
  });

  it("tolerates base64url-encoded input that already lacks padding at every remainder", () => {
    // "f" -> Zg, "fo" -> Zm8, "foo" -> Zm9v (remainders of 2, 3, 0 chars mod 4)
    expect(base64UrlDecodeUtf8("Zg")).toBe("f");
    expect(base64UrlDecodeUtf8("Zm8")).toBe("fo");
    expect(base64UrlDecodeUtf8("Zm9v")).toBe("foo");
  });

  it("throws Base64UrlError for a length that can never be valid base64", () => {
    // remainder-1 (5 chars) can't be padded into a valid base64 quantum.
    expect(() => base64UrlDecodeBytes("abcde")).toThrow(Base64UrlError);
  });

  it("throws Base64UrlError for invalid characters", () => {
    expect(() => base64UrlDecodeBytes("not valid base64!!")).toThrow(Base64UrlError);
  });

  it("swaps -_ for +/ correctly (round-trips bytes that would base64 to + or /)", () => {
    // Byte sequences chosen so standard base64 would contain '+' and '/'.
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf]);
    const encoded = base64UrlEncodeBytes(bytes);
    expect(encoded).not.toMatch(/[+/]/);
    expect(base64UrlDecodeBytes(encoded)).toEqual(bytes);
  });
});
