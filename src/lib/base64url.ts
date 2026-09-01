/**
 * base64url helpers (RFC 4648 §5) used by JWT's three dot-separated segments.
 * Deliberately dependency-free: every JS runtime we care about (evergreen
 * browsers, Node 18+) ships `atob`/`btoa` or a `Buffer`, but not a shared
 * base64url primitive, so this file is the one place that knows the
 * '+/' <-> '-_' swap and the padding rules.
 */

export class Base64UrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Base64UrlError";
  }
}

function toStandardBase64(input: string): string {
  // base64url swaps the two characters that are unsafe in URLs/filenames.
  let standard = input.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = standard.length % 4;
  if (remainder === 1) {
    // A valid base64 payload can never leave a single leftover character;
    // padding cannot fix this, so the input itself is malformed.
    throw new Base64UrlError("invalid base64url length");
  }
  if (remainder > 0) {
    standard += "=".repeat(4 - remainder);
  }
  return standard;
}

/** Decode a base64url string to raw bytes. */
export function base64UrlDecodeBytes(input: string): Uint8Array {
  if (input === "") return new Uint8Array(0);
  const standard = toStandardBase64(input);
  if (typeof atob === "function") {
    let binary: string;
    try {
      binary = atob(standard);
    } catch {
      throw new Base64UrlError("invalid base64url characters");
    }
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  /* v8 ignore next 3 -- unreachable on every runtime this project targets (Node 18+, evergreen browsers all have atob); kept as a defensive fallback for older/unusual hosts. */
  const buf = Buffer.from(standard, "base64");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/** Decode a base64url string to a UTF-8 string. */
export function base64UrlDecodeUtf8(input: string): string {
  const bytes = base64UrlDecodeBytes(input);
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

/** Encode raw bytes to base64url (no padding). */
export function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 =
    typeof btoa === "function"
      ? btoa(binary)
      : Buffer.from(bytes).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Encode a UTF-8 string to base64url. */
export function base64UrlEncodeUtf8(input: string): string {
  return base64UrlEncodeBytes(new TextEncoder().encode(input));
}
