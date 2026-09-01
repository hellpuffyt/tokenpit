import { base64UrlDecodeBytes, base64UrlDecodeUtf8, Base64UrlError } from "./base64url.js";

/** A JSON value as parsed from a JWT segment — claims are arbitrary JSON. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

export interface DecodedSegment {
  /** The raw base64url text of the segment, exactly as it appeared in the token. */
  raw: string;
  /** Parsed JSON, or undefined if the segment was not valid JSON. */
  json: JsonObject | undefined;
  /** Parse error message, set when `json` is undefined. */
  error?: string;
}

export interface DecodedToken {
  header: DecodedSegment;
  payload: DecodedSegment;
  /** Raw base64url text of the signature segment (may be empty). */
  signature: string;
  /** The bytes covered by the signature: `header.raw + "." + payload.raw`. */
  signingInput: string;
  /** The token split into exactly three dot-separated parts. */
  parts: [string, string, string];
}

export class TokenFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenFormatError";
  }
}

function decodeSegment(raw: string, label: string): DecodedSegment {
  if (raw === "") {
    return { raw, json: undefined, error: `${label} segment is empty` };
  }
  let text: string;
  try {
    text = base64UrlDecodeUtf8(raw);
  } catch (err) {
    const message = err instanceof Base64UrlError ? err.message : "decode failed";
    return { raw, json: undefined, error: `${label} is not valid base64url: ${message}` };
  }
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return { raw, json: undefined, error: `${label} JSON must be an object` };
    }
    return { raw, json: parsed as JsonObject };
  } catch {
    return { raw, json: undefined, error: `${label} is not valid JSON` };
  }
}

/**
 * Split and decode a compact JWT into its three segments without verifying
 * anything. Structural problems (wrong segment count, bad base64url, bad
 * JSON) are reported per-segment rather than thrown, so a partially-broken
 * token can still be inspected — a workbench that refuses to render half a
 * token is less useful than one that shows exactly what's wrong with it.
 */
export function decodeToken(token: string): DecodedToken {
  const trimmed = token.trim();
  const parts = trimmed.split(".");
  if (parts.length !== 3) {
    throw new TokenFormatError(
      `expected 3 dot-separated segments (header.payload.signature), got ${parts.length}`,
    );
  }
  const [headerRaw, payloadRaw, signature] = parts as [string, string, string];
  return {
    header: decodeSegment(headerRaw, "header"),
    payload: decodeSegment(payloadRaw, "payload"),
    signature,
    signingInput: `${headerRaw}.${payloadRaw}`,
    parts: [headerRaw, payloadRaw, signature],
  };
}

/** Raw signature bytes, decoded from base64url. Throws on malformed base64url. */
export function decodeSignatureBytes(decoded: DecodedToken): Uint8Array {
  return base64UrlDecodeBytes(decoded.signature);
}
