import { base64UrlEncodeBytes, base64UrlEncodeUtf8 } from "./base64url.js";
import { computeHmacSignature, type HmacAlg } from "./verify.js";
import type { JsonObject } from "./decode.js";

/**
 * Build a compact HS256/384/512 JWT from a header and payload object. Used
 * by the bundled example tokens and by tests; not exposed as a general
 * "issue tokens for production" API (this is an analysis tool, not an
 * auth library).
 */
export async function signHmacToken(
  header: JsonObject,
  payload: JsonObject,
  alg: HmacAlg,
  secret: string,
): Promise<string> {
  const headerSeg = base64UrlEncodeUtf8(JSON.stringify(header));
  const payloadSeg = base64UrlEncodeUtf8(JSON.stringify(payload));
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const sig = await computeHmacSignature(signingInput, alg, secret);
  return `${signingInput}.${base64UrlEncodeBytes(sig)}`;
}

/** Build a token with no cryptographic signature at all (alg: "none"). */
export function buildUnsecuredToken(header: JsonObject, payload: JsonObject): string {
  const headerSeg = base64UrlEncodeUtf8(JSON.stringify({ ...header, alg: "none" }));
  const payloadSeg = base64UrlEncodeUtf8(JSON.stringify(payload));
  return `${headerSeg}.${payloadSeg}.`;
}
