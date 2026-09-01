import type { DecodedToken, JsonObject, JsonValue } from "./decode.js";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  /** Stable machine-readable id, e.g. "alg-none". Used in tests and deep links. */
  id: string;
  severity: Severity;
  title: string;
  /** What this specific token/claim combination does, in plain language. */
  detail: string;
  /** What to do about it. */
  recommendation: string;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function claim(payload: JsonObject | undefined, key: string): JsonValue | undefined {
  if (!payload) return undefined;
  return payload[key];
}

function asNumericDate(v: JsonValue | undefined): number | undefined {
  // JWT NumericDate (RFC 7519 §2) is defined as a JSON number of seconds
  // since the epoch. A string that merely looks numeric is still a spec
  // violation many libraries mis-handle, so it's flagged separately.
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

const SUSPICIOUS_KID_PATTERN = /(\.\.[/\\])|['";`]|(\bunion\b)|(\bselect\b)|(\bdrop\b)/i;

/**
 * Evaluate every rule against a decoded token and an optional bag of
 * verification context (whether we could check the signature, and
 * against what). Each rule is independent and side-effect free; a rule
 * that doesn't apply (e.g. the exp-related rules when there is no
 * payload at all) simply contributes nothing.
 */
export interface ExplainContext {
  now?: Date;
  /** Set once the workbench has attempted signature verification. */
  signatureVerified?: boolean;
  /** Present when an HS256/384/512 secret produced a valid signature. */
  crackedSecret?: string | null;
}

export function explainToken(decoded: DecodedToken, ctx: ExplainContext = {}): Finding[] {
  const findings: Finding[] = [];
  const now = ctx.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);

  const header = decoded.header.json;
  const payload = decoded.payload.json;

  if (decoded.header.error) {
    findings.push({
      id: "header-malformed",
      severity: "high",
      title: "Header is not valid JSON",
      detail: decoded.header.error,
      recommendation:
        "A token whose header can't be parsed can't be trusted or processed; reject it before it reaches any business logic.",
    });
  }
  if (decoded.payload.error) {
    findings.push({
      id: "payload-malformed",
      severity: "high",
      title: "Payload is not valid JSON",
      detail: decoded.payload.error,
      recommendation: "Reject tokens whose payload fails to parse as a JSON object.",
    });
  }

  // --- alg header -----------------------------------------------------
  const algRaw = header ? claim(header, "alg") : undefined;
  if (header && (algRaw === undefined || algRaw === null)) {
    findings.push({
      id: "alg-missing",
      severity: "high",
      title: '"alg" claim is missing',
      detail:
        'The header has no "alg" field. Some JWT libraries default to a fallback algorithm when this is absent, which an attacker can use to smuggle a different verification path than the server intended.',
      recommendation:
        'Always set "alg" explicitly when issuing tokens, and configure verifiers with an explicit allow-list of algorithms rather than trusting the header.',
    });
  } else if (typeof algRaw === "string") {
    if (algRaw.trim().toLowerCase() === "none") {
      const isExactCase = algRaw === "none";
      findings.push({
        id: "alg-none",
        severity: "critical",
        title: isExactCase
          ? '"alg" is "none" — signature is not checked at all'
          : `"alg" is "${algRaw}" — a case-variant of "none"`,
        detail: isExactCase
          ? "This token declares the unsecured JWS algorithm. Any party can produce a token like this with any payload they want; a verifier that honors the header's alg without an allow-list will accept it as authentic."
          : `Some JWT libraries lowercase "alg" before comparing it, so "${algRaw}" is silently treated the same as "none" — this is the exact bypass from CVE-2015-9235 and the wave of "alg confusion" advisories that followed it.`,
        recommendation:
          'Verifiers must reject "none" (in any casing) unless a token is explicitly, intentionally unsecured, and should never accept an algorithm the caller did not request.',
      });
    } else if (algRaw.length === 0) {
      findings.push({
        id: "alg-empty",
        severity: "high",
        title: '"alg" is an empty string',
        detail: "An empty algorithm name is not a valid JWS algorithm and should never verify.",
        recommendation: "Reject tokens whose alg is not one of your explicitly supported values.",
      });
    }

    if (/^HS/i.test(algRaw)) {
      findings.push({
        id: "alg-confusion-hs-rs",
        severity: "medium",
        title: "HMAC algorithm — verify the key really is a shared secret",
        detail:
          "If this server also accepts RS256/ES256 tokens signed with an asymmetric key pair, and the verifier picks its algorithm from the token header, an attacker who knows the RSA/EC public key can forge an HS256 token by HMAC-signing it with that public key as the secret (the classic RS256→HS256 \"algorithm confusion\" attack).",
        recommendation:
          "Pin the expected algorithm per key/issuer at verification time instead of trusting the token's own alg header.",
      });
    }
  } else if (algRaw !== undefined) {
    findings.push({
      id: "alg-not-string",
      severity: "high",
      title: '"alg" is not a string',
      detail: `Expected a string algorithm identifier, found ${typeof algRaw}.`,
      recommendation: "Reject tokens whose alg field is not a string.",
    });
  }

  // --- signature / structural issues ----------------------------------
  const algDisplay = typeof algRaw === "string" ? algRaw : JSON.stringify(algRaw);
  if (header && algRaw !== undefined && (typeof algRaw !== "string" || algRaw.toLowerCase() !== "none")) {
    if (decoded.signature.length === 0) {
      findings.push({
        id: "signature-empty",
        severity: "critical",
        title: "Signature segment is empty",
        detail: `The header declares "alg": "${algDisplay}" but the token has no signature bytes. A verifier that only checks "is the signature segment present" rather than cryptographically verifying it can be fooled by this.`,
        recommendation: "Always run the actual signature-verification routine; never treat a non-empty header as proof of authenticity.",
      });
    }
  }

  // --- embedded / external key material in the header ------------------
  if (header && "jwk" in header) {
    findings.push({
      id: "header-jwk",
      severity: "critical",
      title: '"jwk" key embedded directly in the header',
      detail:
        "The token carries its own public key in the header instead of referencing one the verifier already trusts. A verifier that blindly uses this embedded key to check the signature will accept any token an attacker signs with a key of their own choosing.",
      recommendation:
        'Never verify against a key supplied by the token itself. Only accept keys from a pre-configured trust store, keyed by "kid".',
    });
  }
  if (header && "jku" in header) {
    findings.push({
      id: "header-jku",
      severity: "high",
      title: '"jku" points the verifier at an attacker-influenced URL',
      detail:
        'The header names a JWK Set URL to fetch the verification key from. If the verifier follows it without an allow-list, an attacker who controls (or can redirect/SSRF into) that URL controls what key "validates" the token.',
      recommendation:
        "Only fetch jku from a strict allow-list of your own trusted hosts, or ignore it and resolve keys by kid from your own store.",
    });
  }
  if (header && "x5c" in header) {
    findings.push({
      id: "header-x5c",
      severity: "high",
      title: '"x5c" embeds a certificate chain in the header',
      detail:
        "The token supplies its own X.509 certificate chain for verification. If the verifier trusts a self-signed or attacker-issued leaf certificate here instead of validating the chain against a real trust anchor, this becomes the same bypass as an embedded jwk.",
      recommendation:
        "Validate the certificate chain against your own trusted CAs before ever using it, or don't honor x5c at all.",
    });
  }
  if (header) {
    const kid = claim(header, "kid");
    if (typeof kid === "string" && SUSPICIOUS_KID_PATTERN.test(kid)) {
      findings.push({
        id: "header-kid-suspicious",
        severity: "high",
        title: '"kid" contains path-traversal or injection-like characters',
        detail: `kid = ${JSON.stringify(kid)}. Some deployments use "kid" directly to build a filesystem path or SQL query to look up the verification key — a value like this is a probe for exactly that class of bug.`,
        recommendation:
          '"kid" must be treated as an opaque lookup key into a fixed, pre-registered set of key ids — never interpolated into a path, command, or query.',
      });
    }
    const crit = claim(header, "crit");
    if (Array.isArray(crit) && crit.length > 0) {
      findings.push({
        id: "header-crit",
        severity: "medium",
        title: '"crit" declares extension header parameters as mandatory',
        detail: `crit = ${JSON.stringify(crit)}. Per RFC 7515 §4.1.11, a verifier that doesn't understand every parameter listed here is required to reject the token — most JWT libraries do not implement this check.`,
        recommendation:
          "Confirm your JWT library actually enforces crit, or reject tokens that set it if you don't have a specific reason to support it.",
      });
    }
    const typ = claim(header, "typ");
    if (typ !== undefined && typeof typ === "string" && typ.toUpperCase() !== "JWT") {
      findings.push({
        id: "header-typ-unexpected",
        severity: "low",
        title: `"typ" is "${typ}", not "JWT"`,
        detail:
          'A non-standard "typ" can be intentional (e.g. "at+jwt" for OAuth access tokens) but is also how a token meant for one purpose gets replayed as another if the verifier never checks it.',
        recommendation:
          'If your system issues more than one kind of token, verify "typ" explicitly to stop cross-token-type confusion.',
      });
    }
  }

  // --- expiry / lifetime claims -----------------------------------------
  if (payload) {
    const expRaw = claim(payload, "exp");
    if (expRaw === undefined) {
      findings.push({
        id: "exp-missing",
        severity: "high",
        title: '"exp" (expiration) claim is missing',
        detail:
          "Without exp, a verifier that only checks the signature will accept this token forever. A leaked token becomes a permanent credential.",
        recommendation: "Issue every token with a short, explicit exp appropriate to its use.",
      });
    } else {
      const exp = asNumericDate(expRaw);
      if (exp === undefined) {
        findings.push({
          id: "exp-not-numeric",
          severity: "medium",
          title: '"exp" is not a NumericDate',
          detail: `RFC 7519 requires exp to be a JSON number of seconds since the epoch; found ${JSON.stringify(expRaw)}. Libraries that coerce this loosely can produce inconsistent expiry behavior.`,
          recommendation: "Always encode exp as a numeric Unix timestamp, never a string or date.",
        });
      } else {
        if (exp <= nowSeconds) {
          findings.push({
            id: "exp-expired",
            severity: "info",
            title: "Token is expired",
            detail: `exp (${exp}) is ${formatRelative(nowSeconds - exp)} in the past relative to the reference time used here.`,
            recommendation: "A correct verifier must already reject this; no action needed beyond confirming that it does.",
          });
        }

        const iatForLifetime = asNumericDate(claim(payload, "iat"));
        if (iatForLifetime !== undefined && exp - iatForLifetime > 60 * 60 * 24 * 365) {
          findings.push({
            id: "exp-far-future",
            severity: "medium",
            title: "Token lifetime is longer than a year",
            detail: `exp is ${formatRelative(exp - iatForLifetime)} after iat. Long-lived tokens turn any leak (logs, browser history, a compromised client) into a long-lived credential.`,
            recommendation:
              "Prefer short-lived access tokens plus a separate, revocable refresh-token flow over one long-lived JWT.",
          });
        }
      }
    }

    const iatRaw = claim(payload, "iat");
    if (iatRaw === undefined) {
      findings.push({
        id: "iat-missing",
        severity: "low",
        title: '"iat" (issued at) claim is missing',
        detail: "Without iat, there's no anchor for computing token age or lifetime, and some replay-detection strategies rely on it.",
        recommendation: "Set iat when issuing tokens even if you don't currently check it.",
      });
    } else {
      const iat = asNumericDate(iatRaw);
      if (iat === undefined) {
        findings.push({
          id: "iat-not-numeric",
          severity: "low",
          title: '"iat" is not a NumericDate',
          detail: `Found ${JSON.stringify(iatRaw)}; RFC 7519 requires a JSON number.`,
          recommendation: "Encode iat as a numeric Unix timestamp.",
        });
      } else if (iat > nowSeconds + 60) {
        findings.push({
          id: "iat-future",
          severity: "medium",
          title: '"iat" is in the future',
          detail: `iat (${iat}) is ${formatRelative(iat - nowSeconds)} ahead of the reference time. This usually means clock skew between issuer and verifier, or a tampered claim.`,
          recommendation: "Allow only a small clock-skew tolerance (a few minutes), not an unbounded future iat.",
        });
      }
    }

    const nbfRaw = claim(payload, "nbf");
    if (nbfRaw !== undefined) {
      const nbf = asNumericDate(nbfRaw);
      if (nbf === undefined) {
        findings.push({
          id: "nbf-not-numeric",
          severity: "low",
          title: '"nbf" is not a NumericDate',
          detail: `Found ${JSON.stringify(nbfRaw)}; RFC 7519 requires a JSON number.`,
          recommendation: "Encode nbf as a numeric Unix timestamp.",
        });
      } else if (nbf > nowSeconds) {
        findings.push({
          id: "nbf-future",
          severity: "info",
          title: '"nbf" (not before) is in the future',
          detail: `This token isn't valid yet — nbf (${nbf}) is ${formatRelative(nbf - nowSeconds)} from now. A correct verifier must reject it until then.`,
          recommendation: "Expected behavior if this token is meant to activate later; otherwise check the issuer's clock.",
        });
      }
    }

    if (claim(payload, "aud") === undefined) {
      findings.push({
        id: "aud-missing",
        severity: "low",
        title: '"aud" (audience) claim is missing',
        detail:
          "Without aud, a token issued for one service can potentially be replayed against another service that trusts the same issuer's signing key.",
        recommendation: "Set aud to the intended recipient and verify it matches on every check.",
      });
    }
    if (claim(payload, "iss") === undefined) {
      findings.push({
        id: "iss-missing",
        severity: "low",
        title: '"iss" (issuer) claim is missing',
        detail: "Without iss, a verifier that trusts multiple issuers' keys can't tell which issuer actually vouched for this token.",
        recommendation: "Set iss and check it explicitly if you ever trust more than one signing authority.",
      });
    }
    if (claim(payload, "sub") === undefined) {
      findings.push({
        id: "sub-missing",
        severity: "info",
        title: '"sub" (subject) claim is missing',
        detail: "There's no standard identifier for who/what this token represents.",
        recommendation: "Set sub if the token needs to identify a specific principal.",
      });
    }

    for (const key of ["exp", "nbf", "iat"] as const) {
      const v = claim(payload, key);
      if (v !== undefined) {
        const n = asNumericDate(v);
        if (n !== undefined && n > 4102444800) {
          // 4102444800 = 2100-01-01T00:00:00Z
          findings.push({
            id: `${key}-implausible`,
            severity: "low",
            title: `"${key}" is implausibly far in the future`,
            detail: `${key} = ${n}, which is after the year 2100. This is almost always a units bug (milliseconds used where seconds were expected).`,
            recommendation: `Double check ${key} is in seconds, not milliseconds, since the epoch.`,
          });
        }
      }
    }
  }

  // --- size / DoS surface -------------------------------------------
  const totalLength = decoded.parts.join(".").length;
  if (totalLength > 8 * 1024) {
    findings.push({
      id: "token-oversized",
      severity: "low",
      title: "Token is unusually large",
      detail: `The encoded token is ${totalLength} bytes. Very large tokens increase header/cookie size limits risk and the cost of parsing on every request.`,
      recommendation: "Keep JWTs small — store bulk data server-side and reference it by id instead of embedding it in the token.",
    });
  }

  // --- signature verification outcome, if attempted -------------------
  if (ctx.crackedSecret) {
    findings.push({
      id: "hmac-secret-weak",
      severity: "critical",
      title: "Signature verifies against a known weak/example secret",
      detail: `This token's signature was successfully forged using "${ctx.crackedSecret}", a value from a small list of common tutorial/default JWT secrets. Anyone with this tool and that same short list can mint arbitrary valid tokens for this system.`,
      recommendation: "Rotate the signing secret to a high-entropy random value (32+ bytes) generated with a CSPRNG, and never reuse tutorial/example secrets.",
    });
  } else if (ctx.signatureVerified === false) {
    findings.push({
      id: "signature-invalid",
      severity: "high",
      title: "Signature does not verify against the provided key",
      detail: "The signature was checked and did not match — this token is not authentic for the key/secret you supplied.",
      recommendation: "Confirm you're using the correct key/secret and algorithm before trusting anything else about this token.",
    });
  } else if (ctx.signatureVerified === true) {
    findings.push({
      id: "signature-valid",
      severity: "info",
      title: "Signature verifies against the provided key",
      detail: "The signature matches the header and payload for the key/secret you supplied.",
      recommendation: "This confirms integrity for the given key only — it says nothing about exp/aud/iss checks, which the verifier must still perform.",
    });
  }

  return findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

function formatRelative(seconds: number): string {
  const abs = Math.abs(seconds);
  if (abs < 60) return `${abs}s`;
  if (abs < 3600) return `${Math.round(abs / 60)}m`;
  if (abs < 86400) return `${Math.round(abs / 3600)}h`;
  return `${Math.round(abs / 86400)}d`;
}
