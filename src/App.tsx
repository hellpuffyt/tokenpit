import { useEffect, useMemo, useRef, useState } from "react";
import { decodeToken, TokenFormatError, type DecodedToken } from "./lib/decode";
import { explainToken, type Finding } from "./lib/rules";
import { isHmacAlg, isRsaAlg, verifyHmacSignature, verifyRsaSignature, crackWeakHmacSecret, assessSecretStrength } from "./lib/verify";
import { LIVE_EXAMPLES } from "./lib/liveExamples";
import { FindingsList } from "./components/FindingsList";
import { JsonPanel } from "./components/JsonPanel";
import { useTheme } from "./useTheme";

type VerifyStatus =
  | { kind: "none" }
  | { kind: "checking" }
  | { kind: "verified" }
  | { kind: "verified-weak"; secret: string }
  | { kind: "invalid" }
  | { kind: "unsupported-alg"; alg: string };

function App() {
  const [theme, toggleTheme] = useTheme();
  const [tokenText, setTokenText] = useState("");
  const [secret, setSecret] = useState("");
  const [verifyStatus, setVerifyStatus] = useState<VerifyStatus>({ kind: "none" });
  const requestId = useRef(0);

  let decoded: DecodedToken | null = null;
  let structuralError: string | null = null;
  const trimmed = tokenText.trim();
  if (trimmed.length > 0) {
    try {
      decoded = decodeToken(trimmed);
    } catch (err) {
      structuralError = err instanceof TokenFormatError ? err.message : "Could not decode token.";
    }
  }

  const alg = decoded?.header.json?.["alg"];
  const algStr = typeof alg === "string" ? alg : undefined;

  // Live signature check: re-runs whenever the decoded token or the
  // candidate secret changes. Guarded by a request id so a slow crack
  // attempt from a stale token can't overwrite a newer result.
  useEffect(() => {
    const myRequest = ++requestId.current;
    if (!decoded || !algStr) {
      // Synchronous reset (no token / no alg to check yet) rather than an
      // async result — this is the documented cancellable-fetch-in-effect
      // pattern (react.dev/learn/synchronizing-with-effects), not a
      // derived-state anti-pattern.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setVerifyStatus({ kind: "none" });
      return;
    }
    if (isHmacAlg(algStr)) {
      setVerifyStatus({ kind: "checking" });
      const activeDecoded = decoded;
      void (async () => {
        if (secret.trim().length > 0) {
          const ok = await verifyHmacSignature(activeDecoded, algStr, secret);
          if (requestId.current !== myRequest) return;
          setVerifyStatus(ok ? { kind: "verified" } : { kind: "invalid" });
        } else {
          const cracked = await crackWeakHmacSecret(activeDecoded, algStr);
          if (requestId.current !== myRequest) return;
          setVerifyStatus(cracked ? { kind: "verified-weak", secret: cracked } : { kind: "none" });
        }
      })();
    } else if (isRsaAlg(algStr)) {
      if (secret.trim().length > 0) {
        setVerifyStatus({ kind: "checking" });
        const activeDecoded = decoded;
        void (async () => {
          try {
            const ok = await verifyRsaSignature(activeDecoded, algStr, secret);
            if (requestId.current !== myRequest) return;
            setVerifyStatus(ok ? { kind: "verified" } : { kind: "invalid" });
          } catch {
            if (requestId.current !== myRequest) return;
            setVerifyStatus({ kind: "invalid" });
          }
        })();
      } else {
        setVerifyStatus({ kind: "none" });
      }
    } else {
      setVerifyStatus({ kind: "unsupported-alg", alg: algStr });
    }
    // decoded is a fresh object each render from the same tokenText, so we
    // key the effect off the raw text + secret instead of the object identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trimmed, secret, algStr]);

  const findings: Finding[] = useMemo(() => {
    if (!decoded) return [];
    const signatureVerified =
      verifyStatus.kind === "verified" || verifyStatus.kind === "verified-weak"
        ? true
        : verifyStatus.kind === "invalid"
          ? false
          : undefined;
    const crackedSecret = verifyStatus.kind === "verified-weak" ? verifyStatus.secret : undefined;
    return explainToken(decoded, { signatureVerified, crackedSecret });
  }, [decoded, verifyStatus]);

  const secretStrength = secret.trim().length > 0 && algStr && isHmacAlg(algStr) ? assessSecretStrength(secret) : null;

  async function loadExample(id: string) {
    const ex = LIVE_EXAMPLES.find((e) => e.id === id);
    if (!ex) return;
    const built = await ex.build(new Date());
    setTokenText(built);
    setSecret(ex.suggestedSecret ?? "");
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            {"{ }"}
          </span>
          <div>
            <h1>tokenpit</h1>
            <p className="tagline">Decode a JWT, and see the threat model attached to every claim.</p>
          </div>
        </div>
        <button type="button" className="theme-toggle" onClick={toggleTheme} aria-label="Toggle color theme">
          {theme === "dark" ? "☀ Light" : "☾ Dark"}
        </button>
      </header>

      <main className="layout">
        <section className="input-column" aria-label="Token input">
          <div className="field-row">
            <label htmlFor="token-input">JWT</label>
            <select
              aria-label="Load an example token"
              defaultValue=""
              onChange={(e) => {
                void loadExample(e.target.value);
                e.target.value = "";
              }}
            >
              <option value="" disabled>
                Load an example…
              </option>
              {LIVE_EXAMPLES.map((ex) => (
                <option key={ex.id} value={ex.id}>
                  {ex.label}
                </option>
              ))}
            </select>
          </div>
          <textarea
            id="token-input"
            className="token-textarea"
            placeholder="Paste a JSON Web Token (header.payload.signature)…"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            value={tokenText}
            onChange={(e) => setTokenText(e.target.value)}
          />

          <div className="field-row">
            <label htmlFor="secret-input">
              {algStr && isRsaAlg(algStr) ? "Public key (PEM, SPKI)" : "HMAC secret"}
              <span className="label-hint"> — optional</span>
            </label>
          </div>
          <textarea
            id="secret-input"
            className="secret-textarea"
            placeholder={
              algStr && isRsaAlg(algStr)
                ? "-----BEGIN PUBLIC KEY-----…"
                : "Try the real signing secret, or leave blank to test known-weak secrets"
            }
            spellCheck={false}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
          />
          {secretStrength && (
            <p className={`secret-strength secret-strength-${secretStrength.score}`}>
              Secret strength: <strong>{secretStrength.label}</strong> — {secretStrength.reasons.join("; ")}
            </p>
          )}

          <VerifyStatusLine status={verifyStatus} algStr={algStr} />
        </section>

        <section className="claims-column" aria-label="Decoded token">
          {!decoded && !structuralError && (
            <div className="empty-state">
              <p>Paste a token, or load an example, to see its decoded claims and threat analysis here.</p>
            </div>
          )}
          {structuralError && (
            <div className="error-state" role="alert">
              <h2>Can't decode this token</h2>
              <p>{structuralError}</p>
            </div>
          )}
          {decoded && (
            <div className="json-grid">
              <JsonPanel title="Header" segment={decoded.header} />
              <JsonPanel title="Payload" segment={decoded.payload} />
            </div>
          )}
        </section>

        <section className="findings-column" aria-label="Threat model findings">
          <h2>Threat model</h2>
          {!decoded && !structuralError && <p className="empty-note">No token to analyze yet.</p>}
          {decoded && <FindingsList findings={findings} />}
        </section>
      </main>

      <footer className="app-footer">
        <p>
          Everything above runs entirely in your browser — no token, secret, or key is ever sent to a server.{" "}
          <a href="https://github.com/hellpuffyt/tokenpit" target="_blank" rel="noreferrer">
            Source
          </a>
        </p>
      </footer>
    </div>
  );
}

function VerifyStatusLine({ status, algStr }: { status: VerifyStatus; algStr: string | undefined }) {
  switch (status.kind) {
    case "none":
      return null;
    case "checking":
      return (
        <p className="verify-status verify-checking" role="status">
          Checking signature…
        </p>
      );
    case "verified":
      return (
        <p className="verify-status verify-ok" role="status">
          ✓ Signature verifies against the provided key.
        </p>
      );
    case "verified-weak":
      return (
        <p className="verify-status verify-critical" role="alert">
          ✗ Signature was forged using a known weak secret: "{status.secret}"
        </p>
      );
    case "invalid":
      return (
        <p className="verify-status verify-fail" role="alert">
          ✗ Signature does not match the provided key.
        </p>
      );
    case "unsupported-alg":
      return (
        <p className="verify-status verify-info" role="status">
          Signature verification for "{algStr}" isn't implemented in this workbench (HS256/384/512 and RS256/384/512
          are supported) — claim analysis below still applies.
        </p>
      );
  }
}

export default App;
