#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { decodeToken, TokenFormatError } from "./lib/decode.js";
import { explainToken } from "./lib/rules.js";
import { isHmacAlg, verifyHmacSignature, crackWeakHmacSecret } from "./lib/verify.js";

interface CliOptions {
  token?: string;
  secret?: string;
  now?: number;
  help: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = { help: false };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    if (arg === "--secret") {
      const value = argv[++i];
      if (value !== undefined) opts.secret = value;
    } else if (arg === "--now") {
      const value = argv[++i];
      if (value !== undefined) opts.now = Number(value);
    } else if (arg === "--help" || arg === "-h") {
      opts.help = true;
    } else if (arg !== "") {
      rest.push(arg);
    }
  }
  const first = rest[0];
  if (first !== undefined) opts.token = first;
  return opts;
}

const HELP = `tokenpit - decode, verify and explain a JWT's threat model

Usage:
  tokenpit <token> [--secret <hmac-secret>] [--now <unix-seconds>]
  tokenpit --help

Prints JSON: { header, payload, signatureVerified, findings }.
Exit code is 1 if any "critical" or "high" severity finding is present,
0 otherwise (0 also for informational-only or no findings).
`;

export async function run(argv: string[], stdout: (s: string) => void): Promise<number> {
  const opts = parseArgs(argv);
  if (opts.help || !opts.token) {
    stdout(HELP);
    return opts.help ? 0 : 1;
  }

  let decoded;
  try {
    decoded = decodeToken(opts.token);
  } catch (err) {
    const message = err instanceof TokenFormatError ? err.message : String(err);
    stdout(JSON.stringify({ error: message }, null, 2));
    return 1;
  }

  let signatureVerified: boolean | undefined;
  let crackedSecret: string | null | undefined;

  const alg = decoded.header.json?.["alg"];
  if (typeof alg === "string" && isHmacAlg(alg)) {
    if (opts.secret !== undefined) {
      signatureVerified = await verifyHmacSignature(decoded, alg, opts.secret);
    } else {
      crackedSecret = await crackWeakHmacSecret(decoded, alg);
      if (crackedSecret) signatureVerified = true;
    }
  }

  const explainCtx: Parameters<typeof explainToken>[1] = {};
  if (opts.now !== undefined && !Number.isNaN(opts.now)) explainCtx.now = new Date(opts.now * 1000);
  if (signatureVerified !== undefined) explainCtx.signatureVerified = signatureVerified;
  if (crackedSecret !== undefined) explainCtx.crackedSecret = crackedSecret;
  const findings = explainToken(decoded, explainCtx);

  const result = {
    header: decoded.header.json ?? null,
    payload: decoded.payload.json ?? null,
    signatureVerified: signatureVerified ?? null,
    findings: findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      title: f.title,
    })),
  };

  stdout(JSON.stringify(result, null, 2));

  const hasSevere = findings.some((f) => f.severity === "critical" || f.severity === "high");
  return hasSevere ? 1 : 0;
}

/* c8 ignore start -- exercised via the built CLI in CI's dogfood job, not unit tests */
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void run(process.argv.slice(2), (s) => console.log(s)).then((code) => {
    process.exitCode = code;
  });
}
/* c8 ignore stop */
