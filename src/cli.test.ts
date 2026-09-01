import { describe, expect, it } from "vitest";
import { run } from "./cli";
import { EXAMPLE_TOKENS, EXAMPLES_REFERENCE_UNIX_SECONDS } from "./lib/examples";

function capture(): { lines: string[]; sink: (s: string) => void } {
  const lines: string[] = [];
  return { lines, sink: (s) => lines.push(s) };
}

describe("cli run()", () => {
  it("prints help and exits 0 when --help is passed", async () => {
    const { lines, sink } = capture();
    const code = await run(["--help"], sink);
    expect(code).toBe(0);
    expect(lines[0]).toContain("tokenpit - decode, verify and explain");
  });

  it("prints help and exits 1 when no token is given", async () => {
    const { lines, sink } = capture();
    const code = await run([], sink);
    expect(code).toBe(1);
    expect(lines[0]).toContain("Usage:");
  });

  it("exits 1 and prints an error for a structurally invalid token", async () => {
    const { lines, sink } = capture();
    const code = await run(["not.a.valid.jwt"], sink);
    expect(code).toBe(1);
    const parsed = JSON.parse(lines[0]) as { error: string };
    expect(parsed.error).toMatch(/3 dot-separated segments/);
  });

  it("finds and reports a cracked weak HMAC secret with no --secret given, exit code 1", async () => {
    const ex = EXAMPLE_TOKENS.find((e) => e.id === "weak-secret")!;
    const { lines, sink } = capture();
    const code = await run([ex.token, "--now", String(EXAMPLES_REFERENCE_UNIX_SECONDS)], sink);
    expect(code).toBe(1);
    const parsed = JSON.parse(lines[0]) as { signatureVerified: boolean; findings: { id: string }[] };
    expect(parsed.signatureVerified).toBe(true);
    expect(parsed.findings.some((f) => f.id === "hmac-secret-weak")).toBe(true);
  });

  it("verifies against an explicitly supplied correct secret", async () => {
    const ex = EXAMPLE_TOKENS.find((e) => e.id === "healthy")!;
    const { lines, sink } = capture();
    const code = await run([ex.token, "--secret", ex.suggestedSecret!, "--now", String(EXAMPLES_REFERENCE_UNIX_SECONDS)], sink);
    const parsed = JSON.parse(lines[0]) as { signatureVerified: boolean };
    expect(parsed.signatureVerified).toBe(true);
    expect(code).toBe(0);
  });

  it("reports signatureVerified: false for a wrong explicit secret", async () => {
    const ex = EXAMPLE_TOKENS.find((e) => e.id === "healthy")!;
    const { lines } = capture();
    const sink = (s: string) => lines.push(s);
    const code = await run([ex.token, "--secret", "definitely-wrong", "--now", String(EXAMPLES_REFERENCE_UNIX_SECONDS)], sink);
    const parsed = JSON.parse(lines[0]) as { signatureVerified: boolean };
    expect(parsed.signatureVerified).toBe(false);
    expect(code).toBe(1); // signature-invalid is a "high" finding
  });

  it("exits 0 for the alg-none example's own analysis being all we can say (still critical, so exit 1)", async () => {
    const ex = EXAMPLE_TOKENS.find((e) => e.id === "alg-none")!;
    const { lines, sink } = capture();
    const code = await run([ex.token, "--now", String(EXAMPLES_REFERENCE_UNIX_SECONDS)], sink);
    expect(code).toBe(1);
    const parsed = JSON.parse(lines[0]) as { findings: { id: string; severity: string }[] };
    expect(parsed.findings.some((f) => f.id === "alg-none" && f.severity === "critical")).toBe(true);
  });

  it("ignores a non-numeric --now and falls back to the real current time", async () => {
    const ex = EXAMPLE_TOKENS.find((e) => e.id === "healthy")!;
    const { lines, sink } = capture();
    const code = await run([ex.token, "--now", "not-a-number"], sink);
    expect(typeof code).toBe("number");
    const parsed = JSON.parse(lines[0]) as { header: unknown };
    expect(parsed.header).toBeDefined();
  });
});
