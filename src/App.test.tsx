import { describe, expect, it, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import { LIVE_EXAMPLES } from "./lib/liveExamples";
import { generateKeyPair, exportSPKI, SignJWT } from "jose";

beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});

describe("App", () => {
  it("shows the empty state when no token has been entered", () => {
    render(<App />);
    expect(screen.getByText(/paste a token, or load an example/i)).toBeInTheDocument();
  });

  it("shows a structural error state for an invalid token", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.type(screen.getByLabelText(/^jwt$/i), "not-a-jwt");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/can't decode this token/i);
  });

  it("decodes a pasted token and shows its header/payload claims", async () => {
    const user = userEvent.setup();
    render(<App />);
    const healthy = LIVE_EXAMPLES.find((e) => e.id === "healthy")!;
    const textarea = screen.getByLabelText(/^jwt$/i);
    await user.click(textarea);
    await user.paste(await healthy.build(new Date()));
    expect(await screen.findByText(/"alg": "HS256"/)).toBeInTheDocument();
    expect(screen.getByText(/"sub": "user_8f2c1"/)).toBeInTheDocument();
  });

  it("loading the alg-none example surfaces the critical alg-none finding", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.selectOptions(screen.getByLabelText(/load an example/i), "alg-none");
    const finding = await screen.findByTestId("finding-alg-none");
    expect(within(finding).getByText(/critical/i)).toBeInTheDocument();
  });

  it("loading the weak-secret example eventually reports the cracked secret", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.selectOptions(screen.getByLabelText(/load an example/i), "weak-secret");
    await waitFor(
      () => {
        expect(screen.getByText(/forged using a known weak secret/i)).toBeInTheDocument();
      },
      { timeout: 5000 },
    );
    expect(await screen.findByTestId("finding-hmac-secret-weak")).toBeInTheDocument();
  });

  it("loading the healthy example with its suggested secret verifies successfully", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.selectOptions(screen.getByLabelText(/load an example/i), "healthy");
    await waitFor(() => {
      expect(screen.getAllByText(/signature verifies against the provided key/i).length).toBeGreaterThan(0);
    });
  });

  it("shows a secret-strength readout once a secret is typed for an HMAC token", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.selectOptions(screen.getByLabelText(/load an example/i), "healthy");
    const secretBox = screen.getByLabelText(/hmac secret/i);
    await user.clear(secretBox);
    await user.type(secretBox, "x");
    expect(await screen.findByText(/secret strength:/i)).toBeInTheDocument();
  });

  it("toggles the theme and persists the choice to localStorage", async () => {
    const user = userEvent.setup();
    render(<App />);
    const toggle = screen.getByRole("button", { name: /toggle color theme/i });
    const initial = document.documentElement.dataset.theme;
    await user.click(toggle);
    expect(document.documentElement.dataset.theme).not.toBe(initial);
    expect(window.localStorage.getItem("tokenpit:theme")).toBe(document.documentElement.dataset.theme);
  });

  it("shows the empty findings note before any token is entered", () => {
    render(<App />);
    expect(screen.getByText(/no token to analyze yet/i)).toBeInTheDocument();
  });

  it("verifies an RS256 token against a pasted PEM public key", async () => {
    const user = userEvent.setup();
    const { publicKey, privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
    const jwt = await new SignJWT({ sub: "u1" }).setProtectedHeader({ alg: "RS256", typ: "JWT" }).sign(privateKey);
    const pem = await exportSPKI(publicKey);

    render(<App />);
    await user.click(screen.getByLabelText(/^jwt$/i));
    await user.paste(jwt);
    const keyBox = await screen.findByLabelText(/public key/i);
    await user.click(keyBox);
    await user.paste(pem);

    await waitFor(() => {
      expect(screen.getAllByText(/signature verifies against the provided key/i).length).toBeGreaterThan(0);
    });
  });

  it("reports an invalid RS256 signature for the wrong public key", async () => {
    const user = userEvent.setup();
    const { privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
    const { publicKey: wrongKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
    const jwt = await new SignJWT({ sub: "u1" }).setProtectedHeader({ alg: "RS256", typ: "JWT" }).sign(privateKey);
    const wrongPem = await exportSPKI(wrongKey);

    render(<App />);
    await user.click(screen.getByLabelText(/^jwt$/i));
    await user.paste(jwt);
    const keyBox = await screen.findByLabelText(/public key/i);
    await user.click(keyBox);
    await user.paste(wrongPem);

    expect(await screen.findByText(/does not match the provided key/i)).toBeInTheDocument();
  });

  it("reports invalid rather than crashing when the pasted PEM is garbage", async () => {
    const user = userEvent.setup();
    const { privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
    const jwt = await new SignJWT({ sub: "u1" }).setProtectedHeader({ alg: "RS256", typ: "JWT" }).sign(privateKey);

    render(<App />);
    await user.click(screen.getByLabelText(/^jwt$/i));
    await user.paste(jwt);
    const keyBox = await screen.findByLabelText(/public key/i);
    await user.click(keyBox);
    await user.paste("not a real PEM key");

    expect(await screen.findByText(/does not match the provided key/i)).toBeInTheDocument();
  });

  it("shows an unsupported-algorithm note for an ES256 token with no secret entered", async () => {
    const user = userEvent.setup();
    render(<App />);
    const header = { alg: "ES256", typ: "JWT" };
    const payload = { sub: "u1" };
    const b64 = (o: unknown) =>
      btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    await user.click(screen.getByLabelText(/^jwt$/i));
    await user.paste(`${b64(header)}.${b64(payload)}.sig`);
    expect(await screen.findByText(/isn't implemented in this workbench/i)).toBeInTheDocument();
  });

  it("does not attempt RSA verification when the key field is left blank", async () => {
    const user = userEvent.setup();
    const { privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
    const jwt = await new SignJWT({ sub: "u1" }).setProtectedHeader({ alg: "RS256", typ: "JWT" }).sign(privateKey);

    render(<App />);
    await user.click(screen.getByLabelText(/^jwt$/i));
    await user.paste(jwt);
    expect(await screen.findByText(/"sub": "u1"/)).toBeInTheDocument();
    expect(screen.queryByText(/signature verifies against/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/does not match the provided key/i)).not.toBeInTheDocument();
  });
});
