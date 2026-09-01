import "@testing-library/jest-dom/vitest";
import { webcrypto } from "node:crypto";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// `test.globals` is off (deliberately — see vitest.config.ts), so
// testing-library's automatic afterEach cleanup never registers itself;
// do it explicitly so each component test starts from an empty DOM.
afterEach(() => {
  cleanup();
});

// jsdom doesn't implement SubtleCrypto; Node's WebCrypto implementation is
// a drop-in for the parts of it this app uses (importKey/sign/verify).
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}

// jsdom doesn't implement matchMedia; provide a default "no preference"
// stub so components can call it, and so tests can vi.spyOn() over it.
if (!window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList;
}
