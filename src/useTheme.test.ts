import { describe, expect, it, beforeEach, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { useTheme } from "./useTheme";

beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});

describe("useTheme", () => {
  it("defaults to light when there's no stored theme and the OS doesn't prefer dark", () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({ matches: false } as MediaQueryList);
    const { result } = renderHook(() => useTheme());
    expect(result.current[0]).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("defaults to dark when the OS prefers dark and nothing is stored", () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({ matches: true } as MediaQueryList);
    const { result } = renderHook(() => useTheme());
    expect(result.current[0]).toBe("dark");
  });

  it("reads a previously stored theme over the OS preference", () => {
    window.localStorage.setItem("tokenpit:theme", "dark");
    vi.spyOn(window, "matchMedia").mockReturnValue({ matches: false } as MediaQueryList);
    const { result } = renderHook(() => useTheme());
    expect(result.current[0]).toBe("dark");
  });

  it("ignores a garbage stored value", () => {
    window.localStorage.setItem("tokenpit:theme", "purple");
    vi.spyOn(window, "matchMedia").mockReturnValue({ matches: false } as MediaQueryList);
    const { result } = renderHook(() => useTheme());
    expect(result.current[0]).toBe("light");
  });

  it("toggle() flips the theme and persists it", () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({ matches: false } as MediaQueryList);
    const { result } = renderHook(() => useTheme());
    act(() => result.current[1]());
    expect(result.current[0]).toBe("dark");
    expect(window.localStorage.getItem("tokenpit:theme")).toBe("dark");
    act(() => result.current[1]());
    expect(result.current[0]).toBe("light");
  });

  it("falls back to OS preference when localStorage.getItem throws", () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({ matches: true } as MediaQueryList);
    const spy = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const { result } = renderHook(() => useTheme());
    expect(result.current[0]).toBe("dark");
    spy.mockRestore();
  });

  it("does not throw when localStorage.setItem fails", () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({ matches: false } as MediaQueryList);
    const spy = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("quota exceeded");
    });
    const { result } = renderHook(() => useTheme());
    expect(() => act(() => result.current[1]())).not.toThrow();
    spy.mockRestore();
  });
});
