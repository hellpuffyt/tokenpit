import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { JsonPanel } from "./JsonPanel";

describe("JsonPanel", () => {
  it("renders a placeholder when there's no segment at all", () => {
    render(<JsonPanel title="Header" segment={undefined} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("renders pretty-printed JSON when the segment parsed successfully", () => {
    render(<JsonPanel title="Header" segment={{ raw: "x", json: { alg: "HS256" } }} />);
    expect(screen.getByText(/"alg": "HS256"/)).toBeInTheDocument();
  });

  it("renders the parse error when the segment failed to decode", () => {
    render(<JsonPanel title="Header" segment={{ raw: "x", json: undefined, error: "boom" }} />);
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
  });
});
