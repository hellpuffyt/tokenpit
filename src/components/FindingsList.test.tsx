import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingsList } from "./FindingsList";

describe("FindingsList", () => {
  it("shows a no-findings note for an empty list", () => {
    render(<FindingsList findings={[]} />);
    expect(screen.getByText(/no findings for this token/i)).toBeInTheDocument();
  });

  it("pluralizes the singular case correctly", () => {
    render(
      <FindingsList
        findings={[
          { id: "x", severity: "low", title: "T", detail: "D", recommendation: "R" },
        ]}
      />,
    );
    expect(screen.getByText(/1 finding, none critical or high\./i)).toBeInTheDocument();
  });
});
