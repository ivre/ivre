import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { FilterBar } from "./FilterBar";

describe("fixed filter scope", () => {
  const fixedFilters = [{ type: "host", value: "192.0.2.42" }];

  it("shows the IP without a remove control and submits only editable filters", () => {
    const change = vi.fn();
    render(
      <FilterBar
        filters={[]}
        fixedFilters={fixedFilters}
        onFiltersChange={change}
      />,
    );
    expect(screen.getByTitle("Fixed IP scope")).toHaveTextContent(
      "host:192.0.2.42",
    );
    expect(
      screen.queryByRole("button", { name: "Remove filter host:192.0.2.42" }),
    ).not.toBeInTheDocument();
    const input = screen.getByRole("textbox", { name: "Filter query" });
    fireEvent.change(input, { target: { value: "sensor:east" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(change).toHaveBeenCalledWith([
      { type: "sensor", value: "east", neg: false },
    ]);
  });

  it("clears optional filters without offering to clear the fixed IP", () => {
    const change = vi.fn();
    render(
      <FilterBar
        filters={[{ type: "sensor", value: "east" }, { value: "tcp/443" }]}
        fixedFilters={fixedFilters}
        onFiltersChange={change}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Clear all" }));
    expect(change).toHaveBeenCalledWith([]);
    expect(screen.getByTitle("Fixed IP scope")).toBeInTheDocument();
  });
});
