import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import App from "./App";

describe("App", () => {
  it("renders the workspace heading", () => {
    render(<App />);
    expect(
      screen.getByRole("heading", { name: /IVRE web-ui workspace/i }),
    ).toBeInTheDocument();
  });

  it("renders the placeholder Ping button", () => {
    render(<App />);
    expect(screen.getByTestId("ping")).toHaveTextContent("Ping");
  });
});
