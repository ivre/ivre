/* @vitest-environment jsdom */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { HostCard } from "./HostCard";

import type { HostRecord } from "@/lib/api";
import { createFilter } from "@/lib/field-mapper";
import { buildHighlightMap } from "@/lib/filter";

const HOST: HostRecord = {
  addr: "192.0.2.1",
  ports: [
    {
      protocol: "tcp",
      port: 80,
      state_state: "open",
      service_name: "http",
      service_product: "nginx",
    },
    {
      protocol: "tcp",
      port: 443,
      state_state: "open",
      service_name: "http",
      service_product: "Apache httpd",
    },
    {
      protocol: "tcp",
      port: 8080,
      state_state: "open",
      service_name: "http-proxy",
      service_product: "nginx",
    },
    {
      protocol: "tcp",
      port: 22,
      state_state: "open",
      service_name: "ssh",
      service_product: "OpenSSH",
    },
  ],
};

describe("HostCard — product highlights", () => {
  it("highlights matching service and product ports after a product facet click", () => {
    const filter = createFilter("product", ["http", "nginx"]);
    if (!filter) throw new Error("Expected a product filter");
    render(<HostCard host={HOST} highlights={buildHighlightMap([filter])} />);

    for (const token of ["tcp/80", "tcp/443", "tcp/8080"]) {
      expect(screen.getByText(token)).toHaveClass("ring-2");
    }
    expect(screen.getByText("tcp/22")).not.toHaveClass("ring-2");
  });

  it("does not highlight ports for a negated product filter", () => {
    render(
      <HostCard
        host={HOST}
        highlights={buildHighlightMap([
          { type: "product", value: "http:nginx", neg: true },
        ])}
      />,
    );

    for (const token of ["tcp/80", "tcp/443", "tcp/8080", "tcp/22"]) {
      expect(screen.getByText(token)).not.toHaveClass("ring-2");
    }
  });
});
