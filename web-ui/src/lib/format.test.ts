import { describe, expect, it } from "vitest";

import {
  formatPort,
  formatServices,
  formatTimestamp,
  getCountryFlag,
  getPortColor,
  getTagColor,
} from "./format";

describe("getCountryFlag", () => {
  it("maps a valid 2-letter code to a regional-indicator pair", () => {
    expect(getCountryFlag("FR")).toBe("\u{1F1EB}\u{1F1F7}");
    expect(getCountryFlag("us")).toBe("\u{1F1FA}\u{1F1F8}");
  });

  it("returns empty string for invalid input", () => {
    expect(getCountryFlag("")).toBe("");
    expect(getCountryFlag(undefined)).toBe("");
    expect(getCountryFlag("FRA")).toBe("");
    expect(getCountryFlag("1A")).toBe("");
  });
});

describe("getTagColor", () => {
  it("returns a known palette for known types", () => {
    expect(getTagColor("info")).toContain("blue");
    expect(getTagColor("warning")).toContain("yellow");
    expect(getTagColor("error")).toContain("red");
    expect(getTagColor("success")).toContain("green");
  });

  it("falls back to default palette for unknown types", () => {
    expect(getTagColor(undefined)).toContain("purple");
    expect(getTagColor("nonsense")).toContain("purple");
  });
});

describe("getPortColor", () => {
  it("maps state to colour family", () => {
    expect(getPortColor("open")).toContain("green");
    expect(getPortColor("closed")).toContain("red");
    expect(getPortColor("filtered")).toContain("orange");
    expect(getPortColor("open|filtered")).toContain("orange");
    expect(getPortColor(undefined)).toContain("gray");
  });
});

describe("formatServices", () => {
  it("returns a deduped, comma-joined preview", () => {
    expect(
      formatServices([
        { state_state: "open", service_name: "http" },
        { state_state: "open", service_name: "http" },
        { state_state: "open", service_name: "ssh" },
      ]),
    ).toBe("http, ssh");
  });

  it("includes product and version when present", () => {
    expect(
      formatServices([
        {
          state_state: "open",
          service_name: "http",
          service_product: "nginx",
          service_version: "1.18",
        },
      ]),
    ).toBe("http (nginx 1.18)");
  });

  it("ignores closed ports", () => {
    expect(
      formatServices([
        { state_state: "open", service_name: "http" },
        { state_state: "closed", service_name: "ftp" },
      ]),
    ).toBe("http");
  });
});

describe("formatPort", () => {
  it("renders proto/port", () => {
    expect(formatPort({ protocol: "tcp", port: 443 })).toBe("tcp/443");
  });

  it("returns empty string on missing fields", () => {
    expect(formatPort({ protocol: "tcp" })).toBe("");
    expect(formatPort({ port: 443 })).toBe("");
    expect(formatPort({})).toBe("");
  });
});

describe("formatTimestamp", () => {
  it("formats ISO strings", () => {
    expect(formatTimestamp("2025-01-02T03:04:05Z")).toBe("2025-01-02 03:04:05Z");
  });

  it("formats seconds-since-epoch numbers", () => {
    // Wed 11 Sep 2024 14:37:43 UTC
    expect(formatTimestamp(1726065463)).toBe("2024-09-11 14:37:43Z");
  });

  it("returns empty string on invalid input", () => {
    expect(formatTimestamp(undefined)).toBe("");
    expect(formatTimestamp("not a date")).toBe("");
  });
});
