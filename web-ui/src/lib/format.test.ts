import { describe, expect, it } from "vitest";

import {
  formatPort,
  formatResultsCount,
  formatServices,
  formatTimestamp,
  getCountryFlag,
  getPortColor,
  getTagColor,
  sortTagsByImportance,
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

describe("sortTagsByImportance", () => {
  it("orders error > warning > success > info > default/unknown", () => {
    const input = [
      { value: "a", type: "info" },
      { value: "b", type: "default" },
      { value: "c", type: "error" },
      { value: "d", type: "success" },
      { value: "e" }, // missing type → default rank
      { value: "f", type: "warning" },
    ];
    expect(sortTagsByImportance(input).map((t) => t.value)).toEqual([
      "c", // error
      "f", // warning
      "d", // success
      "a", // info
      "b", // default (string "default" is not a known rank → default bucket)
      "e", // missing type
    ]);
  });

  it("is stable within a rank bucket (preserves server order)", () => {
    const input = [
      { value: "x1" },
      { value: "x2" },
      { value: "x3", type: "info" },
      { value: "x4" },
      { value: "x5", type: "info" },
    ];
    expect(sortTagsByImportance(input).map((t) => t.value)).toEqual([
      "x3",
      "x5",
      "x1",
      "x2",
      "x4",
    ]);
  });

  it("does not mutate the input array", () => {
    const input = [
      { value: "a" },
      { value: "b", type: "error" },
    ];
    const before = [...input];
    sortTagsByImportance(input);
    expect(input).toEqual(before);
  });

  it("returns an empty array for empty input", () => {
    expect(sortTagsByImportance([])).toEqual([]);
  });

  it("pulls highlighted tags ahead of every non-highlighted tag", () => {
    // Highlighted info should still beat non-highlighted error
    // because the highlight key dominates the type key.
    const input = [
      { value: "a", type: "error" },
      { value: "b", type: "info" },
      { value: "c", type: "warning" },
    ];
    const highlighted = new Set(["b"]);
    expect(
      sortTagsByImportance(input, (t) => highlighted.has(t.value)).map(
        (t) => t.value,
      ),
    ).toEqual(["b", "a", "c"]);
  });

  it("ranks highlighted tags among themselves by importance", () => {
    const input = [
      { value: "h-info", type: "info" },
      { value: "h-default" },
      { value: "h-error", type: "error" },
      { value: "h-warning", type: "warning" },
      { value: "h-success", type: "success" },
      { value: "plain", type: "error" },
    ];
    const highlighted = new Set([
      "h-info",
      "h-default",
      "h-error",
      "h-warning",
      "h-success",
    ]);
    expect(
      sortTagsByImportance(input, (t) => highlighted.has(t.value)).map(
        (t) => t.value,
      ),
    ).toEqual([
      "h-error",
      "h-warning",
      "h-success",
      "h-info",
      "h-default",
      "plain",
    ]);
  });

  it("is stable within the highlighted same-type bucket", () => {
    const input = [
      { value: "n1", type: "info" },
      { value: "h1", type: "info" },
      { value: "h2", type: "info" },
      { value: "n2", type: "info" },
      { value: "h3", type: "info" },
    ];
    const highlighted = new Set(["h1", "h2", "h3"]);
    expect(
      sortTagsByImportance(input, (t) => highlighted.has(t.value)).map(
        (t) => t.value,
      ),
    ).toEqual(["h1", "h2", "h3", "n1", "n2"]);
  });

  it("treats an always-false predicate as no predicate at all", () => {
    const input = [
      { value: "a", type: "info" },
      { value: "b", type: "error" },
      { value: "c" },
    ];
    expect(
      sortTagsByImportance(input, () => false).map((t) => t.value),
    ).toEqual(sortTagsByImportance(input).map((t) => t.value));
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

describe("formatResultsCount", () => {
  it("renders ``loaded/total`` when the page is a partial slice", () => {
    expect(formatResultsCount(10, 45643)).toBe("10/45643");
  });

  it("drops the redundant ``/total`` suffix when the page holds every match", () => {
    expect(formatResultsCount(7, 7)).toBe("7");
  });

  it("falls back to the bare loaded count while the total is unknown", () => {
    // ``total`` stays ``undefined`` while the /count query is
    // pending, errored, or for sections whose backend exposes no
    // ``/count`` companion (DNS, Flow).
    expect(formatResultsCount(10, undefined)).toBe("10");
  });

  it("clamps a stale total that lags the page (never renders ``11/10``)", () => {
    // Background mutations can transiently leave the cached total
    // below the freshly-loaded page size; prefer the bare loaded
    // count over a self-contradictory ``11/10``.
    expect(formatResultsCount(11, 10)).toBe("11");
  });

  it("renders the zero-match case as a bare ``0``", () => {
    expect(formatResultsCount(0, 0)).toBe("0");
    expect(formatResultsCount(0, undefined)).toBe("0");
  });
});
