import { describe, expect, it } from "vitest";

import {
  buildHighlightMap,
  buildQueryFromFilters,
  parseFiltersFromQuery,
  quoteValue,
  renderFilter,
  type Filter,
} from "./filter";

describe("quoteValue", () => {
  it("returns plain values unchanged", () => {
    expect(quoteValue("FR")).toBe("FR");
    expect(quoteValue("tcp/443")).toBe("tcp/443");
    expect(quoteValue("1.2.3.4")).toBe("1.2.3.4");
  });

  it("quotes values containing whitespace", () => {
    expect(quoteValue("Hello World")).toBe('"Hello World"');
  });

  it("quotes values containing colons", () => {
    expect(quoteValue("CDN:Cloudflare")).toBe('"CDN:Cloudflare"');
  });

  it("escapes embedded double quotes", () => {
    expect(quoteValue('say "hi"')).toBe('"say \\"hi\\""');
  });
});

describe("renderFilter", () => {
  it("renders a typed filter", () => {
    expect(renderFilter({ type: "country", value: "FR" })).toBe("country:FR");
  });

  it("renders an anonymous filter as a bare token", () => {
    expect(renderFilter({ value: "tcp/443" })).toBe("tcp/443");
  });

  it("quotes values that need it", () => {
    expect(renderFilter({ type: "tag", value: "CDN:Cloudflare" })).toBe(
      'tag:"CDN:Cloudflare"',
    );
  });

  it("prefixes negation with !", () => {
    expect(renderFilter({ type: "country", value: "FR", neg: true })).toBe(
      "!country:FR",
    );
  });
});

describe("buildQueryFromFilters", () => {
  it("space-joins multiple filters", () => {
    const filters: Filter[] = [
      { type: "country", value: "FR" },
      { type: "port", value: "tcp/443" },
      { type: "tag", value: "CDN:Cloudflare" },
    ];
    expect(buildQueryFromFilters(filters)).toBe(
      'country:FR port:tcp/443 tag:"CDN:Cloudflare"',
    );
  });

  it("returns the empty string for no filters", () => {
    expect(buildQueryFromFilters([])).toBe("");
  });
});

describe("parseFiltersFromQuery", () => {
  it("parses the empty string", () => {
    expect(parseFiltersFromQuery("")).toEqual([]);
  });

  it("parses a single typed filter", () => {
    expect(parseFiltersFromQuery("country:FR")).toEqual([
      { type: "country", value: "FR", neg: false },
    ]);
  });

  it("parses an anonymous filter", () => {
    expect(parseFiltersFromQuery("tcp/443")).toEqual([
      { value: "tcp/443", neg: false },
    ]);
  });

  it("parses negation", () => {
    expect(parseFiltersFromQuery("!country:FR")).toEqual([
      { type: "country", value: "FR", neg: true },
    ]);
    expect(parseFiltersFromQuery("-port:tcp/22")).toEqual([
      { type: "port", value: "tcp/22", neg: true },
    ]);
  });

  it("parses quoted values with embedded colons", () => {
    expect(parseFiltersFromQuery('tag:"CDN:Cloudflare"')).toEqual([
      { type: "tag", value: "CDN:Cloudflare", neg: false },
    ]);
  });

  it("parses quoted values with embedded whitespace", () => {
    expect(parseFiltersFromQuery('city:"San Francisco"')).toEqual([
      { type: "city", value: "San Francisco", neg: false },
    ]);
  });

  it("parses backslash-escaped quotes inside a quoted value", () => {
    expect(parseFiltersFromQuery('banner:"say \\"hi\\""')).toEqual([
      { type: "banner", value: 'say "hi"', neg: false },
    ]);
  });

  it("parses multiple mixed filters", () => {
    expect(
      parseFiltersFromQuery('country:FR port:tcp/443 !tag:"CDN:Cloudflare"'),
    ).toEqual([
      { type: "country", value: "FR", neg: false },
      { type: "port", value: "tcp/443", neg: false },
      { type: "tag", value: "CDN:Cloudflare", neg: true },
    ]);
  });

  it("collapses runs of whitespace", () => {
    expect(parseFiltersFromQuery("  country:FR    port:tcp/443  ")).toEqual([
      { type: "country", value: "FR", neg: false },
      { type: "port", value: "tcp/443", neg: false },
    ]);
  });
});

describe("buildHighlightMap", () => {
  it("indexes typed filters by type, lowercased", () => {
    const map = buildHighlightMap([
      { type: "country", value: "FR" },
      { type: "country", value: "BE" },
      { type: "port", value: "tcp/443" },
    ]);
    expect(map.get("country")).toEqual(new Set(["fr", "be"]));
    expect(map.get("port")).toEqual(new Set(["tcp/443"]));
  });

  it("ignores anonymous filters", () => {
    const map = buildHighlightMap([{ value: "tcp/443" }]);
    expect(map.size).toBe(0);
  });

  it("ignores negated filters", () => {
    const map = buildHighlightMap([
      { type: "country", value: "FR", neg: true },
    ]);
    expect(map.size).toBe(0);
  });

  it("ignores unknown types", () => {
    const map = buildHighlightMap([{ type: "totally-made-up", value: "x" }]);
    expect(map.size).toBe(0);
  });
});

describe("round-trip", () => {
  it("parse then build is the identity for typical queries", () => {
    const queries = [
      "country:FR",
      "country:FR port:tcp/443",
      'tag:"CDN:Cloudflare"',
      '!country:FR port:tcp/443 tag:"CDN:Cloudflare"',
      "tcp/443 1.2.3.4/24",
    ];
    for (const q of queries) {
      const filters = parseFiltersFromQuery(q);
      expect(buildQueryFromFilters(filters)).toBe(q);
    }
  });
});
