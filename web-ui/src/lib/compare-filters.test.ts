import { describe, expect, it } from "vitest";

import {
  applyCompareToSearchParams,
  deriveCompareQueries,
  parseCompareFromSearchParams,
} from "@/lib/compare-filters";

describe("compare-filters", () => {
  it("derives set queries from common + per-set filters", () => {
    const queries = deriveCompareQueries({
      common: [{ type: "country", value: "FR" }],
      set1: [{ type: "port", value: "tcp/80" }],
      set2: [{ type: "port", value: "tcp/443" }],
    });
    expect(queries.commonQ).toBe("country:FR");
    expect(queries.set1Q).toBe("country:FR port:tcp/80");
    expect(queries.set2Q).toBe("country:FR port:tcp/443");
    expect(queries.allSetsQ).toBe(
      "country:FR port:tcp/80 country:FR port:tcp/443",
    );
  });

  it("round-trips URL search params", () => {
    const params = new URLSearchParams();
    applyCompareToSearchParams(
      {
        common: [{ type: "country", value: "FR" }],
        set1: [{ value: "1.2.3.4" }],
        set2: [],
      },
      params,
    );
    expect(params.get("q")).toBe("country:FR");
    expect(params.get("set1")).toBe("1.2.3.4");
    expect(params.get("set2")).toBeNull();

    const parsed = parseCompareFromSearchParams(params);
    expect(parsed.common[0]).toMatchObject({ type: "country", value: "FR" });
    expect(parsed.set1[0]?.value).toBe("1.2.3.4");
    expect(parsed.set2).toEqual([]);
  });

  it("strips pagination meta-tokens from all filter keys", () => {
    const params = new URLSearchParams({
      q: "country:FR skip:50",
      set1: "port:tcp/80 limit:10",
      set2: "skip:0",
    });
    const parsed = parseCompareFromSearchParams(params);
    expect(parsed.common).toEqual([
      { type: "country", value: "FR", neg: false },
    ]);
    expect(parsed.set1).toEqual([
      { type: "port", value: "tcp/80", neg: false },
    ]);
    expect(parsed.set2).toEqual([]);
  });
});
