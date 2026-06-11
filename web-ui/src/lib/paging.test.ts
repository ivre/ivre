import { describe, expect, it } from "vitest";

import { buildPagedQuery, computePagination } from "./paging";

describe("buildPagedQuery", () => {
  it("appends limit and omits skip on the first page", () => {
    expect(buildPagedQuery("country:FR", 50, 0)).toBe("country:FR limit:50");
  });

  it("appends both limit and skip past the first page", () => {
    expect(buildPagedQuery("country:FR", 50, 50)).toBe(
      "country:FR limit:50 skip:50",
    );
  });

  it("works with an empty query (no filters)", () => {
    expect(buildPagedQuery("", 50, 0)).toBe("limit:50");
    expect(buildPagedQuery("", 25, 75)).toBe("limit:25 skip:75");
  });

  it("never emits a skip:0 token", () => {
    expect(buildPagedQuery("port:open", 10, 0)).not.toContain("skip:");
  });
});

describe("computePagination", () => {
  it("computes exact bounds on the first page when the total is known", () => {
    expect(computePagination({ loaded: 50, limit: 50, skip: 0, total: 120 })).toEqual(
      {
        first: 1,
        last: 50,
        atStart: true,
        atEnd: false,
        lastSkip: 100,
      },
    );
  });

  it("is neither at the start nor at the end on a middle page", () => {
    expect(
      computePagination({ loaded: 50, limit: 50, skip: 50, total: 120 }),
    ).toEqual({
      first: 51,
      last: 100,
      atStart: false,
      atEnd: false,
      lastSkip: 100,
    });
  });

  it("detects the last page from the total", () => {
    expect(
      computePagination({ loaded: 20, limit: 50, skip: 100, total: 120 }),
    ).toEqual({
      first: 101,
      last: 120,
      atStart: false,
      atEnd: true,
      lastSkip: 100,
    });
  });

  it("places lastSkip on the final full page when the total is a multiple of the limit", () => {
    // total 100, limit 50 -> pages [0..49], [50..99]; last page starts at 50.
    const bounds = computePagination({
      loaded: 50,
      limit: 50,
      skip: 50,
      total: 100,
    });
    expect(bounds.lastSkip).toBe(50);
    expect(bounds.atEnd).toBe(true);
  });

  it("treats a full page as not-final when the total is unknown", () => {
    const bounds = computePagination({ loaded: 50, limit: 50, skip: 0 });
    expect(bounds.atEnd).toBe(false);
    // Last-page jump is disabled by the caller when lastSkip is 0
    // and the total is unknown.
    expect(bounds.lastSkip).toBe(0);
  });

  it("treats a short page as final when the total is unknown", () => {
    expect(computePagination({ loaded: 12, limit: 50, skip: 0 }).atEnd).toBe(
      true,
    );
  });

  it("treats an empty page as final regardless of the total source", () => {
    expect(computePagination({ loaded: 0, limit: 50, skip: 0 }).atEnd).toBe(
      true,
    );
    expect(
      computePagination({ loaded: 0, limit: 50, skip: 200, total: 120 }).atEnd,
    ).toBe(true);
  });

  it("keeps lastSkip at 0 for an empty result set", () => {
    expect(
      computePagination({ loaded: 0, limit: 50, skip: 0, total: 0 }).lastSkip,
    ).toBe(0);
  });
});
