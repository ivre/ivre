import { describe, expect, it } from "vitest";

import {
  cloneReportElements,
  DEFAULT_REPORT_ELEMENTS,
  swapReportElements,
} from "@/lib/report-elements";

describe("report-elements", () => {
  it("clones default elements", () => {
    const copy = cloneReportElements(DEFAULT_REPORT_ELEMENTS);
    expect(copy).toHaveLength(3);
    expect(copy[0].parameters).toBe("country");
    copy[0].text = "changed";
    expect(DEFAULT_REPORT_ELEMENTS[0].text).toBe("Top countries");
  });

  it("swaps elements by index", () => {
    const base = cloneReportElements(DEFAULT_REPORT_ELEMENTS);
    const swapped = swapReportElements(base, 0, 2);
    expect(swapped[0].parameters).toBe("as");
    expect(swapped[2].parameters).toBe("country");
  });

  it("ignores out-of-range swap", () => {
    const base = cloneReportElements(DEFAULT_REPORT_ELEMENTS);
    expect(swapReportElements(base, -1, 0)).toBe(base);
    expect(swapReportElements(base, 0, 99)).toBe(base);
  });
});
