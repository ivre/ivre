import { describe, expect, it } from "vitest";

import {
  hostRecordId,
  hostReportUrl,
  hostResultsUrl,
  readHostNavigation,
} from "./host-report";

describe("host report links and record identity", () => {
  it("uses opaque API identifiers without deriving identity from content", () => {
    expect(hostRecordId({ addr: "192.0.2.42", _id: "9007199254740993" })).toBe(
      "9007199254740993",
    );
    expect(
      hostRecordId({
        addr: "192.0.2.42",
        _id: "opaque/value?x=1",
        source: "old",
      }),
    ).toBe("opaque/value?x=1");
    expect(
      hostRecordId({
        addr: "192.0.2.42",
        _id: "opaque/value?x=1",
        source: "new",
      }),
    ).toBe("opaque/value?x=1");
    expect(hostRecordId({ addr: "192.0.2.42" })).toBeUndefined();
    expect(hostRecordId({ addr: "192.0.2.42", _id: "" })).toBeUndefined();
  });

  it("encodes IPv6 and preserves the original result query", () => {
    const params = new URLSearchParams({
      q: "service:https",
      skip: "20",
      limit: "10",
    });
    expect(hostReportUrl("view", "2001:db8::42", params)).toBe(
      "/view/host/2001%3Adb8%3A%3A42?q=service%3Ahttps&skip=20&limit=10",
    );
    params.set("tab", "passive");
    params.set("passivePort", "443");
    params.set("record", "example");
    params.set("section", "port-tcp-443");
    expect(hostResultsUrl("view", params)).toBe(
      "/view?q=service%3Ahttps&skip=20&limit=10",
    );
    expect(params.get("tab")).toBe("passive");
  });

  it("accepts only internal result-list navigation contexts", () => {
    expect(
      readHostNavigation({
        hostNavigation: {
          returnTo: "https://example.org/",
          returnScrollY: 0,
          entries: [],
        },
      }),
    ).toBeUndefined();
    expect(
      readHostNavigation({
        hostNavigation: {
          returnTo: "//example.org",
          returnScrollY: 0,
          entries: [],
        },
      }),
    ).toBeUndefined();
    expect(
      readHostNavigation({
        hostNavigation: {
          returnTo: "/view/host/a",
          returnScrollY: 0,
          entries: [],
        },
      }),
    ).toBeUndefined();
    expect(
      readHostNavigation({
        hostNavigation: {
          returnTo: "/view?q=ssh",
          returnScrollY: -10,
          entries: [],
        },
      }),
    ).toBeUndefined();
    expect(
      readHostNavigation({
        hostNavigation: {
          returnTo: "/view?q=ssh",
          returnScrollY: 100,
          entries: [{ addr: "192.0.2.42" }, null, {}],
        },
      })?.entries,
    ).toEqual([{ addr: "192.0.2.42" }]);
  });
});
