import { describe, expect, it } from "vitest";

import { hostEvidenceFilters, hostEvidenceQuery } from "./host-evidence";
import { hostResultsUrl } from "./host-report";

describe("IP-scoped evidence queries", () => {
  it("does not inherit the originating search or pagination", () => {
    const params = new URLSearchParams({
      q: "country:FR",
      skip: "900",
      activeQ: "source:lab skip:40 limit:1000",
      passiveQ: "sensor:east",
    });
    expect(
      hostEvidenceQuery("192.0.2.42", hostEvidenceFilters(params, "active")),
    ).toBe("host:192.0.2.42 source:lab");
    expect(
      hostEvidenceQuery("192.0.2.42", hostEvidenceFilters(params, "passive")),
    ).toBe("host:192.0.2.42 sensor:east");
    expect(hostResultsUrl("view", params)).toBe(
      "/view?q=country%3AFR&skip=900",
    );
  });

  it("retains compatibility with previous port/type/sensor links", () => {
    const params = new URLSearchParams({
      section: "port-udp-53",
      passivePort: "443",
      passiveType: "SSL_SERVER",
      passiveSensor: "east",
    });
    expect(
      hostEvidenceQuery("192.0.2.42", hostEvidenceFilters(params, "active")),
    ).toBe("host:192.0.2.42 udp/53");
    expect(
      hostEvidenceQuery("192.0.2.42", hostEvidenceFilters(params, "passive")),
    ).toBe("host:192.0.2.42 tcp/443 recontype:SSL_SERVER sensor:east");
  });

  it("prefers explicit source queries, including an explicitly cleared query", () => {
    const params = new URLSearchParams({
      passiveQ: "",
      passivePort: "443",
      activeQ: "source:new",
      section: "port-tcp-22",
    });
    expect(hostEvidenceFilters(params, "passive")).toEqual([]);
    expect(hostEvidenceFilters(params, "active")).toEqual([
      { type: "source", value: "new", neg: false },
    ]);
  });

  it("keeps the fixed IP even when another address is added as a filter", () => {
    expect(
      hostEvidenceQuery("2001:db8::42", [
        { type: "host", value: "192.0.2.99" },
      ]),
    ).toBe('host:"2001:db8::42" host:192.0.2.99');
  });

  it("does not turn an older individual-scan anchor into a port filter", () => {
    const params = new URLSearchParams({
      record: "snapshot",
      section: "port-tcp-443",
    });
    expect(hostEvidenceFilters(params, "active")).toEqual([]);
  });
});
