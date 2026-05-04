import { describe, expect, it } from "vitest";

import { rangeToCidr } from "./rir";

describe("rangeToCidr (inet[6]num collapse)", () => {
  it("collapses a /24 to its CIDR form", () => {
    expect(rangeToCidr("192.0.2.0", "192.0.2.255")).toBe("192.0.2.0/24");
  });

  it("collapses a single /32 to its CIDR form", () => {
    expect(rangeToCidr("192.0.2.42", "192.0.2.42")).toBe("192.0.2.42/32");
  });

  it("collapses the /0 IPv4 wildcard", () => {
    expect(rangeToCidr("0.0.0.0", "255.255.255.255")).toBe("0.0.0.0/0");
  });

  it("returns null for a non-power-of-2 range", () => {
    // 192.0.2.0 — 192.0.2.10 (11 addresses).
    expect(rangeToCidr("192.0.2.0", "192.0.2.10")).toBeNull();
  });

  it("returns null when start is misaligned", () => {
    // 192.0.2.1 — 192.0.2.4 (4 addresses, but 192.0.2.1 is not /30-aligned).
    expect(rangeToCidr("192.0.2.1", "192.0.2.4")).toBeNull();
  });

  it("returns null when stop precedes start", () => {
    expect(rangeToCidr("192.0.2.10", "192.0.2.0")).toBeNull();
  });

  it("collapses an IPv6 /48 to its CIDR form", () => {
    expect(
      rangeToCidr("2001:db8::", "2001:db8:0:ffff:ffff:ffff:ffff:ffff"),
    ).toBe("2001:db8::/48");
  });

  it("collapses an IPv6 /128 single-host", () => {
    expect(rangeToCidr("2001:db8::1", "2001:db8::1")).toBe("2001:db8::1/128");
  });

  it("returns null for mixed-family inputs", () => {
    expect(rangeToCidr("192.0.2.0", "::ffff:192.0.2.255")).toBeNull();
  });

  it("returns null for invalid input", () => {
    expect(rangeToCidr("not-an-ip", "192.0.2.0")).toBeNull();
    expect(rangeToCidr("192.0.2.0", "not-an-ip")).toBeNull();
  });
});
