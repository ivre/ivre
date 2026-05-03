import { describe, expect, it } from "vitest";

import type { PassiveRecord } from "./api";
import { describePassiveValue } from "./passive";

const baseRecord = (
  overrides: Partial<PassiveRecord> = {},
): PassiveRecord => ({
  schema_version: 3,
  recontype: "DNS_ANSWER",
  value: "example.com",
  count: 1,
  firstseen: 1_700_000_000,
  lastseen: 1_700_000_000,
  ...overrides,
});

describe("describePassiveValue (recontype-aware rendering)", () => {
  it("DNS A: renders ``name → addr``", () => {
    const r = baseRecord({
      recontype: "DNS_ANSWER",
      rrtype: "A",
      value: "example.com",
      addr: "1.2.3.4",
    });
    const d = describePassiveValue(r);
    expect(d.heading).toBe("DNS A");
    expect(d.primary).toBe("example.com → 1.2.3.4");
  });

  it("DNS CNAME: renders ``name → targetval``", () => {
    const r = baseRecord({
      recontype: "DNS_ANSWER",
      rrtype: "CNAME",
      value: "time.windows.com",
      targetval: "time.microsoft.akadns.net",
    });
    const d = describePassiveValue(r);
    expect(d.heading).toBe("DNS CNAME");
    expect(d.primary).toBe("time.windows.com → time.microsoft.akadns.net");
  });

  it("HTTP_SERVER_HEADER includes the header name in the heading", () => {
    const r = baseRecord({
      recontype: "HTTP_SERVER_HEADER",
      source: "SERVER",
      value: "Apache",
    });
    const d = describePassiveValue(r);
    expect(d.heading).toMatch(/HTTP server header.*SERVER/);
    expect(d.primary).toBe("Apache");
  });

  it("SSL_SERVER cert: surfaces subject + issuer + sha1", () => {
    const r = baseRecord({
      recontype: "SSL_SERVER",
      source: "cert",
      value: "MIIBvjCCASegAwIBAg...",
      infos: {
        subject_text: "commonName=example.com",
        issuer_text: "commonName=Example CA",
        sha1: "ce9cbaa461eef2b82e27d3dfc29aab381880732e",
      },
    });
    const d = describePassiveValue(r);
    expect(d.heading).toBe("TLS server cert");
    expect(d.primary).toBe("commonName=example.com");
    expect(d.secondary).toContain("Example CA");
    expect(d.secondary).toContain("ce9cbaa461eef2b82e27d3dfc29aab381880732e");
  });

  it("SSL_SERVER ja3-*: surfaces JA3-S as primary, sha1 as secondary", () => {
    const r = baseRecord({
      recontype: "SSL_SERVER",
      source: "ja3-1be3ecebe5aa9d3654e6e703d81f6928",
      value: "a95ca7eab4d47d051a5cd4fb7b6005dc",
      infos: { sha1: "2bdc6a444280c528ff3f465d95a6425286a1faa2" },
    });
    const d = describePassiveValue(r);
    expect(d.heading).toBe("JA3-S");
    expect(d.primary).toBe("a95ca7eab4d47d051a5cd4fb7b6005dc");
    expect(d.secondary).toBe(
      "SHA1: 2bdc6a444280c528ff3f465d95a6425286a1faa2",
    );
  });

  it("falls back to a humanised recontype for unknown shapes", () => {
    const r = baseRecord({
      recontype: "STUN_HONEYPOT_REQUEST",
      value: "Binding Request",
    });
    const d = describePassiveValue(r);
    expect(d.heading).toBe("stun honeypot request");
    expect(d.primary).toBe("Binding Request");
  });
});
