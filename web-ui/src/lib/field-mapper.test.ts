import { describe, expect, it } from "vitest";

import { createFilter, displayLabel } from "./field-mapper";

describe("createFilter — simple fields", () => {
  it("country (string label)", () => {
    expect(createFilter("country", "FR")).toEqual({
      type: "country",
      value: "FR",
    });
  });

  it("country (tuple label) keeps the code", () => {
    expect(createFilter("country", ["FR", "France"])).toEqual({
      type: "country",
      value: "FR",
    });
  });

  it("asnum (number)", () => {
    expect(createFilter("asnum", 13335)).toEqual({
      type: "asnum",
      value: "13335",
    });
  });

  it("asnum (tuple) keeps the number", () => {
    expect(createFilter("asnum", [13335, "Cloudflare"])).toEqual({
      type: "asnum",
      value: "13335",
    });
  });

  it('"as" alias maps to asnum', () => {
    expect(createFilter("as", [13335, "Cloudflare"])).toEqual({
      type: "asnum",
      value: "13335",
    });
  });

  it("source", () => {
    expect(createFilter("source", "scan-1")).toEqual({
      type: "source",
      value: "scan-1",
    });
  });

  it("hostname", () => {
    expect(createFilter("hostname", "foo.example.com")).toEqual({
      type: "hostname",
      value: "foo.example.com",
    });
  });
});

describe("createFilter — port family", () => {
  it("port:open with [proto, port] → bare token", () => {
    expect(createFilter("port:open", ["tcp", 443])).toEqual({
      value: "tcp/443",
    });
  });

  it("port:open with limit suffix is normalised", () => {
    expect(createFilter("port:open:15", ["tcp", 443])).toEqual({
      value: "tcp/443",
    });
  });

  it("port:filtered also flows through the same shape", () => {
    expect(createFilter("port:filtered", ["udp", 53])).toEqual({
      value: "udp/53",
    });
  });
});

describe("createFilter — city", () => {
  it("city tuple", () => {
    expect(createFilter("city", ["FR", "Carcassonne"])).toEqual({
      type: "city",
      value: "FR/Carcassonne",
    });
  });
});

describe("createFilter — service / product / version", () => {
  it("service tuple keeps name only", () => {
    expect(createFilter("service", ["http", "nginx", "1.18"])).toEqual({
      type: "service",
      value: "http",
    });
  });

  it("product tuple keeps last element", () => {
    expect(createFilter("product", ["http", "nginx"])).toEqual({
      type: "product",
      value: "nginx",
    });
  });

  it("version tuple keeps last element", () => {
    expect(createFilter("version", ["http", "nginx", "1.18"])).toEqual({
      type: "version",
      value: "1.18",
    });
  });
});

describe("createFilter — tag", () => {
  it("tag tuple joins with colon", () => {
    expect(createFilter("tag", ["CDN", "Cloudflare"])).toEqual({
      type: "tag",
      value: "CDN:Cloudflare",
    });
  });

  it("tag string", () => {
    expect(createFilter("tag", "Honeypot")).toEqual({
      type: "tag",
      value: "Honeypot",
    });
  });
});

describe("createFilter — smb.* family", () => {
  it("smb.dnsdomain", () => {
    expect(createFilter("smb.dnsdomain", "EXAMPLE.LOCAL")).toEqual({
      type: "smb.dnsdomain",
      value: "EXAMPLE.LOCAL",
    });
  });

  it("smb.unknown still flows through with the same type", () => {
    expect(createFilter("smb.somethingnew", "x")).toEqual({
      type: "smb.somethingnew",
      value: "x",
    });
  });
});

describe("createFilter — fallback", () => {
  it("unknown type falls back to anonymous bare token", () => {
    expect(createFilter("totally-unknown", "hi")).toEqual({ value: "hi" });
  });
});

describe("placeholder rendering (null → (unknown))", () => {
  it("displayLabel: null inside a tuple becomes '(unknown)'", () => {
    expect(displayLabel("product", ["http", null as unknown as string])).toBe(
      "http / (unknown)",
    );
    expect(
      displayLabel("product", [
        null as unknown as string,
        null as unknown as string,
      ]),
    ).toBe("(unknown) / (unknown)");
  });

  it("displayLabel: literal-string 'null' also becomes '(unknown)'", () => {
    expect(displayLabel("product", ["http", "null"])).toBe(
      "http / (unknown)",
    );
    expect(displayLabel("product", ["null", "null"])).toBe(
      "(unknown) / (unknown)",
    );
  });

  it("displayLabel: empty-string slot becomes '(unknown)'", () => {
    expect(displayLabel("product", ["http", ""])).toBe("http / (unknown)");
  });

  it("displayLabel: tuple slots are joined with ' / '", () => {
    expect(displayLabel("product", ["http", "nginx"])).toBe("http / nginx");
    expect(displayLabel("version", ["http", "nginx", "1.18"])).toBe(
      "http / nginx / 1.18",
    );
  });

  it("createFilter: null in tuple becomes '(unknown)' in the filter value", () => {
    expect(
      createFilter("country", [null as unknown as string, "France"]),
    ).toEqual({ type: "country", value: "(unknown)" });
  });
});

describe("displayLabel", () => {
  it("country tuple → human name", () => {
    expect(displayLabel("country", ["FR", "France"])).toBe("France");
  });

  it("asnum tuple → AS<num> <name>", () => {
    expect(displayLabel("asnum", [13335, "Cloudflare"])).toBe(
      "AS13335 Cloudflare",
    );
  });

  it("city tuple → name, country", () => {
    expect(displayLabel("city", ["FR", "Carcassonne"])).toBe(
      "Carcassonne, FR",
    );
  });

  it("tag tuple → category: description", () => {
    expect(displayLabel("tag", ["CDN", "Cloudflare"])).toBe("CDN: Cloudflare");
  });

  it("port:open tuple → proto/port", () => {
    expect(displayLabel("port:open", ["tcp", 443])).toBe("tcp/443");
  });

  it("service tuple → slot-by-slot with ' / '", () => {
    expect(displayLabel("service", ["http", "nginx", "1.18"])).toBe(
      "http / nginx / 1.18",
    );
  });

  it("plain string passes through", () => {
    expect(displayLabel("source", "scan-1")).toBe("scan-1");
  });
});
