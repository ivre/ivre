import { describe, expect, it } from "vitest";

import { getSection, SECTIONS } from "./sections";

describe("section configs", () => {
  it("defines all known sections", () => {
    const ids = SECTIONS.map((s) => s.id);
    expect(ids).toEqual([
      "view",
      "active",
      "passive",
      "dns",
      "flow",
      "rir",
      "admin",
    ]);
  });

  describe("view", () => {
    const view = getSection("view")!;

    it("is a real (non-stub) host-list section", () => {
      expect(view.stub).toBeFalsy();
      expect(view.resultType).toBe("hosts");
    });

    it("hits ``/cgi/view`` for the host list, top, and map", () => {
      expect(view.listEndpoint).toBe("/view");
      expect(view.topEndpoint).toBe("/view/top");
      expect(view.mapEndpoint).toBe("/view/coordinates");
    });

    it("declares country and AS facets (GeoIP-enriched data)", () => {
      expect(view.facets).toContain("country");
      expect(view.facets).toContain("as");
    });
  });

  describe("active", () => {
    const active = getSection("active")!;

    it("is a real (non-stub) host-list section", () => {
      expect(active.stub).toBeFalsy();
      expect(active.resultType).toBe("hosts");
    });

    it("hits ``/cgi/scans`` for the host list and top", () => {
      expect(active.listEndpoint).toBe("/scans");
      expect(active.topEndpoint).toBe("/scans/top");
    });

    it("does not declare a map endpoint (no GeoIP enrichment on raw scans)", () => {
      expect(active.mapEndpoint).toBeUndefined();
    });

    it("does not include country / AS facets", () => {
      // ``db.nmap`` records typically lack MaxMind enrichment;
      // those facets get populated only after ``db2view`` runs.
      expect(active.facets).not.toContain("country");
      expect(active.facets).not.toContain("as");
      expect(active.facets).not.toContain("asnum");
    });

    it("includes the active-specific ``category`` facet", () => {
      expect(active.facets).toContain("category");
    });

    it("includes service / product / port / tag facets", () => {
      expect(active.facets).toContain("service");
      expect(active.facets).toContain("product");
      expect(active.facets).toContain("port:open");
      expect(active.facets).toContain("tag");
    });
  });

  describe("passive", () => {
    const passive = getSection("passive")!;

    it("is a real (non-stub) section with passive result shape", () => {
      expect(passive.stub).toBeFalsy();
      expect(passive.resultType).toBe("passive");
    });

    it("hits ``/cgi/passive`` for the record list and top", () => {
      expect(passive.listEndpoint).toBe("/passive");
      expect(passive.topEndpoint).toBe("/passive/top");
    });

    it("does not declare a map endpoint (no GeoIP enrichment)", () => {
      expect(passive.mapEndpoint).toBeUndefined();
    });

    it("does not include country / AS facets", () => {
      expect(passive.facets).not.toContain("country");
      expect(passive.facets).not.toContain("as");
    });

    it("includes the passive-specific sensor / recontype / source facets", () => {
      expect(passive.facets).toContain("sensor");
      expect(passive.facets).toContain("recontype");
      expect(passive.facets).toContain("source");
    });
  });

  it("returns ``undefined`` for unknown section ids", () => {
    expect(getSection("nope")).toBeUndefined();
  });
});
