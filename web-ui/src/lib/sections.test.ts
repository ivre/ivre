import { describe, expect, it } from "vitest";

import { getSection, SECTIONS } from "./sections";

describe("section configs", () => {
  it("defines all known data sections", () => {
    const ids = SECTIONS.map((s) => s.id);
    // Account / admin pages (Admin, API keys) are intentionally
    // *not* listed here — they are pure routes registered in
    // ``routes/root.tsx`` and surfaced via the user menu only.
    expect(ids).toEqual([
      "view",
      "active",
      "passive",
      "dns",
      "flow",
      "rir",
    ]);
  });

  it("does not list Admin or API keys (those are user-menu-only routes)", () => {
    const ids = SECTIONS.map((s) => s.id) as readonly string[];
    expect(ids).not.toContain("admin");
    expect(ids).not.toContain("api-keys");
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

    it("declares a /count companion for the results headline", () => {
      expect(view.countEndpoint).toBe("/view/count");
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

    it("declares a /count companion for the results headline", () => {
      expect(active.countEndpoint).toBe("/scans/count");
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

    it("declares a /count companion for the results headline", () => {
      expect(passive.countEndpoint).toBe("/passive/count");
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

  describe("dns", () => {
    const dns = getSection("dns")!;

    it("is a real (non-stub) section with its own ``dns`` result type", () => {
      expect(dns.stub).toBeFalsy();
      expect(dns.resultType).toBe("dns");
    });

    it("hits ``/cgi/dns`` (the dedicated merge endpoint)", () => {
      expect(dns.listEndpoint).toBe("/dns");
    });

    it("does not declare a /count companion (no /cgi/dns/count on the server)", () => {
      // The DNS section is a synthetic merge over ``db.nmap`` and
      // ``db.passive``; the backend exposes neither a
      // ``top/<field>`` companion nor a ``/count`` route. The
      // results header therefore falls back to the loaded-only
      // form.
      expect(dns.countEndpoint).toBeUndefined();
    });

    it("does not declare a top endpoint or facets (no facet sidebar)", () => {
      // ``/cgi/dns`` does not expose a ``top/<field>``
      // companion; the section's facet sidebar is therefore
      // empty, and the FacetSidebar component renders nothing.
      expect(dns.topEndpoint).toBeUndefined();
      expect(dns.facets).toEqual([]);
    });

    it("does not declare a map endpoint", () => {
      expect(dns.mapEndpoint).toBeUndefined();
    });
  });

  describe("rir", () => {
    const rir = getSection("rir")!;

    it("is a real (non-stub) section with its own ``rir`` result type", () => {
      expect(rir.stub).toBeFalsy();
      expect(rir.resultType).toBe("rir");
    });

    it("hits ``/cgi/rir`` for the record list and ``/cgi/rir/top`` for facets", () => {
      expect(rir.listEndpoint).toBe("/rir");
      expect(rir.topEndpoint).toBe("/rir/top");
    });

    it("declares a /count companion for the results headline", () => {
      expect(rir.countEndpoint).toBe("/rir/count");
    });

    it("does not declare a map endpoint (RIR data carries no coordinates)", () => {
      expect(rir.mapEndpoint).toBeUndefined();
    });

    it("declares the country and source_file facets", () => {
      // ``country`` reuses the standard facet; ``source_file``
      // (the basename of the RIR dump archive) is RIR-specific.
      // Other RPSL fields are reachable via free-text or via
      // direct tokens (``asnum:``, ``asname:``, ``sourcefile:``).
      expect(rir.facets).toContain("country");
      expect(rir.facets).toContain("source_file");
    });
  });

  describe("flow", () => {
    const flow = getSection("flow")!;

    it("is a real (non-stub) section with its own ``flow`` result type", () => {
      expect(flow.stub).toBeFalsy();
      expect(flow.resultType).toBe("flow");
    });

    it("hits ``/cgi/flows`` for the graph endpoint", () => {
      // The flow route is structurally different from the
      // other data sections \u2014 a single endpoint that
      // returns a graph (``{nodes, edges}``), counts, or
      // details depending on the JSON-encoded ``q=``.
      expect(flow.listEndpoint).toBe("/flows");
    });

    it("does not declare a /count companion (counts ride on the main route)", () => {
      // Flow counts are obtained by setting ``q.count = true``
      // on the main ``/cgi/flows`` request, not via a separate
      // ``/count`` companion. The Flow route renders its own
      // counts block (clients / servers / flows) and does not
      // share the generic ``loaded / total`` results headline.
      expect(flow.countEndpoint).toBeUndefined();
    });

    it("does not declare a top endpoint or facets", () => {
      // The flow route exposes no ``/cgi/flows/top/<field>``
      // companion; the facet sidebar is therefore empty and
      // the FilterBar is replaced by a dedicated dual-input
      // (node-filters / edge-filters) panel \u2014 see
      // ``components/FlowFilterPanel.tsx``.
      expect(flow.topEndpoint).toBeUndefined();
      expect(flow.facets).toEqual([]);
    });

    it("does not declare a map endpoint", () => {
      expect(flow.mapEndpoint).toBeUndefined();
    });
  });

  it("returns ``undefined`` for unknown section ids", () => {
    expect(getSection("nope")).toBeUndefined();
  });
});
