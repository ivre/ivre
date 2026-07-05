/* @vitest-environment jsdom */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { UploadScansError, uploadScans } from "./upload";

const realFetch = globalThis.fetch;

function mockFetch(impl: typeof fetch) {
  globalThis.fetch = impl as typeof fetch;
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("uploadScans", () => {
  beforeEach(() => {
    mockFetch(vi.fn());
  });

  it("POSTs multipart FormData to /cgi/view without Content-Type", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    mockFetch(
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          url: String(input),
          init: init ?? {},
        });
        return Response.json({ count: 2 }, { status: 200 });
      }) as typeof fetch,
    );

    const file = new File(["<nmaprun></nmaprun>"], "scan.xml", {
      type: "application/xml",
    });
    const result = await uploadScans({
      files: [file],
      source: "lab-scanner",
      categories: "Country-FR,Standard",
      referer: "https://ivre.example/ui/#/upload",
    });

    expect(result).toEqual({ count: 2 });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("/cgi/view");
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.credentials).toBe("same-origin");
    expect(calls[0]!.init.headers).toBeUndefined();

    const body = calls[0]!.init.body as FormData;
    expect(body.get("source")).toBe("lab-scanner");
    expect(body.get("categories")).toBe("Country-FR,Standard");
    expect(body.get("referer")).toBe("https://ivre.example/ui/#/upload");
    const results = body.getAll("result");
    expect(results).toHaveLength(1);
    expect(results[0]).toBe(file);
  });

  it("appends one result part per file", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    mockFetch(
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          url: String(input),
          init: init ?? {},
        });
        return Response.json({ count: 2 }, { status: 200 });
      }) as typeof fetch,
    );

    const a = new File(["a"], "a.xml", { type: "application/xml" });
    const b = new File(["b"], "b.xml", { type: "application/xml" });
    await uploadScans({ files: [a, b], source: "src" });

    const body = calls[0]!.init.body as FormData;
    expect(body.getAll("result")).toEqual([a, b]);
  });

  it("throws UploadScansError with server JSON message on 403", async () => {
    mockFetch(
      vi.fn(async () =>
        Response.json(
          { error: "Uploads are disabled. Set WEB_UPLOAD_OK = True in ivre.conf to enable write endpoints." },
          { status: 403 },
        ),
      ),
    );

    const file = new File(["x"], "x.xml");
    await expect(
      uploadScans({ files: [file], source: "s" }),
    ).rejects.toMatchObject({
      name: "UploadScansError",
      status: 403,
      message: expect.stringContaining("WEB_UPLOAD_OK"),
    });
  });

  it("rejects empty file list before networking", async () => {
    const spy = vi.fn();
    mockFetch(spy);
    await expect(uploadScans({ files: [], source: "s" })).rejects.toThrow(
      UploadScansError,
    );
    expect(spy).not.toHaveBeenCalled();
  });

  it("rejects blank source before networking", async () => {
    const spy = vi.fn();
    mockFetch(spy);
    const file = new File(["x"], "x.xml");
    await expect(uploadScans({ files: [file], source: "  " })).rejects.toThrow(
      /mandatory/i,
    );
    expect(spy).not.toHaveBeenCalled();
  });

  it("forwards AbortSignal to fetch", async () => {
    const spy = vi.fn(async () => Response.json({ count: 1 }, { status: 200 }));
    mockFetch(spy);
    const controller = new AbortController();
    const file = new File(["x"], "x.xml");
    await uploadScans({ files: [file], source: "s" }, controller.signal);
    expect(spy).toHaveBeenCalledWith(
      "/cgi/view",
      expect.objectContaining({ signal: controller.signal }),
    );
  });
});
