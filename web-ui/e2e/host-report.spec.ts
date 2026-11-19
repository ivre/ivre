import { expect, test, type Page } from "@playwright/test";
import type { HostRecord } from "../src/lib/api";

const address = "192.0.2.11";
const ports = [
  {
    port: 22,
    protocol: "tcp",
    state_state: "open",
    service_name: "ssh",
    service_product: "OpenSSH",
    service_version: "9.6p1",
    scripts: [
      {
        id: "ssh2-enum-algos",
        output:
          "kex_algorithms:\n  curve25519-sha256\n  ecdh-sha2-nistp256\n" +
          Array.from(
            { length: 22 },
            (_, index) => `  example-algorithm-${index + 1}`,
          ).join("\n"),
      },
    ],
  },
  {
    port: 443,
    protocol: "tcp",
    state_state: "open",
    service_name: "https",
    service_product: "nginx",
    service_version: "1.24.0",
    scripts: [
      {
        id: "ssl-cert",
        output:
          "Subject: CN=edge.example.net\nIssuer: Example Lab CA\nSubject Alternative Name:\n  DNS:edge.example.net\n  DNS:portal.example.net\nNot valid before: 2026-10-01\nNot valid after: 2027-01-01",
      },
      {
        id: "http-headers",
        output:
          "HTTP/1.1 200 OK\nServer: nginx/1.24.0\nContent-Type: text/html; charset=utf-8\nStrict-Transport-Security: max-age=31536000\nContent-Security-Policy: " +
          "default-src 'self'; ".repeat(20),
      },
    ],
  },
];
const hosts = Array.from({ length: 30 }, (_, index) => ({
  addr: `192.0.2.${index + 1}`,
  source: ["lab-active", "lab-passive"],
  hostnames: [{ name: "edge.example.net" }],
  starttime: "2026-11-12T10:20:00Z",
  endtime: "2026-11-18T09:44:00Z",
  infos: {
    country_code: "FR",
    country_name: "France",
    as_num: 64500,
    as_name: "Example Network",
  },
  ports,
  cpes: [
    {
      type: "o",
      vendor: "linux",
      product: "linux_kernel",
      version: "",
      origins: ["os"],
    },
    {
      type: "a",
      vendor: "openbsd",
      product: "openssh",
      version: "9.6p1",
      origins: ["ports.port:22"],
    },
  ],
}));
const latest = {
  ...hosts[10],
  _id: "507f1f77bcf86cd799439011",
  source: "lab-new",
  categories: ["weekly"],
};
const older = {
  ...latest,
  _id: "507f1f77bcf86cd799439012",
  source: "lab-old",
  endtime: "2026-11-12T10:23:00Z",
  ports: [
    {
      ...ports[1],
      service_version: "1.22.1",
      scripts: [
        {
          id: "ssl-cert",
          output: "Subject: CN=edge.example.net\nIssuer: Example Legacy CA",
        },
      ],
    },
  ],
};
const detailedReport = {
  ...latest,
  ports: ports.map((port) => ({
    ...port,
    scripts: port.scripts.map((script) => ({
      ...script,
      output: script.output + "\n" + "Detailed scan evidence\n".repeat(100),
    })),
  })),
};

function matchesScanPort(record: HostRecord, query: string) {
  const match =
    /(?:^|\s)(?:(open|closed|filtered):)?(tcp|udp)\/(\d+)(?:\s|$)/.exec(query);
  return (
    !match ||
    record.ports?.some(
      (port) =>
        port.protocol === match[2] &&
        port.port === Number(match[3]) &&
        port.state_state === (match[1] ?? "open"),
    )
  );
}

async function backend(
  page: Page,
  missingView = false,
  scanRecords: HostRecord[] = [latest, older],
) {
  const queries: Array<{
    endpoint: string;
    query: string;
    record: string | null;
    includeId: boolean;
  }> = [];
  await page.route("**/cgi/**", async (route) => {
    const url = new URL(route.request().url());
    const query = url.searchParams.get("q") ?? "";
    const recordId = url.searchParams.get("record");
    const includeId = url.searchParams.get("include_id") === "1";
    queries.push({
      endpoint: url.pathname,
      query,
      record: recordId,
      includeId,
    });
    if (url.pathname === "/cgi/config")
      return route.fulfill({
        contentType: "application/javascript",
        body: 'window.config = { modules: ["view", "active", "passive", "notes"], dflt_limit: 10, sequential_loading: false };',
      });
    if (url.pathname.endsWith("/count"))
      return route.fulfill({
        body: String(
          url.pathname.includes("/scans")
            ? query.includes("source:lab-old")
              ? 1
              : scanRecords.filter((record) => matchesScanPort(record, query))
                  .length
            : url.pathname.includes("/passive")
              ? 1
              : 30,
        ),
      });
    if (url.pathname === "/cgi/view" || url.pathname === "/cgi/scans") {
      const addr = /host:(?:"([^"]+)"|(\S+))/.exec(query);
      let records: HostRecord[] =
        url.pathname === "/cgi/scans" ? scanRecords : missingView ? [] : hosts;
      if (addr)
        records = records.filter((host) => host.addr === (addr[1] ?? addr[2]));
      if (url.pathname === "/cgi/scans")
        records = records.filter((host) => matchesScanPort(host, query));
      if (query.includes("source:lab-old"))
        records = records.filter((host) => host.source === "lab-old");
      if (recordId !== null)
        records = records.filter((host) => host._id === recordId);
      const skip = Number(/(?:^|\s)skip:(\d+)/.exec(query)?.[1] ?? 0);
      const limit = Number(/(?:^|\s)limit:(\d+)/.exec(query)?.[1] ?? 50);
      return route.fulfill({
        contentType: "application/x-ndjson",
        body: records
          .slice(skip, skip + limit)
          .map((record) => {
            const output = { ...record };
            if (!includeId) delete output._id;
            return JSON.stringify(output);
          })
          .join("\n"),
      });
    }
    if (url.pathname === "/cgi/passive")
      return route.fulfill({
        contentType: "application/x-ndjson",
        body: JSON.stringify({
          schema_version: 3,
          addr: address,
          recontype: "HTTP_SERVER_HEADER",
          source: "SERVER",
          value: "nginx/1.24.0",
          port: 443,
          sensor: "sensor-east",
          count: 4,
          firstseen: 1794988800,
          lastseen: 1794992400,
        }),
      });
    if (url.pathname.startsWith("/cgi/notes/"))
      return route.fulfill({ status: 501 });
    if (url.pathname.endsWith("/coordinates"))
      return route.fulfill({
        json: { type: "GeometryCollection", geometries: [] },
      });
    if (url.pathname.includes("/top/")) return route.fulfill({ json: [] });
    return route.fulfill({ status: 204 });
  });
  return queries;
}

test("full-page report connects port-level View, Active and Passive evidence", async ({
  page,
}, testInfo) => {
  const queries = await backend(page);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(`/#/view/host/${address}?q=country%3AFR&skip=20`);
  await expect(
    page.getByRole("heading", { level: 1, name: address }),
  ).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator("#port-tcp-443 pre").first()).toContainText(
    "Example Lab CA",
  );
  const cpes = page.getByRole("table", { name: "Common Platform Enumeration" });
  await expect(
    cpes.getByRole("cell", { name: "linux_kernel", exact: true }),
  ).toBeVisible();
  await expect(
    cpes.getByRole("cell", { name: "openssh", exact: true }),
  ).toBeVisible();
  await expect(
    cpes.getByRole("cell", { name: "9.6p1", exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath("ip-report-desktop.png"),
    fullPage: true,
  });
  const reportNav = page.getByRole("navigation", { name: "Report sections" });
  await reportNav.getByRole("link", { name: /443\/tcp/ }).click();
  await expect(page).toHaveURL(/section=port-tcp-443/);
  await expect
    .poll(() => page.evaluate(() => window.scrollY))
    .toBeGreaterThan(0);
  await reportNav.getByRole("button", { name: "Back to top" }).click();
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
  await expect(
    page.getByRole("heading", { level: 1, name: address }),
  ).toBeFocused();
  await expect(page).not.toHaveURL(/section=/);
  await reportNav.getByRole("link", { name: /443\/tcp/ }).click();
  const certificate = page.locator("#port-tcp-443 pre").first();
  await expect(certificate).toContainText("Example Lab CA");
  await expect(certificate).toBeVisible();
  await page
    .locator("#port-tcp-443")
    .getByRole("link", { name: "Active scans →" })
    .click();
  const activeBrowser = page.getByRole("region", {
    name: "Active scans for this IP",
  });
  const activeTimeline = activeBrowser.getByRole("img", {
    name: /Timeline of 2 scans/,
  });
  await expect(activeTimeline).toBeVisible();
  await activeBrowser.locator('[data-slot="card"]').nth(1).hover();
  await expect(activeTimeline.locator("line").nth(1)).toHaveClass(
    /stroke-orange/,
  );
  await page.screenshot({
    path: testInfo.outputPath("ip-active-browser-desktop.png"),
    fullPage: true,
  });
  await activeBrowser.getByRole("link", { name: "Details" }).nth(1).click();
  await expect(page.locator("#port-tcp-443 pre").first()).toContainText(
    "Example Legacy CA",
  );
  await page.reload();
  await expect(page.locator("#port-tcp-443 pre").first()).toContainText(
    "Example Legacy CA",
  );
  await page
    .locator("#port-tcp-443")
    .getByRole("link", { name: "Passive observations →" })
    .click();
  const passiveBrowser = page.getByRole("region", {
    name: "Passive observations for this IP",
  });
  await expect(
    passiveBrowser.getByRole("button", { name: "Remove filter tcp/443" }),
  ).toBeVisible();
  await expect(
    passiveBrowser.getByRole("img", {
      name: /Timeline of 1 passive observation/,
    }),
  ).toBeVisible();
  await expect(
    passiveBrowser.getByText("nginx/1.24.0", { exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath("ip-passive-browser-desktop.png"),
    fullPage: true,
  });
  const passive = queries.find((item) => item.endpoint === "/cgi/passive")!;
  expect(passive.query).toContain(`host:${address} tcp/443`);
  expect(passive.query).not.toContain("country:");
  expect(passive.query).not.toContain("skip:20");
});

for (const state of ["open", "closed", "filtered"] as const) {
  test(`related Active scans match the displayed ${state} port state`, async ({
    page,
  }) => {
    const scans = (["open", "closed", "filtered"] as const).map(
      (value, index) => ({
        ...latest,
        _id: String(index + 100),
        source: `observed-${value}`,
        ports: [{ ...ports[1], state_state: value }],
      }),
    );
    const queries = await backend(page, false, scans);
    await page.route("**/cgi/view?**", (route) =>
      route.fulfill({
        contentType: "application/x-ndjson",
        body: JSON.stringify({
          ...latest,
          ports: [{ ...ports[1], state_state: state }],
        }),
      }),
    );
    await page.goto(`/#/view/host/${address}?q=country%3AFR&skip=900`);
    const port = page.locator("#port-tcp-443");
    await port.getByRole("link", { name: "443/tcp", exact: true }).click();
    await expect(port).toBeFocused();
    expect(
      queries.filter((request) => request.endpoint === "/cgi/scans"),
    ).toHaveLength(0);
    await port.getByRole("link", { name: "Active scans →" }).click();
    const browser = page.getByRole("region", {
      name: "Active scans for this IP",
    });
    await expect(browser.getByText("Showing 1–1 of 1")).toBeVisible();
    await expect(browser.getByRole("link", { name: "Details" })).toHaveCount(1);
    await expect(
      browser.getByRole("button", { name: `observed-${state}`, exact: true }),
    ).toBeVisible();
    const requests = queries.filter(
      (request) => request.endpoint === "/cgi/scans",
    );
    expect(requests.length).toBeGreaterThan(0);
    for (const request of requests)
      expect(request.query).toBe(
        `host:${address} ${state}:tcp/443 -sortby:endtime -sortby:starttime limit:10`,
      );
  });
}

test("Details is a real link and returns to the search position, filters and page", async ({
  page,
}) => {
  await backend(page);
  const search = "/#/view?q=service%3Ahttps&skip=10&limit=10";
  await page.goto(search);
  const details = page.getByRole("link", { name: "Details" }).nth(4);
  await details.scrollIntoViewIfNeeded();
  const position = await page.evaluate(() => window.scrollY);
  expect(position).toBeGreaterThan(200);
  await details.click();
  await expect(
    page.getByRole("heading", { level: 1, name: "192.0.2.15" }),
  ).toBeVisible();
  await page.goBack();
  await expect(page).toHaveURL(
    new RegExp("q=service%3Ahttps&skip=10&limit=10$"),
  );
  await expect
    .poll(() => page.evaluate(() => window.scrollY))
    .toBeGreaterThan(position - 100);
  await page.getByRole("link", { name: "Details" }).nth(4).click();
  await page.getByRole("link", { name: "Next host" }).click();
  await expect(
    page.getByRole("heading", { level: 1, name: "192.0.2.16" }),
  ).toBeVisible();
  await page
    .getByRole("navigation", { name: "Host evidence sources" })
    .getByRole("link", { name: /Passive/ })
    .click();
  await page.getByRole("link", { name: "Back to results" }).click();
  await expect(page).toHaveURL(
    new RegExp("q=service%3Ahttps&skip=10&limit=10$"),
  );
  await expect
    .poll(() => page.evaluate(() => window.scrollY))
    .toBeGreaterThan(position - 100);
});

test("View-origin Previous and Next host keep Passive and Notes selected", async ({
  page,
}) => {
  await backend(page);
  await page.goto("/#/view?q=service%3Ahttps&skip=10&limit=10");
  await page.getByRole("link", { name: "Details" }).nth(4).click();
  const sources = page.getByRole("navigation", {
    name: "Host evidence sources",
  });
  for (const tab of ["Passive", "Notes"]) {
    await sources.getByRole("link", { name: new RegExp(`^${tab}`) }).click();
    await page.getByRole("link", { name: "Next host" }).click();
    await expect(
      page.getByRole("heading", { level: 1, name: "192.0.2.16" }),
    ).toBeVisible();
    await expect(
      sources.getByRole("link", { name: new RegExp(`^${tab}`) }),
    ).toHaveAttribute("aria-current", "page");
    await page.getByRole("link", { name: "Previous host" }).click();
    await expect(
      page.getByRole("heading", { level: 1, name: "192.0.2.15" }),
    ).toBeVisible();
    await expect(
      sources.getByRole("link", { name: new RegExp(`^${tab}`) }),
    ).toHaveAttribute("aria-current", "page");
  }
  await expect(
    page.getByRole("link", { name: "Back to results" }),
  ).toHaveAttribute("href", "#/view?q=service%3Ahttps&skip=10&limit=10");
});

test("Active-origin Previous and Next host keep View selected without scan identifiers", async ({
  page,
}) => {
  await backend(page, false, [latest, { ...older, addr: "192.0.2.12" }]);
  await page.goto("/#/active");
  await page.getByRole("link", { name: "Details" }).first().click();
  const sources = page.getByRole("navigation", {
    name: "Host evidence sources",
  });
  await sources.getByRole("link", { name: /^View/ }).click();
  await page.getByRole("link", { name: "Next host" }).click();
  await expect(
    page.getByRole("heading", { level: 1, name: "192.0.2.12" }),
  ).toBeVisible();
  await expect(sources.getByRole("link", { name: /^View/ })).toHaveAttribute(
    "aria-current",
    "page",
  );
  await expect(page).not.toHaveURL(/record=/);
  await expect(page.locator("[data-host-report]")).toBeVisible();
  await page.getByRole("link", { name: "Previous host" }).click();
  await expect(
    page.getByRole("heading", { level: 1, name: address }),
  ).toBeVisible();
  await expect(sources.getByRole("link", { name: /^View/ })).toHaveAttribute(
    "aria-current",
    "page",
  );
  await expect(page).not.toHaveURL(/record=/);
});

for (const source of ["view", "active"] as const) {
  test(`${source} report restores reading positions instead of replaying section jumps on Back and Forward`, async ({
    page,
  }) => {
    await backend(page, false, [detailedReport]);
    if (source === "view")
      await page.route("**/cgi/view?**", (route) =>
        route.fulfill({
          contentType: "application/x-ndjson",
          body: JSON.stringify(detailedReport),
        }),
      );
    await page.setViewportSize({ width: 1440, height: 900 });
    const record = source === "active" ? `?record=${latest._id}` : "";
    await page.goto(`/#/${source}/host/${address}${record}`);
    const nav = page.getByRole("navigation", { name: "Report sections" });
    await nav.getByRole("link", { name: /443\/tcp/ }).click();
    await expect(page.locator("#port-tcp-443")).toBeFocused();
    const anchor443 = await page.evaluate(() => window.scrollY);
    await page.evaluate(() => window.scrollBy(0, 400));
    await expect
      .poll(() => page.evaluate(() => window.scrollY))
      .toBe(anchor443 + 400);
    await nav.getByRole("link", { name: /22\/tcp/ }).click();
    await expect(page.locator("#port-tcp-22")).toBeFocused();
    const anchor22 = await page.evaluate(() => window.scrollY);
    await page.evaluate(() => window.scrollBy(0, 300));
    await expect
      .poll(() => page.evaluate(() => window.scrollY))
      .toBe(anchor22 + 300);
    // Let the browser dispatch the programmatic scroll event before leaving.
    await page.evaluate(
      () =>
        new Promise<void>((resolve) => requestAnimationFrame(() => resolve())),
    );
    await page.goBack();
    await expect(page).toHaveURL(/section=port-tcp-443/);
    await expect
      .poll(() => page.evaluate(() => window.scrollY))
      .toBeCloseTo(anchor443 + 400, 0);
    await page.goForward();
    await expect(page).toHaveURL(/section=port-tcp-22/);
    await expect
      .poll(() => page.evaluate(() => window.scrollY))
      .toBeCloseTo(anchor22 + 300, 0);
    const related = page
      .locator("#port-tcp-22")
      .getByRole("link", { name: "Passive observations →" });
    await related.scrollIntoViewIfNeeded();
    const beforeLeaving = await page.evaluate(() => window.scrollY);
    expect(beforeLeaving - anchor22).toBeGreaterThan(300);
    await related.click();
    await expect(
      page.getByRole("region", { name: "Passive observations for this IP" }),
    ).toBeVisible();
    await page.goBack();
    await expect(page).toHaveURL(/section=port-tcp-22/);
    await expect
      .poll(() => page.evaluate(() => window.scrollY))
      .toBeCloseTo(beforeLeaving, 0);
  });

  test(`${source} fresh section permalink waits for delayed data and still works after reload`, async ({
    page,
  }) => {
    await backend(page);
    let release!: () => void;
    const dataReady = new Promise<void>((resolve) => {
      release = resolve;
    });
    const endpoint = source === "view" ? "/cgi/view" : "/cgi/scans";
    await page.route(`**${endpoint}?**`, async (route) => {
      await dataReady;
      return route.fulfill({
        contentType: "application/x-ndjson",
        body: JSON.stringify(detailedReport),
      });
    });
    await page.setViewportSize({ width: 1440, height: 900 });
    const record = source === "active" ? `&record=${latest._id}` : "";
    await page.goto(
      `/#/${source}/host/${address}?section=port-tcp-443${record}`,
    );
    await expect(page.getByText("Loading observations…")).toBeVisible();
    await expect(page.locator("[data-host-report]")).toHaveCount(0);
    release();
    const target = page.locator("#port-tcp-443");
    await expect(target).toBeFocused();
    await expect
      .poll(() =>
        target.evaluate((element) => element.getBoundingClientRect().top),
      )
      .toBeCloseTo(80, 0);
    await page.reload();
    await expect(target).toBeFocused();
    await expect
      .poll(() =>
        target.evaluate((element) => element.getBoundingClientRect().top),
      )
      .toBeCloseTo(80, 0);
    if (source === "view") {
      const top = page.getByRole("button", { name: "Back to top" });
      await top.click();
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
      await expect(
        page.getByRole("heading", { level: 1, name: address }),
      ).toBeFocused();
      await expect(page).not.toHaveURL(/section=/);
      await page.evaluate(() => window.scrollTo(0, 300));
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(300);
      await top.click();
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
    }
  });
}

test("different active records for the same IP open the selected scan", async ({
  page,
}) => {
  await backend(page);
  await page.goto("/#/active");
  await page.getByRole("link", { name: "Details" }).nth(1).click();
  await expect(page.locator("#port-tcp-443 pre").first()).toContainText(
    "Example Legacy CA",
  );
  await page.getByRole("link", { name: "Previous scan" }).click();
  await expect(page.locator("#port-tcp-443 pre").first()).toContainText(
    "Example Lab CA",
  );
});

test("an old scan permalink resolves in a fresh tab after newer scans are inserted", async ({
  page,
}) => {
  const archived = { ...older, _id: "9007199254740993" };
  const scans: HostRecord[] = [
    ...Array.from({ length: 30 }, (_, index) => ({
      ...latest,
      _id: String(index + 100),
    })),
    archived,
  ];
  await backend(page, false, scans);
  await page.goto("/#/active?q=source%3Alab-old");
  await page.getByRole("link", { name: "Details" }).click();
  await expect(page.locator("#port-tcp-443 pre").first()).toContainText(
    "Example Legacy CA",
  );
  const permalink = page.url();
  expect(new URL(permalink).hash).toContain(`record=${archived._id}`);
  scans.unshift({ ...latest, _id: "9007199254740994" });
  const fresh = await page.context().newPage();
  const requests = await backend(fresh, false, scans);
  await fresh.goto(permalink);
  await expect(fresh.locator("#port-tcp-443 pre").first()).toContainText(
    "Example Legacy CA",
  );
  const lookups = requests.filter(
    (request) => request.endpoint === "/cgi/scans",
  );
  expect(lookups.length).toBeGreaterThan(0);
  for (const lookup of lookups)
    expect(lookup).toMatchObject({
      record: archived._id,
      includeId: true,
      query: `host:${address} limit:1`,
    });
  scans.splice(
    scans.findIndex((scan) => scan._id === archived._id),
    1,
  );
  await fresh.reload();
  await expect(
    fresh.getByText(
      "This active scan record is no longer available for this IP address.",
    ),
  ).toBeVisible();
  await expect(fresh.locator("[data-host-report]")).toHaveCount(0);
  await fresh.close();
});

for (const source of ["active", "passive"] as const) {
  test(`capped ${source} pagination reverses visited pages after reload and browser navigation`, async ({
    page,
  }) => {
    await backend(page);
    const endpoint = source === "active" ? "/cgi/scans" : "/cgi/passive";
    const key = source === "active" ? "recordsSkip" : "passiveSkip";
    const records = Array.from({ length: 9 }, (_, index) =>
      source === "active"
        ? { ...latest, _id: String(index + 100), source: `lab-${index}` }
        : {
            addr: address,
            schema_version: 3,
            recontype: "HTTP_SERVER_HEADER",
            value: `server-${index}`,
            sensor: "sensor-east",
            port: 443,
            count: 1,
            firstseen: 1794988800,
            lastseen: 1794992400,
          },
    );
    await page.route("**/cgi/**", async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname === `${endpoint}/count`)
        return route.fulfill({ body: String(records.length) });
      if (url.pathname !== endpoint) return route.fallback();
      const query = url.searchParams.get("q") ?? "";
      const skip = Number(/(?:^|\s)skip:(\d+)/.exec(query)?.[1] ?? 0);
      const cap = skip === 4 ? 3 : 4;
      return route.fulfill({
        contentType: "application/x-ndjson",
        body: records
          .slice(skip, skip + cap)
          .map((record) => JSON.stringify(record))
          .join("\n"),
      });
    });
    await page.goto(
      `/#/view/host/${address}?tab=${source}&q=country%3AFR&skip=900`,
    );
    await expect(page.getByText("Showing 1–4 of 9")).toBeVisible();
    await page.getByRole("button", { name: "Next records" }).click();
    await expect(page.getByText("Showing 5–7 of 9")).toBeVisible();
    await page.getByRole("button", { name: "Next records" }).click();
    await expect(page.getByText("Showing 8–9 of 9")).toBeVisible();
    await page.reload();
    await expect(page.getByText("Showing 8–9 of 9")).toBeVisible();
    await page.getByRole("button", { name: "Previous records" }).click();
    await expect(page.getByText("Showing 5–7 of 9")).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`${key}=4`));
    await page.goBack();
    await expect(page.getByText("Showing 8–9 of 9")).toBeVisible();
    await page.goForward();
    await expect(page.getByText("Showing 5–7 of 9")).toBeVisible();
    await page.getByRole("button", { name: "Previous records" }).click();
    await expect(page.getByText("Showing 1–4 of 9")).toBeVisible();
    await expect(page).not.toHaveURL(new RegExp(`${key}=`));
    await expect(page).toHaveURL(/skip=900/);
  });
}

test("report works without a View record and stays readable on a narrow screen", async ({
  page,
}, testInfo) => {
  await backend(page, true);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`/#/view/host/${address}`);
  await expect(page.getByText(/No merged View record/)).toBeVisible();
  await page.getByRole("link", { name: "Browse active scans →" }).click();
  const activeBrowser = page.getByRole("region", {
    name: "Active scans for this IP",
  });
  await expect(
    activeBrowser.getByRole("img", { name: /Timeline of 2 scans/ }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: testInfo.outputPath("ip-active-browser-mobile.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: /switch to dark mode/i }).click();
  await expect(page.locator("html")).toHaveClass(/dark/);
  await page.screenshot({
    path: testInfo.outputPath("ip-active-browser-mobile-dark.png"),
    fullPage: true,
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await activeBrowser.getByRole("link", { name: "Details" }).first().click();
  await expect(page.locator("#port-tcp-443 pre").first()).toContainText(
    "Example Lab CA",
  );
  await page
    .locator("#port-tcp-443")
    .getByRole("link", { name: "Passive observations →" })
    .click();
  await expect(
    page
      .getByRole("region", { name: "Passive observations for this IP" })
      .getByRole("img", { name: /Timeline of 1 passive observation/ }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
});

test("evidence filtering keeps the fixed IP and separate Active and Passive filters", async ({
  page,
}) => {
  const queries = await backend(page);
  await page.goto(`/#/view/host/${address}?q=country%3AFR&skip=20&tab=active`);
  const activeBrowser = page.getByRole("region", {
    name: "Active scans for this IP",
  });
  await activeBrowser
    .getByRole("button", { name: "lab-old", exact: true })
    .click();
  await expect(
    activeBrowser.getByRole("button", { name: "Remove filter source:lab-old" }),
  ).toBeVisible();
  await expect(
    activeBrowser.getByRole("link", { name: "Details" }),
  ).toHaveCount(1);
  await activeBrowser
    .getByRole("textbox", { name: "Filter query" })
    .fill("category:weekly");
  await activeBrowser
    .getByRole("textbox", { name: "Filter query" })
    .press("Enter");
  await activeBrowser.getByRole("button", { name: "Clear all" }).click();
  await expect(
    activeBrowser.getByRole("link", { name: "Details" }),
  ).toHaveCount(2);
  await expect(
    activeBrowser.locator('[title="Fixed IP scope"]:visible'),
  ).toBeVisible();
  await expect(
    activeBrowser.getByRole("button", {
      name: `Remove filter host:${address}`,
    }),
  ).toHaveCount(0);
  await activeBrowser
    .getByRole("button", { name: "lab-old", exact: true })
    .click();
  await expect(
    activeBrowser.getByRole("button", { name: "Remove filter source:lab-old" }),
  ).toBeVisible();
  await page
    .getByRole("navigation", { name: "Host evidence sources" })
    .getByRole("link", { name: /Passive/ })
    .click();
  const passiveBrowser = page.getByRole("region", {
    name: "Passive observations for this IP",
  });
  await passiveBrowser
    .getByRole("textbox", { name: "Filter query" })
    .fill("sensor:sensor-east");
  await passiveBrowser
    .getByRole("textbox", { name: "Filter query" })
    .press("Enter");
  await expect(
    passiveBrowser.getByRole("button", {
      name: "Remove filter sensor:sensor-east",
    }),
  ).toBeVisible();
  await page
    .getByRole("navigation", { name: "Host evidence sources" })
    .getByRole("link", { name: /Active scans/ })
    .click();
  await expect(
    activeBrowser.getByRole("button", { name: "Remove filter source:lab-old" }),
  ).toBeVisible();
  await expect(
    activeBrowser.getByRole("link", { name: "Details" }),
  ).toHaveCount(1);
  for (const request of queries.filter(
    (item) =>
      item.endpoint.startsWith("/cgi/scans") ||
      item.endpoint.startsWith("/cgi/passive"),
  )) {
    expect(request.query).toContain(`host:${address}`);
    expect(request.query).not.toContain("country:FR");
    expect(request.query).not.toContain("skip:20");
    if (request.endpoint.startsWith("/cgi/passive"))
      expect(request.query).not.toContain("source:lab-old");
    if (request.endpoint.startsWith("/cgi/scans"))
      expect(request.query).not.toContain("sensor:sensor-east");
  }
});

test("scan Details returns to the filtered IP browser and then the originating search", async ({
  page,
}) => {
  await backend(page);
  await page.goto("/#/view?q=service%3Ahttps&skip=10&limit=10");
  await page.getByRole("link", { name: "Details" }).first().click();
  await page
    .getByRole("navigation", { name: "Host evidence sources" })
    .getByRole("link", { name: /Active scans/ })
    .click();
  const browser = page.getByRole("region", {
    name: "Active scans for this IP",
  });
  await browser.getByRole("button", { name: "lab-old", exact: true }).click();
  await expect(browser.getByRole("link", { name: "Details" })).toHaveCount(1);
  await browser.getByRole("link", { name: "Details" }).click();
  await expect(page.locator("#port-tcp-443 pre").first()).toContainText(
    "Example Legacy CA",
  );
  await page.getByRole("link", { name: "Back to active scans" }).click();
  await expect(
    browser.getByRole("button", { name: "Remove filter source:lab-old" }),
  ).toBeVisible();
  await expect(browser.getByRole("link", { name: "Details" })).toHaveCount(1);
  await page.getByRole("link", { name: "Back to results" }).click();
  await expect(page).toHaveURL(/#\/view\?q=service%3Ahttps&skip=10&limit=10$/);
});
