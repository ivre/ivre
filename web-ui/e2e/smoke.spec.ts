import { expect, test } from "@playwright/test";

/**
 * Smoke test: the app shell renders and the View section is the
 * default route. We do not exercise backend-dependent UI here
 * because ``pnpm dev`` runs without a real ``ivre httpd`` in CI.
 */
test("app shell loads and lands on View", async ({ page }) => {
  // The /cgi/config script tag will 404 in CI dev mode (no backend
  // running). We don't care for this smoke test.
  await page.route("**/cgi/config", (route) => route.fulfill({ status: 204 }));
  await page.route("**/cgi/**", (route) => route.fulfill({ status: 204 }));

  await page.goto("/");

  // Brand link visible.
  await expect(page.getByRole("link", { name: /IVRE/i })).toBeVisible();

  // Default redirect to /view → the View tab is current.
  await expect(page).toHaveURL(/#\/view/);
  await expect(page.getByRole("link", { name: "View" })).toHaveAttribute(
    "aria-current",
    "page",
  );

  // Filter input is present.
  await expect(page.getByRole("textbox", { name: /filter query/i })).toBeVisible();

  // Theme toggle is present.
  await expect(
    page.getByRole("button", { name: /switch to (dark|light) mode/i }),
  ).toBeVisible();
});

test("section nav switches to a stub", async ({ page }) => {
  await page.route("**/cgi/**", (route) => route.fulfill({ status: 204 }));
  await page.goto("/");
  await page.getByRole("link", { name: "RIR" }).click();
  await expect(page).toHaveURL(/#\/rir/);
  await expect(page.getByRole("heading", { name: /RIR/i })).toBeVisible();
  await expect(page.getByText(/under construction/i)).toBeVisible();
});

test("Active section renders the host-list page (no world map)", async ({
  page,
}) => {
  // No backend in CI dev mode; stub everything to 204.
  await page.route("**/cgi/**", (route) => route.fulfill({ status: 204 }));
  await page.goto("/");
  await page.getByRole("link", { name: "Active" }).click();
  await expect(page).toHaveURL(/#\/active/);
  await expect(page.getByRole("link", { name: "Active" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  // Same filter-bar UI as View (proves the page rendered, not the
  // "under construction" stub).
  await expect(
    page.getByRole("textbox", { name: /filter query/i }),
  ).toBeVisible();
  // The world map widget has its own ``role="img"`` with the SR-only
  // "World map showing the geographic distribution of results."
  // label; raw scans aren't typically GeoIP-enriched so the Active
  // section omits it entirely.
  await expect(page.getByLabel(/world map/i)).toHaveCount(0);
});

test("direct navigation to /view/host/<addr> opens the detail sheet", async ({
  page,
}) => {
  // Mock the single-host fetch so the route renders something.
  // ``page.route`` handlers stack LIFO and ``route.continue()`` forwards
  // the request to the actual network (no backend in CI dev), so we
  // dispatch from a single handler rather than chaining via
  // ``route.fallback()``.
  const sample = {
    addr: "1.2.3.4",
    infos: { country_code: "FR", country_name: "France" },
    ports: [
      { protocol: "tcp", port: 443, state_state: "open", service_name: "https" },
    ],
  };
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/view") {
      const q = url.searchParams.get("q") ?? "";
      if (q.includes("host:")) {
        return route.fulfill({
          status: 200,
          contentType: "application/x-ndjson",
          body: JSON.stringify(sample) + "\n",
        });
      }
      return route.fulfill({ status: 200, body: "" });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/view/host/1.2.3.4");
  await expect(
    page.getByRole("heading", { name: "1.2.3.4" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /copy permalink/i }),
  ).toBeVisible();
});
