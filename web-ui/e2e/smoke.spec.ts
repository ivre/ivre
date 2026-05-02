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
