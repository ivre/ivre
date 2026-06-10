import { defineConfig, devices } from "@playwright/test";

// Playwright config — drives end-to-end smoke tests against `pnpm dev`.
// The chromium project uses channel: "chrome" so it launches the
// system-installed Google Chrome (preinstalled on the CI runner image)
// instead of Playwright's bundled Chromium. This avoids downloading the
// browser from cdn.playwright.dev, which repeatedly hung in CI. CI only
// needs `pnpm exec playwright install-deps chromium` for the OS libs.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://localhost:5173",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], channel: "chrome" },
    },
  ],
  webServer: {
    command: "pnpm dev",
    url: "http://localhost:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
