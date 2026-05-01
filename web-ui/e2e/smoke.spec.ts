import { expect, test } from "@playwright/test";

test("workspace boots", async ({ page }) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: /IVRE web-ui workspace/i }),
  ).toBeVisible();
  await expect(page.getByTestId("ping")).toHaveText("Ping");
});
