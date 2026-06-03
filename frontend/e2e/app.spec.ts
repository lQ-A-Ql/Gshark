import { test, expect } from "./fixtures";

test.describe("app startup", () => {
  test("loads and shows startup page", async ({ startupPage: page }) => {
    await expect(page.locator("text=MEOW~TRAFFIC")).toBeVisible();
    await expect(page.locator("h1")).toHaveText("启动中");
  });

  test("displays backend connection status", async ({ startupPage: page }) => {
    await expect(page.locator("text=后端服务")).toBeVisible();
    await expect(page.locator("text=后端服务").locator("..")).toContainText(
      /已连接|启动中/,
    );
  });
});
