import { test as base, expect, type Page } from "@playwright/test";

export { expect };

type SentinelFixtures = {
  startupPage: Page;
};

export const test = base.extend<SentinelFixtures>({
  startupPage: async ({ page }, use) => {
    await page.goto("/");
    await page.waitForLoadState("domcontentloaded");
    await use(page);
  },
});
