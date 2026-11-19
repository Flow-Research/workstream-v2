import { expect, test } from "@playwright/test";
import { chromium } from "@playwright/test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

test("loads the unpacked extension in a fresh profile and renders the popup", async () => {
  const profile = await mkdtemp(join(tmpdir(), "workstream-extension-"));
  const extensionPath = resolve("dist");
  const context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
    ],
  });

  try {
    const worker =
      context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"));
    const extensionId = new URL(worker.url()).host;
    expect(extensionId).toMatch(/^[a-p]{32}$/);

    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/popup.html`);
    await expect(page.getByRole("heading", { name: "WorkStream Wallet" })).toBeVisible();
    await expect(page.locator("#version")).toHaveText(/^\d+\.\d+\.\d+$/);
  } finally {
    await context.close();
    await rm(profile, { recursive: true, force: true });
  }
});
