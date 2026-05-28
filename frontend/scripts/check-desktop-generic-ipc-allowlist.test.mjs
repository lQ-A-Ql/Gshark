import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findDesktopGenericIpcAllowlistViolations } from "./check-desktop-generic-ipc-allowlist.mjs";

function writeClientFixture(content) {
  const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-generic-ipc-allowlist-"));
  const clientDir = resolve(frontendRoot, "src/app/integrations/clients");
  mkdirSync(clientDir, { recursive: true });
  writeFileSync(resolve(clientDir, "demoClient.ts"), content);
  return frontendRoot;
}

describe("check-desktop-generic-ipc-allowlist script", () => {
  it("accepts migrated typed routes including MISC import", () => {
    const frontendRoot = writeClientFixture(`
      request("/api/tools/misc/modules");
      request("/api/tools/misc/import");
      request(\`/api/tools/misc/packages/\${encodeURIComponent(id)}/invoke\`);
      request("/api/runtime/identity");
    `);

    expect(findDesktopGenericIpcAllowlistViolations({ frontendRoot })).toEqual([]);
  });

  it("rejects new unclassified backend routes in desktop client sources", () => {
    const frontendRoot = writeClientFixture('request("/api/new-business-route");\n');

    expect(findDesktopGenericIpcAllowlistViolations({ frontendRoot })).toEqual([
      "src/app/integrations/clients/demoClient.ts:1: unclassified backend route /api/new-business-route; add a typed DesktopApp binding or explicit compatibility entry",
    ]);
  });
});
