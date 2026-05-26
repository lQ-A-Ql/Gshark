import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findDesktopMiscCompatInventoryViolations } from "./check-desktop-misc-compat-inventory.mjs";

const design = [
  "ListMiscModules",
  "ImportMiscModulePackageFromPath",
  "ImportMiscModulePackageFromPath(path string",
  "DeleteMiscModulePackage",
  "DeleteMiscModulePackage(id string)",
  "RunMiscModulePackage",
  "RunMiscModulePackage(id string",
  "ListMiscModules()",
  "runtime-complete; list-import-delete-run-typed",
].join("\n");

function writeFixtureFile(root, relativePath, content) {
  const absolutePath = resolve(root, relativePath);
  mkdirSync(resolve(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, content);
}

function createFixture(toolClientBody, designBody = design) {
  const workspace = mkdtempSync(resolve(tmpdir(), "gshark-misc-compat-inventory-"));
  const frontendRoot = resolve(workspace, "frontend");
  const designPath = resolve(workspace, "docs/desktop-ipc-misc-native-binding-design.md");
  writeFixtureFile(frontendRoot, "src/app/integrations/clients/toolClient.ts", toolClientBody);
  writeFixtureFile(workspace, "docs/desktop-ipc-misc-native-binding-design.md", designBody);
  return { frontendRoot, designPath };
}

describe("check-desktop-misc-compat-inventory script", () => {
  it("accepts the current migrated MISC routes after import typed migration", () => {
    const { frontendRoot, designPath } = createFixture(`
      request("/api/tools/misc/modules");
      request("/api/tools/misc/import");
      request(\`/api/tools/misc/packages/\${encodeURIComponent(id)}\`);
      request(\`/api/tools/misc/packages/\${encodeURIComponent(id)}/invoke\`);
    `);

    expect(findDesktopMiscCompatInventoryViolations({ frontendRoot, designPath })).toEqual([]);
  });

  it("rejects new unclassified MISC generic routes", () => {
    const { frontendRoot, designPath } = createFixture(`
      request("/api/tools/misc/modules");
      request("/api/tools/misc/import");
      request(\`/api/tools/misc/packages/\${encodeURIComponent(id)}\`);
      request(\`/api/tools/misc/packages/\${encodeURIComponent(id)}/invoke\`);
      request("/api/tools/misc/new-route");
    `);

    expect(findDesktopMiscCompatInventoryViolations({ frontendRoot, designPath })).toContain(
      "src/app/integrations/clients/toolClient.ts:6: unclassified MISC desktop route /api/tools/misc/new-route; add a typed DesktopApp binding or update the native binding design before expanding MISC transport",
    );
  });

  it("requires the native binding design to name the target typed methods", () => {
    const { frontendRoot, designPath } = createFixture(
      `
        request("/api/tools/misc/modules");
        request("/api/tools/misc/import");
        request(\`/api/tools/misc/packages/\${encodeURIComponent(id)}\`);
        request(\`/api/tools/misc/packages/\${encodeURIComponent(id)}/invoke\`);
      `,
      "design-ready; runtime-deferred",
    );

    expect(findDesktopMiscCompatInventoryViolations({ frontendRoot, designPath })).toEqual([
      "docs/desktop-ipc-misc-native-binding-design.md: missing design token ListMiscModules",
      "docs/desktop-ipc-misc-native-binding-design.md: missing design token ImportMiscModulePackageFromPath",
      "docs/desktop-ipc-misc-native-binding-design.md: missing design token ImportMiscModulePackageFromPath(path string",
      "docs/desktop-ipc-misc-native-binding-design.md: missing design token DeleteMiscModulePackage",
      "docs/desktop-ipc-misc-native-binding-design.md: missing design token DeleteMiscModulePackage(id string)",
      "docs/desktop-ipc-misc-native-binding-design.md: missing design token RunMiscModulePackage",
      "docs/desktop-ipc-misc-native-binding-design.md: missing design token RunMiscModulePackage(id string",
      "docs/desktop-ipc-misc-native-binding-design.md: missing design token ListMiscModules()",
      "docs/desktop-ipc-misc-native-binding-design.md: missing design token runtime-complete; list-import-delete-run-typed",
    ]);
  });
});
