import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findTypeGovernanceViolations } from "./check-type-governance.mjs";

function writeFixtureFile(frontendRoot, relativePath, content) {
  const absolutePath = resolve(frontendRoot, relativePath);
  mkdirSync(resolve(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, content);
}

describe("check-type-governance script", () => {
  it("rejects raw as any in production integration files", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "meow-traffic-type-governance-"));
    writeFixtureFile(frontendRoot, "src/app/integrations/desktopBridge.ts", "export const bad = payload as any;\n");
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/desktopBridge.test.ts",
      "export const allowedInTests = payload as any;\n",
    );

    expect(findTypeGovernanceViolations({ frontendRoot })).toMatchObject([
      {
        path: "src/app/integrations/desktopBridge.ts",
        line: 1,
        reason: "production integrations must use typed normalizers, not raw as any",
      },
    ]);
  });

  it("rejects open string unions in core types outside the compatibility allowlist", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "meow-traffic-type-governance-"));
    writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgeRules.ts", "export const ok = 1;\n");
    writeFixtureFile(frontendRoot, "src/app/core/types/bad.ts", 'export type Mode = "known" | string;\n');
    writeFixtureFile(frontendRoot, "src/app/core/types/evidence.ts", "export type Value = string | number;\n");

    expect(findTypeGovernanceViolations({ frontendRoot })).toMatchObject([
      {
        path: "src/app/core/types/bad.ts",
        line: 1,
        reason: "core enum widening must use KnownOrUnknown<T>",
      },
    ]);
  });

  it("rejects wide Record inheritance in new wire DTO files", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "meow-traffic-type-governance-"));
    writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgeRules.ts", "export const ok = 1;\n");
    writeFixtureFile(frontendRoot, "src/app/core/types/demo.ts", 'export type Mode = KnownOrUnknown<"known">;\n');
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/wire/newWireDtos.ts",
      "export interface NewWireDTO extends Record<string, unknown> { id?: string }\n",
    );
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/wire/packetWireDtos.ts",
      "export interface ExistingWireDTO extends Record<string, unknown> { id?: string }\n",
    );

    expect(findTypeGovernanceViolations({ frontendRoot })).toMatchObject([
      {
        path: "src/app/integrations/wire/newWireDtos.ts",
        line: 1,
        reason: "new wire DTOs must declare explicit fields",
      },
    ]);
  });
});
