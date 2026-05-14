import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findWireAnyViolations } from "./check-wire-any.mjs";

function writeFixtureFile(frontendRoot, relativePath, content) {
  const absolutePath = resolve(frontendRoot, relativePath);
  mkdirSync(resolve(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, content);
}

describe("check-wire-any script", () => {
  it("reports raw any in production wire DTO files", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-wire-any-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/wire/badWireDto.ts",
      "export interface BadWireDTO { payload?: any }\n",
    );
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/wire/badWireDto.test.ts",
      'it("allows the word any in tests", () => {});\n',
    );

    expect(findWireAnyViolations({ frontendRoot })).toEqual([
      {
        path: "src/app/integrations/wire/badWireDto.ts",
        line: 1,
        text: "export interface BadWireDTO { payload?: any }",
      },
    ]);
  });

  it("passes wire DTO files that use unknown for open payloads", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-wire-any-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/wire/goodWireDto.ts",
      "export interface GoodWireDTO { payload?: unknown }\n",
    );

    expect(findWireAnyViolations({ frontendRoot })).toEqual([]);
  });
});
