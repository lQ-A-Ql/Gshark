import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findMapperAnyViolations } from "./check-mapper-any.mjs";

function writeFixtureFile(frontendRoot, relativePath, content) {
  const absolutePath = resolve(frontendRoot, relativePath);
  mkdirSync(resolve(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, content);
}

describe("check-mapper-any script", () => {
  it("reports raw any in production mapper files", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-mapper-any-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/mappers/badMapper.ts",
      "export function asBad(input: any) { return input; }\n",
    );
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/mappers/badMapper.test.ts",
      'it("allows the word any in tests", () => {});\n',
    );

    expect(findMapperAnyViolations({ frontendRoot })).toEqual([
      {
        path: "src/app/integrations/mappers/badMapper.ts",
        line: 1,
        text: "export function asBad(input: any) { return input; }",
      },
    ]);
  });

  it("passes mapper files that use unknown parser inputs", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-mapper-any-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/mappers/goodMapper.ts",
      "export function asGood(input: unknown) { return String(input ?? ''); }\n",
    );

    expect(findMapperAnyViolations({ frontendRoot })).toEqual([]);
  });
});
