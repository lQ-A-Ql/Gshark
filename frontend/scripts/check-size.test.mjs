import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { countLines, findSizeBudgetFailures, findUnbudgetedMapperFiles } from "./check-size.mjs";

function writeFixtureFile(frontendRoot, relativePath, content) {
  const absolutePath = resolve(frontendRoot, relativePath);
  mkdirSync(resolve(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, content);
}

describe("check-size script", () => {
  it("counts empty, Unix, and Windows line endings", () => {
    expect(countLines("")).toBe(0);
    expect(countLines("one")).toBe(1);
    expect(countLines("one\ntwo")).toBe(2);
    expect(countLines("one\r\ntwo\r\nthree")).toBe(3);
  });

  it("reports files that exceed their configured line budget", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-size-check-"));
    writeFixtureFile(frontendRoot, "src/small.ts", "one\ntwo\nthree");
    writeFixtureFile(frontendRoot, "src/large.ts", "one\ntwo\nthree\nfour");

    expect(
      findSizeBudgetFailures({
        frontendRoot,
        budgets: [
          {
            path: "src/small.ts",
            maxLines: 4,
            reason: "small fixture stays within budget",
          },
          {
            path: "src/large.ts",
            maxLines: 3,
            reason: "large fixture should fail",
          },
        ],
      }),
    ).toEqual([
      {
        path: "src/large.ts",
        maxLines: 3,
        reason: "large fixture should fail",
        lines: 4,
      },
    ]);
  });

  it("reports mapper files that do not have a configured line budget", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-size-check-"));
    writeFixtureFile(frontendRoot, "src/app/integrations/mappers/budgetedMapper.ts", "export {};");
    writeFixtureFile(frontendRoot, "src/app/integrations/mappers/unbudgetedMapper.ts", "export {};");
    writeFixtureFile(frontendRoot, "src/app/integrations/mappers/unbudgetedMapper.test.ts", "export {};");

    expect(
      findUnbudgetedMapperFiles({
        frontendRoot,
        budgets: [
          {
            path: "src/app/integrations/mappers/budgetedMapper.ts",
            maxLines: 5,
            reason: "fixture mapper has a budget",
          },
        ],
      }),
    ).toEqual(["src/app/integrations/mappers/unbudgetedMapper.ts"]);
  });
});
