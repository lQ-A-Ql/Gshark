import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findClientAnyViolations } from "./check-client-any.mjs";

function writeFixtureFile(frontendRoot, relativePath, content) {
  const absolutePath = resolve(frontendRoot, relativePath);
  mkdirSync(resolve(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, content);
}

describe("check-client-any script", () => {
  it("reports raw any in production client files", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-client-any-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/clients/badClient.ts",
      "export async function run(request: <T>() => Promise<T>) { return request<any>(); }\n",
    );
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/clients/badClient.test.ts",
      "expect(mock).toHaveBeenCalledWith(expect.any(AbortSignal));\n",
    );

    expect(findClientAnyViolations({ frontendRoot })).toEqual([
      {
        path: "src/app/integrations/clients/badClient.ts",
        line: 1,
        text: "export async function run(request: <T>() => Promise<T>) { return request<any>(); }",
      },
    ]);
  });

  it("passes client files that use unknown parser inputs and explicit DTOs", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-client-any-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/clients/goodClient.ts",
      "interface WireDTO { value?: unknown }\nexport function asGood(input: unknown) { return input as WireDTO; }\n",
    );

    expect(findClientAnyViolations({ frontendRoot })).toEqual([]);
  });
});
