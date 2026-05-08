import { describe, expect, it } from "vitest";
import { resolve } from "node:path";

import { createPrettierBatches, runPrettierFormatCheck } from "./check-format.mjs";

describe("check-format script", () => {
  it("splits prettier targets into stable batches", () => {
    expect(createPrettierBatches(["a", "b", "c", "d", "e"], 2)).toEqual([["a", "b"], ["c", "d"], ["e"]]);
  });

  it("rejects invalid batch sizes", () => {
    expect(() => createPrettierBatches(["a"], 0)).toThrow("batchSize must be greater than zero");
  });

  it("returns the first non-zero prettier status", () => {
    const calls = [];
    const result = runPrettierFormatCheck({
      frontendRoot: "frontend",
      targets: ["one.ts", "two.ts", "three.ts"],
      batchSize: 2,
      nodePath: "node",
      stdio: "pipe",
      spawn: (command, args, options) => {
        calls.push({ command, args, options });
        return { status: calls.length === 1 ? 0 : 2 };
      },
    });

    expect(result).toEqual({ status: 2 });
    expect(calls).toHaveLength(2);
    const prettierCli = resolve("frontend", "node_modules", "prettier", "bin", "prettier.cjs");

    expect(calls[0].args).toEqual([prettierCli, "--check", "one.ts", "two.ts"]);
    expect(calls[1].args).toEqual([prettierCli, "--check", "three.ts"]);
  });

  it("returns spawn errors without throwing", () => {
    expect(
      runPrettierFormatCheck({
        targets: ["one.ts"],
        spawn: () => ({ error: new Error("spawn failed") }),
      }),
    ).toEqual({ status: 1, errorMessage: "spawn failed" });
  });
});
