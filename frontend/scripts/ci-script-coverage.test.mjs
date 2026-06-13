import { describe, expect, it } from "vitest";

import { packageScriptRunsFromCi } from "./ci-script-coverage.mjs";

describe("ci-script-coverage", () => {
  it("finds scripts directly referenced by ci", () => {
    const manifest = {
      scripts: {
        ci: "pnpm run target:check",
        "target:check": "node target.mjs",
      },
    };

    expect(packageScriptRunsFromCi(manifest, "target:check")).toBe(true);
  });

  it("finds scripts through grouped ci stages", () => {
    const manifest = {
      scripts: {
        ci: "pnpm run ci:quality && pnpm run ci:desktop",
        "ci:desktop": "pnpm run target:check",
        "target:check": "node target.mjs",
      },
    };

    expect(packageScriptRunsFromCi(manifest, "target:check")).toBe(true);
  });

  it("does not loop forever on recursive scripts", () => {
    const manifest = {
      scripts: {
        ci: "pnpm run ci:desktop",
        "ci:desktop": "pnpm run ci && pnpm run other:check",
      },
    };

    expect(packageScriptRunsFromCi(manifest, "target:check")).toBe(false);
  });
});
