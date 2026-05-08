import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findPackageManagerFailures } from "./check-package-manager.mjs";

function writePackageJson(frontendRoot, packageManager) {
  writeFileSync(
    resolve(frontendRoot, "package.json"),
    JSON.stringify({
      name: "package-manager-check-fixture",
      ...(packageManager === null ? {} : { packageManager }),
    }),
  );
}

describe("check-package-manager script", () => {
  it("accepts a pnpm-managed frontend workspace", () => {
    const workspaceRoot = mkdtempSync(resolve(tmpdir(), "gshark-package-manager-check-"));
    const frontendRoot = resolve(workspaceRoot, "frontend");
    mkdirSync(frontendRoot, { recursive: true });
    writePackageJson(frontendRoot, "pnpm@10.31.0");
    writeFileSync(resolve(frontendRoot, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");

    expect(findPackageManagerFailures({ frontendRoot, workspaceRoot })).toEqual([]);
  });

  it("rejects missing pnpm metadata and unsupported lockfiles", () => {
    const workspaceRoot = mkdtempSync(resolve(tmpdir(), "gshark-package-manager-check-"));
    const frontendRoot = resolve(workspaceRoot, "frontend");
    mkdirSync(frontendRoot, { recursive: true });
    writePackageJson(frontendRoot, "npm@11.0.0");
    writeFileSync(resolve(workspaceRoot, "package-lock.json"), "{}\n");
    writeFileSync(resolve(frontendRoot, "yarn.lock"), "\n");

    expect(findPackageManagerFailures({ frontendRoot, workspaceRoot })).toEqual([
      "frontend/package.json must declare packageManager as pnpm@...",
      "frontend/pnpm-lock.yaml is required as the only maintained frontend lockfile.",
      `Remove unsupported lockfile: ${resolve(frontendRoot, "yarn.lock")}`,
      `Remove unsupported lockfile: ${resolve(workspaceRoot, "package-lock.json")}`,
    ]);
  });
});
