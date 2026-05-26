import { describe, expect, it } from "vitest";

import {
  isDesktopGenericIpcDisabled,
  isLegacyDesktopGenericIpcDisableExperimentEnabled,
  resolveDesktopGenericIpcPolicy,
} from "./desktopGenericIpcPolicy";

describe("desktop generic IPC policy", () => {
  it("disables generic IPC by default for the Round 24 release candidate", () => {
    expect(resolveDesktopGenericIpcPolicy({})).toBe("disabled");
    expect(isDesktopGenericIpcDisabled({})).toBe(true);
  });

  it("keeps the explicit disabled policy switch idempotent", () => {
    const env = { VITE_DESKTOP_GENERIC_IPC_POLICY: "disabled" };

    expect(resolveDesktopGenericIpcPolicy(env)).toBe("disabled");
    expect(isDesktopGenericIpcDisabled(env)).toBe(true);
  });

  it("keeps the Round 20 legacy disable experiment alias working", () => {
    const env = { VITE_DESKTOP_DISABLE_GENERIC_IPC: "1" };

    expect(isLegacyDesktopGenericIpcDisableExperimentEnabled(env)).toBe(true);
    expect(resolveDesktopGenericIpcPolicy(env)).toBe("disabled");
  });

  it("lets an explicit compat policy override the legacy disable alias", () => {
    const env = {
      VITE_DESKTOP_GENERIC_IPC_POLICY: "compat",
      VITE_DESKTOP_DISABLE_GENERIC_IPC: "1",
    };

    expect(resolveDesktopGenericIpcPolicy(env)).toBe("compat");
    expect(isDesktopGenericIpcDisabled(env)).toBe(false);
  });
});
