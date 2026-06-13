import { describe, expect, it, vi } from "vitest";

import type { DesktopTransportBinding } from "./bridgeTypes";
import { createRuleTypedOverrides } from "./desktopTypedBridgeRules";

describe("createRuleTypedOverrides", () => {
  it("normalizes rule status payloads without raw any casts", async () => {
    const bridge = createRuleTypedOverrides({
      GetRuleStatus: vi.fn(async () => ({
        packs: [
          {
            id: "core",
            name: "Core",
            version: { major: 1, minor: 2, patch: 3, tag: "v1", released_at: "now" },
            enabled: true,
            rule_count: 1,
            rules: [{ id: "r1", name: "Rule", enabled: true }],
          },
        ],
        total_rules: "3",
        update_config: { remote_url: "https://example.test/rules", auto_update: 1, update_interval_hours: "24" },
      })),
    } as DesktopTransportBinding);

    await expect(bridge.getRuleStatus?.()).resolves.toMatchObject({
      packs: [{ id: "core", version: { major: 1 }, rules: [{ id: "r1", enabled: true }] }],
      total_rules: 3,
      update_config: { remote_url: "https://example.test/rules", auto_update: true, update_interval_hours: 24 },
    });
  });

  it("normalizes update, conflict, config, download, and validation payloads", async () => {
    const desktopApp = {
      CheckRuleUpdates: vi.fn(async () => ({ results: [{ pack_id: "core", updated: true, downloaded_rules: "2" }] })),
      GetRuleConflicts: vi.fn(async () => ({ conflicts: [{ rule_id_1: "a", rule_id_2: "b", severity: "high" }] })),
      UpdateRuleConfig: vi.fn(async () => ({ remote_url: "url", auto_update: true, update_interval_hours: "12" })),
      DownloadRulePack: vi.fn(async () => ({ id: "core", enabled: true, version: { tag: "v2" }, rules: [] })),
      ValidateRules: vi.fn(async () => ({ valid: false, errors: [{ line: "7", rule: "bad", message: "oops" }] })),
      ToggleRulePack: vi.fn(async () => undefined),
    } as DesktopTransportBinding;
    const bridge = createRuleTypedOverrides(desktopApp);

    await expect(bridge.checkRuleUpdates?.()).resolves.toMatchObject([{ pack_id: "core", downloaded_rules: 2 }]);
    await expect(bridge.listRuleConflicts?.()).resolves.toMatchObject([{ rule_id_1: "a", severity: "high" }]);
    await expect(
      bridge.updateRuleConfig?.({ remote_url: "url", auto_update: false, update_interval_hours: 1, cache_dir: "" }),
    ).resolves.toMatchObject({ remote_url: "url", update_interval_hours: 12 });
    await expect(bridge.downloadRulePack?.("core", "url")).resolves.toMatchObject({
      id: "core",
      version: { tag: "v2" },
    });
    await expect(bridge.validateRuleContent?.("rule bad {}")).resolves.toMatchObject({
      valid: false,
      errors: [{ line: 7, rule: "bad" }],
    });
    await expect(bridge.toggleRulePack?.("core", true)).resolves.toBeUndefined();
  });
});
