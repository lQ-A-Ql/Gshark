import type {
  RuleConflict,
  RuleEntry,
  RulePack,
  RuleStatus,
  RuleUpdateConfig,
  RuleUpdateResult,
  RuleValidationError,
  RuleVersion,
} from "./clients/ruleClient";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { LONG_TYPED_IPC_TIMEOUT_MS, typedCall } from "./desktopTypedBridgeCore";
import { asArray, asPlainObject } from "./mappers/mapperPrimitives";

export function createRuleTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async getRuleStatus(signal) {
      const payload = await typedCall(() => desktopApp.GetRuleStatus!(), "DesktopApp.GetRuleStatus", signal);
      return asRuleStatus(payload);
    },
    async toggleRulePack(packId, enabled) {
      await typedCall(
        () => desktopApp.ToggleRulePack!(packId, enabled),
        "DesktopApp.ToggleRulePack",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
    },
    async checkRuleUpdates() {
      const payload = await typedCall(
        () => desktopApp.CheckRuleUpdates!(),
        "DesktopApp.CheckRuleUpdates",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
      return asArray(asPlainObject(payload)?.results).map(asRuleUpdateResult);
    },
    async downloadRulePack(packId, url) {
      const payload = await typedCall(
        () => desktopApp.DownloadRulePack!(packId, url),
        "DesktopApp.DownloadRulePack",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
      return asRulePack(payload);
    },
    async updateRuleConfig(config) {
      const payload = await typedCall(
        () => desktopApp.UpdateRuleConfig!(toRuleUpdateConfigRequest(config)),
        "DesktopApp.UpdateRuleConfig",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
      return asRuleUpdateConfig(payload);
    },
    async listRuleConflicts() {
      const payload = await typedCall(() => desktopApp.GetRuleConflicts!(), "DesktopApp.GetRuleConflicts");
      return asArray(asPlainObject(payload)?.conflicts).map(asRuleConflict);
    },
    async validateRuleContent(content) {
      const payload = await typedCall(
        () => desktopApp.ValidateRules!(content),
        "DesktopApp.ValidateRules",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
      return asRuleValidationResult(payload);
    },
  };
}

function toRuleUpdateConfigRequest(config: RuleUpdateConfig) {
  return {
    remote_url: config.remote_url,
    auto_update: config.auto_update,
    update_interval_hours: config.update_interval_hours,
    cache_dir: config.cache_dir,
  };
}

function asRuleStatus(input: unknown): RuleStatus {
  const payload = asPlainObject(input) ?? {};
  return {
    packs: asArray(payload.packs).map(asRulePack),
    total_rules: n(payload.total_rules),
    enabled_rules: n(payload.enabled_rules),
    disabled_rules: n(payload.disabled_rules),
    last_update: s(payload.last_update),
    update_config: asRuleUpdateConfig(payload.update_config),
    conflicts: asArray(payload.conflicts).map(asRuleConflict),
  };
}

function asRulePack(input: unknown): RulePack {
  const payload = asPlainObject(input) ?? {};
  return {
    id: s(payload.id),
    name: s(payload.name),
    description: s(payload.description),
    source: s(payload.source),
    version: asRuleVersion(payload.version),
    enabled: b(payload.enabled),
    rule_count: n(payload.rule_count),
    checksum: s(payload.checksum),
    updated_at: s(payload.updated_at),
    rules: asArray(payload.rules).map(asRuleEntry),
  };
}

function asRuleEntry(input: unknown): RuleEntry {
  const payload = asPlainObject(input) ?? {};
  return {
    id: s(payload.id),
    name: s(payload.name),
    category: s(payload.category),
    severity: s(payload.severity),
    description: s(payload.description),
    enabled: b(payload.enabled),
  };
}

function asRuleVersion(input: unknown): RuleVersion {
  const payload = asPlainObject(input) ?? {};
  return {
    major: n(payload.major),
    minor: n(payload.minor),
    patch: n(payload.patch),
    tag: s(payload.tag),
    released_at: s(payload.released_at),
  };
}

function asRuleConflict(input: unknown): RuleConflict {
  const payload = asPlainObject(input) ?? {};
  return {
    rule_id_1: s(payload.rule_id_1),
    rule_id_2: s(payload.rule_id_2),
    pack_id_1: s(payload.pack_id_1),
    pack_id_2: s(payload.pack_id_2),
    conflict: s(payload.conflict),
    severity: s(payload.severity),
  };
}

function asRuleUpdateConfig(input: unknown): RuleUpdateConfig {
  const payload = asPlainObject(input) ?? {};
  return {
    remote_url: s(payload.remote_url),
    auto_update: b(payload.auto_update),
    update_interval_hours: n(payload.update_interval_hours),
    cache_dir: s(payload.cache_dir),
  };
}

function asRuleUpdateResult(input: unknown): RuleUpdateResult {
  const payload = asPlainObject(input) ?? {};
  return {
    pack_id: s(payload.pack_id),
    old_version: asRuleVersion(payload.old_version),
    new_version: asRuleVersion(payload.new_version),
    updated: b(payload.updated),
    downloaded_rules: n(payload.downloaded_rules),
    error: s(payload.error),
  };
}

function asRuleValidationResult(input: unknown): { valid: boolean; errors: RuleValidationError[] } {
  const payload = asPlainObject(input) ?? {};
  return {
    valid: b(payload.valid),
    errors: asArray(payload.errors).map(asRuleValidationError),
  };
}

function asRuleValidationError(input: unknown): RuleValidationError {
  const payload = asPlainObject(input) ?? {};
  return {
    line: n(payload.line),
    rule: s(payload.rule),
    message: s(payload.message),
  };
}

function s(input: unknown): string {
  return String(input ?? "");
}

function n(input: unknown): number {
  return Number(input ?? 0);
}

function b(input: unknown): boolean {
  return Boolean(input);
}
