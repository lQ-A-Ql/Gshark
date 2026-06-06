export interface DesktopRulesBinding {
  GetRuleStatus?: () => Promise<unknown>;
  ToggleRulePack?: (packId: string, enabled: boolean) => Promise<unknown>;
  CheckRuleUpdates?: () => Promise<unknown>;
  DownloadRulePack?: (packId: string, url: string) => Promise<unknown>;
  UpdateRuleConfig?: (config: unknown) => Promise<unknown>;
  GetRuleConflicts?: () => Promise<unknown>;
  ValidateRules?: (content: string) => Promise<unknown>;
}
