import { useState } from "react";
import { Layers, Shield, AlertTriangle, Check, X, Settings, Download } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { MetricCard, StatusHint, SurfacePanel } from "../components/DesignSystem";
import { PageShell } from "../components/PageShell";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import {
  useRuleManagement,
  type RulePack,
  type RuleUpdateConfig,
} from "../features/rules/useRuleManagement";

export default function RuleManagement() {
  const {
    status,
    loading,
    error,
    fetchStatus,
    togglePack,
    checkUpdates,
    downloadPack,
    updateConfig,
  } = useRuleManagement();

  const [checkingUpdates, setCheckingUpdates] = useState(false);
  const [updateResults, setUpdateResults] = useState<string[]>([]);
  const [showConfig, setShowConfig] = useState(false);
  const [configForm, setConfigForm] = useState<RuleUpdateConfig>({
    remote_url: "",
    auto_update: false,
    update_interval_hours: 24,
    cache_dir: "",
  });
  const [downloadUrl, setDownloadUrl] = useState("");
  const [downloadPackId, setDownloadPackId] = useState("");

  const handleCheckUpdates = async () => {
    setCheckingUpdates(true);
    setUpdateResults([]);
    try {
      const results = await checkUpdates();
      const msgs = results.map((r) =>
        r.updated
          ? `${r.pack_id}: updated to v${r.new_version.major}.${r.new_version.minor}.${r.new_version.patch} (${r.downloaded_rules} rules)`
          : r.error
            ? `${r.pack_id}: ${r.error}`
            : `${r.pack_id}: already up to date`,
      );
      setUpdateResults(msgs);
    } finally {
      setCheckingUpdates(false);
    }
  };

  const handleSaveConfig = async () => {
    await updateConfig(configForm);
    setShowConfig(false);
  };

  const handleDownload = async () => {
    if (!downloadPackId.trim() || !downloadUrl.trim()) return;
    await downloadPack(downloadPackId.trim(), downloadUrl.trim());
    setDownloadPackId("");
    setDownloadUrl("");
  };

  return (
    <PageShell>
      <AnalysisHero
        icon={<Layers className="h-5 w-5" />}
        title="规则管理"
        subtitle="RULE MANAGEMENT"
        description="管理 YARA 检测规则包的版本、启用状态和更新"
        tags={["YARA", "规则", "版本", "更新"]}
        tagsLabel="规则域"
        theme="indigo"
        onRefresh={() => void fetchStatus()}
        refreshLabel="刷新状态"
      />

      <div className="space-y-6">
        {/* Action Bar */}
        <div className="flex items-center gap-4 flex-wrap">
          <Button
            size="sm"
            onClick={handleCheckUpdates}
            disabled={checkingUpdates}
            aria-label="检查规则更新"
          >
            <Download className={checkingUpdates ? "animate-spin" : ""} />
            检查更新
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (status?.update_config) setConfigForm(status.update_config);
              setShowConfig(!showConfig);
            }}
            aria-label={showConfig ? "收起更新配置" : "展开更新配置"}
          >
            <Settings />
            更新配置
          </Button>
          {status && (
            <div className="ml-auto flex items-center gap-4">
              <MetricCard
                label="规则总数"
                value={status.total_rules}
                icon={<Shield className="size-4" />}
                tone="indigo"
              />
              <MetricCard
                label="已启用"
                value={status.enabled_rules}
                icon={<Check className="size-4" />}
                tone="emerald"
              />
              <MetricCard
                label="已禁用"
                value={status.disabled_rules}
                icon={<X className="size-4" />}
                tone="slate"
              />
              {status.conflicts.length > 0 && (
                <MetricCard
                  label="冲突"
                  value={status.conflicts.length}
                  icon={<AlertTriangle className="size-4" />}
                  tone="rose"
                />
              )}
            </div>
          )}
        </div>

        {/* Error Display */}
        {error && <StatusHint tone="rose">{error}</StatusHint>}

        {/* Update Results */}
        {updateResults.length > 0 && (
          <StatusHint tone="blue">
            <div className="space-y-1">
              <div className="font-medium">更新检查结果:</div>
              {updateResults.map((msg, i) => (
                <div key={i}>{msg}</div>
              ))}
            </div>
          </StatusHint>
        )}

        {/* Config Panel */}
        {showConfig && (
          <SurfacePanel
            title="更新配置"
            icon={<Settings className="size-4" />}
            variant="section"
          >
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="config-remote-url" className="text-sm text-muted-foreground">
                  远程仓库 URL
                </label>
                <Input
                  id="config-remote-url"
                  type="text"
                  value={configForm.remote_url}
                  onChange={(e) => setConfigForm({ ...configForm, remote_url: e.target.value })}
                  className="mt-1"
                  placeholder="https://example.com/rules"
                />
              </div>
              <div>
                <label htmlFor="config-interval" className="text-sm text-muted-foreground">
                  更新间隔 (小时)
                </label>
                <Input
                  id="config-interval"
                  type="number"
                  value={configForm.update_interval_hours}
                  onChange={(e) =>
                    setConfigForm({
                      ...configForm,
                      update_interval_hours: parseInt(e.target.value) || 24,
                    })
                  }
                  className="mt-1"
                />
              </div>
              <div className="flex items-center gap-2 sm:col-span-2">
                <Button
                  type="button"
                  variant={configForm.auto_update ? "default" : "outline"}
                  size="sm"
                  onClick={() =>
                    setConfigForm({ ...configForm, auto_update: !configForm.auto_update })
                  }
                  aria-label={configForm.auto_update ? "关闭自动更新" : "开启自动更新"}
                  aria-pressed={configForm.auto_update}
                >
                  {configForm.auto_update ? "✓ 自动更新已开启" : "自动更新已关闭"}
                </Button>
              </div>
            </div>
            <div className="mt-4 flex gap-2">
              <Button
                size="sm"
                onClick={handleSaveConfig}
                aria-label="保存更新配置"
              >
                保存配置
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowConfig(false)}
                aria-label="取消配置编辑"
              >
                取消
              </Button>
            </div>
          </SurfacePanel>
        )}

        {/* Download Panel */}
        <SurfacePanel
          title="下载规则包"
          icon={<Download className="size-4" />}
          variant="section"
        >
          <div className="flex flex-col gap-4 sm:flex-row">
            <div className="flex-1">
              <label htmlFor="download-pack-id" className="text-sm text-muted-foreground">
                规则包 ID
              </label>
              <Input
                id="download-pack-id"
                type="text"
                value={downloadPackId}
                onChange={(e) => setDownloadPackId(e.target.value)}
                className="mt-1"
                placeholder="规则包 ID"
              />
            </div>
            <div className="flex-1">
              <label htmlFor="download-url" className="text-sm text-muted-foreground">
                下载 URL
              </label>
              <Input
                id="download-url"
                type="text"
                value={downloadUrl}
                onChange={(e) => setDownloadUrl(e.target.value)}
                className="mt-1"
                placeholder="下载 URL"
              />
            </div>
            <div className="flex items-end">
              <Button
                size="sm"
                onClick={handleDownload}
                disabled={!downloadPackId.trim() || !downloadUrl.trim()}
                aria-label="下载规则包"
              >
                下载
              </Button>
            </div>
          </div>
        </SurfacePanel>

        {/* Rule Packs */}
        <div className="space-y-3">
          <h3 className="text-sm font-medium">规则包列表</h3>
          {!status && loading && (
            <div className="py-8 text-center text-sm text-muted-foreground">加载中...</div>
          )}
          {status && status.packs.length === 0 && (
            <div className="py-8 text-center text-sm text-muted-foreground">暂无规则包</div>
          )}
          {status?.packs.map((pack) => (
            <RulePackCard key={pack.id} pack={pack} onToggle={togglePack} />
          ))}
        </div>

        {/* Conflicts */}
        {status && status.conflicts.length > 0 && (
          <div className="space-y-3">
            <h3 className="text-sm font-medium text-destructive">规则冲突</h3>
            {status.conflicts.map((conflict, i) => (
              <StatusHint key={i} tone="rose">
                <div>
                  <div className="font-medium">{conflict.conflict}</div>
                  <div className="mt-1 text-muted-foreground">
                    {conflict.rule_id_1} ({conflict.pack_id_1}) ↔ {conflict.rule_id_2} (
                    {conflict.pack_id_2})
                  </div>
                  <div className="mt-1 text-[10px] text-muted-foreground">
                    严重程度: {conflict.severity}
                  </div>
                </div>
              </StatusHint>
            ))}
          </div>
        )}
      </div>
    </PageShell>
  );
}

function RulePackCard({
  pack,
  onToggle,
}: {
  pack: RulePack;
  onToggle: (id: string, enabled: boolean) => void;
}) {
  const version = `v${pack.version.major}.${pack.version.minor}.${pack.version.patch}${pack.version.tag ? `-${pack.version.tag}` : ""}`;

  return (
    <div className="rounded-md border p-4">
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="font-medium">{pack.name}</span>
            <span className="rounded-full bg-muted px-2 py-0.5 text-xs">{version}</span>
            {pack.source === "embedded" && (
              <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs text-blue-700">
                内置
              </span>
            )}
          </div>
          {pack.description && (
            <div className="text-sm text-muted-foreground">{pack.description}</div>
          )}
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span>ID: {pack.id}</span>
            <span>规则数: {pack.rule_count}</span>
            {pack.checksum && <span>校验和: {pack.checksum.substring(0, 12)}...</span>}
            <span>更新: {new Date(pack.updated_at).toLocaleString()}</span>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => onToggle(pack.id, !pack.enabled)}
          aria-label={pack.enabled ? `禁用规则包 ${pack.name}` : `启用规则包 ${pack.name}`}
        >
          {pack.enabled ? "已启用" : "已禁用"}
        </Button>
      </div>
    </div>
  );
}
