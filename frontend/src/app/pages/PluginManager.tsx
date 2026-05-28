import { Puzzle } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { PluginManagerShell } from "../features/plugin/PluginManagerShell";
import { PluginSourceEditor } from "../features/plugin/PluginSourceEditor";
import { usePluginManager } from "../features/plugin/usePluginManager";

export default function PluginManager() {
  const pm = usePluginManager();

  return (
    <PageShell>
      <AnalysisHero
        icon={<Puzzle className="h-5 w-5" />}
        title="插件管理"
        subtitle="PLUGIN MANAGER"
        description="管理自定义检测插件，支持 JavaScript 和 Python 运行时。插件可在包扫描阶段执行自定义威胁检测逻辑。"
        tags={["自定义规则", "JS/Python", "包扫描", "威胁检测"]}
        theme="indigo"
        onRefresh={() => void pm.refreshPlugins()}
      />
      <PluginManagerShell
        plugins={pm.plugins}
        loading={pm.loading}
        error={pm.error}
        onAdd={pm.addPlugin}
        onDelete={pm.deletePlugin}
        onToggle={pm.togglePlugin}
        onBulkToggle={pm.bulkToggle}
        onOpenSource={pm.openSource}
      />
      {pm.sourcePlugin && (
        <PluginSourceEditor
          source={pm.sourcePlugin}
          loading={pm.sourceLoading}
          onSave={pm.saveSource}
          onClose={pm.closeSource}
        />
      )}
    </PageShell>
  );
}
