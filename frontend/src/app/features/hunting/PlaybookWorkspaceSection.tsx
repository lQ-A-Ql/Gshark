import { BookOpen, Lightbulb, RefreshCw, SearchCheck, Workflow } from "lucide-react";
import { useMemo } from "react";
import { SurfacePanel, StatusHint, EmptyState } from "../../components/DesignSystem";
import { Button } from "../../components/ui/button";
import { PlaybookDetailPanel, PlaybookListPanel, SavedSearchPanel, HypothesisPanel } from "./PlaybookPanels";
import { usePlaybookManagement } from "./usePlaybookManagement";

interface PlaybookWorkspaceSectionProps {
  backendConnected: boolean;
}

export function PlaybookWorkspaceSection({ backendConnected }: PlaybookWorkspaceSectionProps) {
  const {
    playbooks,
    playbooksLoading,
    playbooksError,
    selectedPlaybook,
    playbookRunning,
    lastRunResult,
    setSelectedPlaybook,
    runPlaybook,
    deletePlaybook,
    savedSearches,
    savedSearchesLoading,
    savedSearchesError,
    executeSavedSearch,
    deleteSavedSearch,
    hypotheses,
    hypothesesLoading,
    hypothesesError,
    updateHypothesisStatus,
    refreshAll,
    statusText,
  } = usePlaybookManagement({ backendConnected });

  const selectedPlaybookRecord = useMemo(
    () => playbooks.find((playbook) => playbook.id === selectedPlaybook) ?? playbooks[0] ?? null,
    [playbooks, selectedPlaybook],
  );

  return (
    <SurfacePanel
      title="狩猎剧本工作区"
      description="把剧本、保存的搜索和调查假设嵌入威胁狩猎页面，在不离开现有工作台的前提下完成关联分析。"
      icon={<Workflow className="size-4" />}
      variant="page"
      actions={
        <Button
          variant="outline"
          size="sm"
          onClick={() => void refreshAll()}
          disabled={!backendConnected}
          aria-label="刷新狩猎剧本工作区"
        >
          <RefreshCw className="size-4" />
          刷新工作区
        </Button>
      }
    >
      {!backendConnected ? (
        <StatusHint tone="amber">后端未连接，狩猎剧本工作区暂不可用。</StatusHint>
      ) : null}
      {backendConnected && statusText ? <StatusHint tone="blue">{statusText}</StatusHint> : null}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1.4fr)_minmax(18rem,0.95fr)]">
        <SurfacePanel title="剧本列表" icon={<BookOpen className="size-4" />} variant="section" bodyClassName="space-y-3">
          {playbooksError ? <StatusHint tone="rose">Playbook 区域不可用: {playbooksError}</StatusHint> : null}
          {playbooksLoading ? (
            <EmptyState>正在加载剧本...</EmptyState>
          ) : (
            <PlaybookListPanel
              playbooks={playbooks}
              selected={selectedPlaybookRecord?.id ?? null}
              running={playbookRunning}
              onSelect={setSelectedPlaybook}
              onRun={(id) => void runPlaybook(id)}
              onDelete={(id) => void deletePlaybook(id)}
            />
          )}
        </SurfacePanel>

        <SurfacePanel title="剧本详情" icon={<Workflow className="size-4" />} variant="section">
          {selectedPlaybookRecord ? (
            <PlaybookDetailPanel
              playbook={selectedPlaybookRecord}
              lastRun={lastRunResult}
              running={playbookRunning}
              onRun={(id) => void runPlaybook(id)}
            />
          ) : (
            <EmptyState>选择一个剧本后可在这里查看步骤与最近一次执行结果。</EmptyState>
          )}
        </SurfacePanel>

        <div className="grid gap-4">
          <SurfacePanel title="保存的搜索" icon={<SearchCheck className="size-4" />} variant="section" bodyClassName="space-y-3">
            {savedSearchesError ? <StatusHint tone="rose">Playbook 保存的搜索不可用: {savedSearchesError}</StatusHint> : null}
            {savedSearchesLoading ? (
              <EmptyState>正在加载保存的搜索...</EmptyState>
            ) : (
              <SavedSearchPanel
                searches={savedSearches}
                onExecute={(id) => void executeSavedSearch(id)}
                onDelete={(id) => void deleteSavedSearch(id)}
              />
            )}
          </SurfacePanel>

          <SurfacePanel title="调查假设" icon={<Lightbulb className="size-4" />} variant="section" bodyClassName="space-y-3">
            {hypothesesError ? <StatusHint tone="rose">调查假设区域不可用: {hypothesesError}</StatusHint> : null}
            {hypothesesLoading ? (
              <EmptyState>正在加载调查假设...</EmptyState>
            ) : (
              <HypothesisPanel
                hypotheses={hypotheses}
                onUpdateStatus={(id, status) => void updateHypothesisStatus(id, status)}
              />
            )}
          </SurfacePanel>
        </div>
      </div>
    </SurfacePanel>
  );
}
