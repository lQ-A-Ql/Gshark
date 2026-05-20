import { FolderOpen, Trash2 } from "lucide-react";
import { AnalysisPanel as Panel } from "../../components/analysis/AnalysisPrimitives";
import type { DBCProfile } from "../../core/types";

interface VehicleDbcPanelProps {
  profiles: DBCProfile[];
  pathInput: string;
  onPathInputChange: (value: string) => void;
  onImport: () => void;
  onAddPath: () => void;
  onRemove: (path: string) => void;
}

export function VehicleDbcPanel({
  profiles,
  pathInput,
  onPathInputChange,
  onImport,
  onAddPath,
  onRemove,
}: VehicleDbcPanelProps) {
  return (
    <Panel title="DBC 映射" className="mb-0">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <button className="gshark-control inline-flex items-center gap-1 px-3 py-2 text-xs" onClick={onImport}>
            <FolderOpen className="h-4 w-4" />
            导入 DBC
          </button>
          <input
            value={pathInput}
            onChange={(event) => onPathInputChange(event.target.value)}
            placeholder="或直接输入 DBC 文件路径"
            className="gshark-field min-w-[320px] flex-1 px-3 py-2 text-xs outline-none"
          />
          <button className="gshark-control px-3 py-2 text-xs" onClick={onAddPath}>
            添加路径
          </button>
        </div>
        {profiles.length === 0 ? (
          <div className="px-3 py-3 text-xs text-muted-foreground">
            当前未加载 DBC。导入后，CAN 报文会尝试直接映射为报文名和信号值。
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-2 xl:grid-cols-2">
            {profiles.map((profile) => (
              <div key={profile.path} className="gshark-soft-fill flex items-start justify-between px-3 py-3 text-xs">
                <div className="min-w-0">
                  <div className="font-medium text-foreground">{profile.name}</div>
                  <div className="truncate text-muted-foreground" title={profile.path}>
                    {profile.path}
                  </div>
                  <div className="mt-1 text-muted-foreground">
                    报文 {profile.messageCount} / 信号 {profile.signalCount}
                  </div>
                </div>
                <button
                  className="gshark-control-ghost ml-3 p-2 text-muted-foreground hover:text-foreground"
                  onClick={() => onRemove(profile.path)}
                  title="移除 DBC"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}
