import { FolderCog, MicVocal } from "lucide-react";

import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import { RuntimeDependencyCard } from "./RuntimeDependencyCard";

type Props = {
  form: ToolRuntimeConfig;
  snapshot?: ToolRuntimeSnapshot | null;
  speechIssues: string[];
};

export function SpeechDependencyDetails({ form, snapshot, speechIssues }: Props) {
  return (
    <>
      {speechIssues.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {speechIssues.map((issue) => (
            <span
              key={issue}
              className="rounded-full border border-rose-200 bg-rose-50 px-2.5 py-1 text-[11px] font-medium text-rose-700"
            >
              缺少：{issue}
            </span>
          ))}
        </div>
      ) : null}
      <div className="grid grid-cols-2 gap-2">
        <RuntimeDependencyCard
          label="Python"
          Icon={FolderCog}
          available={snapshot?.speech.pythonAvailable ?? false}
          known={Boolean(snapshot)}
          value={snapshot?.speech.pythonCommand || "等待检测"}
        />
        <RuntimeDependencyCard
          label="Vosk 模型"
          Icon={MicVocal}
          available={snapshot?.speech.modelAvailable ?? false}
          known={Boolean(snapshot)}
          value={snapshot?.speech.modelPath || form.voskModelPath || "等待检测"}
        />
      </div>
    </>
  );
}
