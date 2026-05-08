import type { WinRMDecryptResult } from "../../core/types";
import { MetaChip } from "../ui";

interface WinRMResultSummaryProps {
  result: WinRMDecryptResult;
}

export function WinRMResultSummary({ result }: WinRMResultSummaryProps) {
  return (
    <div className="mt-4 animate-in slide-in-from-bottom-2 duration-300 fade-in">
      <div className="flex flex-wrap gap-2 rounded-xl border border-sky-100 bg-sky-50/50 p-4 text-[11px] shadow-sm">
        <MetaChip label="抓包" value={result.captureName} />
        <MetaChip label="Port" value={result.port} />
        <MetaChip label="Mode" value={result.authMode} />
        <MetaChip label="总帧" value={result.frameCount} />
        <MetaChip label="解密失败" value={result.errorFrameCount} color="rose" />
        <MetaChip label="含Payload帧" value={result.extractedFrameCount} color="sky" />
        <MetaChip label="输出行数" value={result.lineCount} color="emerald" />
      </div>
    </div>
  );
}
