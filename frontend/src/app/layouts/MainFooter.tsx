import { Activity, Box, KeyRound } from "lucide-react";
import { cn } from "../components/ui/utils";
import { formatBytes } from "../state/formatBytes";
import type { MainLayoutChromeProps } from "./mainLayoutChromeTypes";

export function MainFooter({
  backendConnected,
  backendStatus,
  decryptionConfigured,
  fileMeta,
  filteredPacketCount,
  packets,
  totalPackets,
}: Pick<
  MainLayoutChromeProps,
  | "backendConnected"
  | "backendStatus"
  | "decryptionConfigured"
  | "fileMeta"
  | "filteredPacketCount"
  | "packets"
  | "totalPackets"
>) {
  return (
    <footer className="z-40 flex h-8 shrink-0 items-center justify-between border-t border-white/16 bg-white/36 px-4 text-[11px] font-medium tracking-wider text-slate-500 backdrop-blur-xl">
      <div className="flex items-center gap-4">
        <span className="flex items-center gap-1">
          <Box className="h-3.5 w-3.5" /> 当前: {fileMeta.name} ({formatBytes(fileMeta.sizeBytes)})
        </span>
        <span className="flex items-center gap-1 text-blue-600">
          显示: {filteredPacketCount.toLocaleString()} / 缓存: {packets.length.toLocaleString()} / 后端总计:{" "}
          {totalPackets.toLocaleString()}
        </span>
      </div>
      <div className="flex items-center gap-4">
        <span className="flex items-center gap-1 text-amber-600">
          <KeyRound className="h-3.5 w-3.5" /> TLS 解密: {decryptionConfigured ? "SSLKEYLOGFILE 已加载" : "未配置"}
        </span>
        <span
          className={cn("flex items-center gap-1", backendConnected ? "text-emerald-600" : "text-muted-foreground")}
        >
          <Activity className="h-3.5 w-3.5" /> 引擎: {backendStatus}
        </span>
      </div>
    </footer>
  );
}
