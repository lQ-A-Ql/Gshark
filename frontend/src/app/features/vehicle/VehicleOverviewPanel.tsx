import { Route } from "lucide-react";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisList as ConversationList,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../../components/analysis/AnalysisPrimitives";
import type { VehicleAnalysis } from "../../core/types";

export const VEHICLE_PROTOCOL_TAGS = ["CAN", "J1939", "DoIP", "UDS"];

export function VehicleOverviewPanel({ analysis }: { analysis: VehicleAnalysis }) {
  return (
    <>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="车载相关包" value={analysis.totalVehiclePackets.toLocaleString()} />
        <StatCard title="识别协议" value={String(analysis.protocols.length)} />
        <StatCard title="CAN 帧" value={analysis.can.totalFrames.toLocaleString()} />
        <StatCard title="DBC 解码报文" value={analysis.can.decodedMessages.length.toLocaleString()} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="车载协议分布">
          <BucketChart data={analysis.protocols} barClassName="bg-blue-500" maxHeightClassName="max-h-[320px]" />
        </Panel>
        <Panel title="网络 / 总线视图">
          <ConversationList
            items={analysis.conversations.map((item) => ({
              label: item.protocol ? `${item.protocol} · ${item.label}` : item.label,
              count: item.count,
            }))}
          />
        </Panel>
      </div>

      <Panel title="分析方案" className="mt-4">
        <div className="space-y-2 text-sm">
          <VehiclePlanItem>
            第一层先做总线基线：看 CAN ID、总线错误帧、J1939 PGN 分布，识别异常节点和异常广播。
          </VehiclePlanItem>
          <VehiclePlanItem>
            第二层做诊断链路：围绕 DoIP 寻址、UDS 会话切换、安全访问、刷写和例程调用，确认是否存在高风险诊断行为。
          </VehiclePlanItem>
          <VehiclePlanItem>
            第三层做安全专项：重点审计 SID 0x27、0x31、0x34、0x36、0x37 和负响应码，判断鉴权绕过、固件下发和诊断滥用。
          </VehiclePlanItem>
        </div>
      </Panel>
    </>
  );
}

function VehiclePlanItem({ children }: { children: string }) {
  return (
    <div className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
      <Route className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
      <span>{children}</span>
    </div>
  );
}
