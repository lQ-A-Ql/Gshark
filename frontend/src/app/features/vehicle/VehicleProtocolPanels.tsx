import { ShieldAlert } from "lucide-react";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisMiniStat as MiniStat,
  AnalysisPanel as Panel,
} from "../../components/analysis/AnalysisPrimitives";
import type { VehicleAnalysis as VehicleAnalysisData } from "../../core/types";

interface VehicleProtocolPanelsProps {
  analysis: VehicleAnalysisData;
}

export function VehicleProtocolPanels({ analysis }: VehicleProtocolPanelsProps) {
  return (
    <>
      <div className="mt-0 grid grid-cols-1 gap-0 xl:grid-cols-2">
        <CanSummaryPanel analysis={analysis} />
        <J1939SummaryPanel analysis={analysis} />
      </div>

      <div className="mt-0 grid grid-cols-1 gap-0 xl:grid-cols-2">
        <DoipSummaryPanel analysis={analysis} />
        <UdsSummaryPanel analysis={analysis} />
      </div>

      <VehicleSecurityNotesPanel recommendations={analysis.recommendations} />
    </>
  );
}

function CanSummaryPanel({ analysis }: VehicleProtocolPanelsProps) {
  return (
    <Panel title="CAN 总线">
      <div className="mb-3 grid grid-cols-2 gap-0">
        <MiniStat title="扩展帧" value={analysis.can.extendedFrames} />
        <MiniStat title="错误帧" value={analysis.can.errorFrames} />
        <MiniStat title="RTR 帧" value={analysis.can.rtrFrames} />
        <MiniStat title="DBC 信号" value={analysis.can.decodedSignals.length} />
      </div>
      <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
        <BucketChart data={analysis.can.busIds} barClassName="bg-cyan-500" maxHeightClassName="max-h-[320px]" />
        <BucketChart data={analysis.can.messageIds} barClassName="bg-indigo-500" maxHeightClassName="max-h-[320px]" />
      </div>
    </Panel>
  );
}

function J1939SummaryPanel({ analysis }: VehicleProtocolPanelsProps) {
  return (
    <Panel title="J1939">
      <div className="mb-3 grid grid-cols-2 gap-0">
        <MiniStat title="消息数" value={analysis.j1939.totalMessages} />
        <MiniStat title="PGN 种类" value={analysis.j1939.pgns.length} />
        <MiniStat title="源地址种类" value={analysis.j1939.sourceAddrs.length} />
        <MiniStat title="目标地址种类" value={analysis.j1939.targetAddrs.length} />
      </div>
      <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
        <BucketChart data={analysis.j1939.pgns} barClassName="bg-emerald-500" maxHeightClassName="max-h-[320px]" />
        <BucketChart
          data={analysis.j1939.sourceAddrs}
          barClassName="bg-violet-500"
          maxHeightClassName="max-h-[320px]"
        />
      </div>
    </Panel>
  );
}

function DoipSummaryPanel({ analysis }: VehicleProtocolPanelsProps) {
  return (
    <Panel title="DoIP">
      <div className="mb-3 grid grid-cols-2 gap-0">
        <MiniStat title="消息数" value={analysis.doip.totalMessages} />
        <MiniStat title="VIN" value={analysis.doip.vins.length} />
        <MiniStat title="消息类型" value={analysis.doip.messageTypes.length} />
        <MiniStat title="逻辑地址" value={analysis.doip.endpoints.length} />
      </div>
      <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
        <BucketChart data={analysis.doip.messageTypes} barClassName="bg-sky-500" maxHeightClassName="max-h-[320px]" />
        <BucketChart data={analysis.doip.vins} barClassName="bg-fuchsia-500" maxHeightClassName="max-h-[320px]" />
      </div>
    </Panel>
  );
}

function UdsSummaryPanel({ analysis }: VehicleProtocolPanelsProps) {
  return (
    <Panel title="UDS">
      <div className="mb-3 grid grid-cols-2 gap-0">
        <MiniStat title="消息数" value={analysis.uds.totalMessages} />
        <MiniStat title="服务数" value={analysis.uds.serviceIDs.length} />
        <MiniStat title="负响应码" value={analysis.uds.negativeCodes.length} />
        <MiniStat title="DTC 数" value={analysis.uds.dtcs.length} />
      </div>
      <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
        <BucketChart data={analysis.uds.serviceIDs} barClassName="bg-orange-500" maxHeightClassName="max-h-[320px]" />
        <BucketChart data={analysis.uds.negativeCodes} barClassName="bg-rose-500" maxHeightClassName="max-h-[320px]" />
      </div>
    </Panel>
  );
}

function VehicleSecurityNotesPanel({ recommendations }: { recommendations: string[] }) {
  return (
    <Panel title="安全提示" className="mt-0">
      <div className="space-y-2 text-sm">
        {recommendations.length === 0 ? (
          <div className="px-3 py-3 text-muted-foreground">
            当前抓包未识别到车载协议。
          </div>
        ) : (
          recommendations.map((note, index) => (
            <div
              key={`${note}-${index}`}
              className="gshark-soft-fill flex items-start gap-2 px-3 py-2"
            >
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
              <span>{note}</span>
            </div>
          ))
        )}
      </div>
    </Panel>
  );
}
