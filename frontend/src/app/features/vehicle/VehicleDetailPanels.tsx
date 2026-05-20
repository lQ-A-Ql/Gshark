import {
  AnalysisBucketChart as BucketChart,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
} from "../../components/analysis/AnalysisPrimitives";
import type { VehicleAnalysis as VehicleAnalysisData } from "../../core/types";
import { CanIdDataBoard, buildCanIdDataGroups } from "./VehicleCanDataBoard";

interface VehicleDetailPanelsProps {
  analysis: VehicleAnalysisData;
}

export function VehicleDetailPanels({ analysis }: VehicleDetailPanelsProps) {
  const canIdDataGroups = buildCanIdDataGroups(analysis);

  return (
    <>
      <Panel title={`CAN 明细预览 (${analysis.can.frames.length} / ${analysis.can.totalFrames})`} className="mt-0">
        <DataTable
          headers={["包号", "时间", "Bus", "ID", "长度", "标志", "摘要"]}
          rows={analysis.can.frames.map((item) => [
            item.packetId,
            item.time || "--",
            item.busId || "--",
            item.identifier || "--",
            item.length || 0,
            [item.isExtended ? "XTD" : "", item.isRTR ? "RTR" : "", item.isError ? item.errorFlags || "ERR" : ""]
              .filter(Boolean)
              .join(" / ") || "--",
            item.summary || "--",
          ])}
        />
      </Panel>

      <div className="mt-0 grid grid-cols-1 gap-0 xl:grid-cols-2">
        <Panel title="CAN Payload 协议分布">
          <BucketChart
            data={analysis.can.payloadProtocols}
            barClassName="bg-amber-500"
            maxHeightClassName="max-h-[320px]"
          />
        </Panel>
        <Panel title={`CAN Payload 明细预览 (${analysis.can.payloadRecords.length})`}>
          <DataTable
            headers={["包号", "时间", "Bus", "ID", "协议", "帧类型", "地址", "服务", "细节", "长度", "摘要"]}
            rows={analysis.can.payloadRecords.map((item) => [
              item.packetId,
              item.time || "--",
              item.busId || "--",
              item.identifier || "--",
              item.protocol || "--",
              item.frameType || "--",
              [item.sourceAddress, item.targetAddress].filter(Boolean).join(" -> ") || "--",
              item.service || "--",
              item.detail || item.rawData || "--",
              item.length || 0,
              item.summary || "--",
            ])}
          />
        </Panel>
      </div>

      <Panel title={`CAN ID 数据区域 (${canIdDataGroups.length})`} className="mt-0">
        <CanIdDataBoard groups={canIdDataGroups} />
      </Panel>

      <VehicleDbcDetailPanels analysis={analysis} />
      <VehicleDiagnosticDetailPanels analysis={analysis} />
    </>
  );
}

function VehicleDbcDetailPanels({ analysis }: VehicleDetailPanelsProps) {
  return (
    <>
      <div className="mt-0 grid grid-cols-1 gap-0 xl:grid-cols-2">
        <Panel title="DBC 报文分布">
          <BucketChart
            data={analysis.can.decodedMessageDist}
            barClassName="bg-emerald-500"
            maxHeightClassName="max-h-[320px]"
          />
        </Panel>
        <Panel title="DBC 信号分布">
          <BucketChart
            data={analysis.can.decodedSignals}
            barClassName="bg-violet-500"
            maxHeightClassName="max-h-[320px]"
          />
        </Panel>
      </div>

      <Panel title={`DBC 解码明细预览 (${analysis.can.decodedMessages.length})`} className="mt-0">
        <DataTable
          headers={["包号", "时间", "Bus", "ID", "数据库", "报文", "发送方", "信号", "摘要"]}
          rows={analysis.can.decodedMessages.map((item) => [
            item.packetId,
            item.time || "--",
            item.busId || "--",
            item.identifier || "--",
            item.database || "--",
            item.messageName || "--",
            item.sender || "--",
            item.signals
              .map((signal) => `${signal.name}=${signal.value}${signal.unit ? ` ${signal.unit}` : ""}`)
              .join(" ; ") || "--",
            item.summary || "--",
          ])}
        />
      </Panel>

      <Panel title={`DBC 信号时间线 (${analysis.can.signalTimelines.length})`} className="mt-0">
        <DataTable
          headers={["信号", "样本数", "最新值", "最小值", "最大值", "单位", "最近报文"]}
          rows={analysis.can.signalTimelines.map((timeline) => {
            const values = timeline.samples.map((sample) => sample.value);
            const latest = timeline.samples[timeline.samples.length - 1];
            const min = Math.min(...values);
            const max = Math.max(...values);
            return [
              timeline.name,
              timeline.samples.length,
              latest ? latest.value : "--",
              Number.isFinite(min) ? min : "--",
              Number.isFinite(max) ? max : "--",
              latest?.unit || "--",
              latest?.messageName || "--",
            ];
          })}
        />
      </Panel>
    </>
  );
}

function VehicleDiagnosticDetailPanels({ analysis }: VehicleDetailPanelsProps) {
  return (
    <div className="mt-0 grid grid-cols-1 gap-0 xl:grid-cols-2">
      <Panel title={`DoIP 明细预览 (${analysis.doip.messages.length} / ${analysis.doip.totalMessages})`}>
        <DataTable
          headers={["包号", "时间", "源", "目标", "类型", "VIN", "状态", "摘要"]}
          rows={analysis.doip.messages.map((item) => [
            item.packetId,
            item.time || "--",
            item.source || "--",
            item.destination || "--",
            item.type || "--",
            item.vin || "--",
            item.responseCode || item.diagnosticState || "--",
            item.summary || "--",
          ])}
        />
      </Panel>
      <Panel title={`UDS 明细预览 (${analysis.uds.messages.length} / ${analysis.uds.totalMessages})`}>
        <DataTable
          headers={["包号", "时间", "SID", "名称", "源", "目标", "DID/DTC", "摘要"]}
          rows={analysis.uds.messages.map((item) => [
            item.packetId,
            item.time || "--",
            item.serviceId || "--",
            item.serviceName || "--",
            item.sourceAddress || "--",
            item.targetAddress || "--",
            item.dataIdentifier || item.dtc || item.negativeCode || "--",
            item.summary || "--",
          ])}
        />
      </Panel>
    </div>
  );
}
