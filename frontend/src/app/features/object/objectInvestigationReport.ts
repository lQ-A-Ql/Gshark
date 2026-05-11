import type { ExtractedObject, InvestigationReport } from "../../core/types";
import { classifyObject, magicGroupLabel } from "./objectExportRules";

export function buildObjectInvestigationReport(objects: ExtractedObject[]): InvestigationReport {
  const report: InvestigationReport = {
    summary: [],
    evidence: [],
    details: [],
    recommendations: [],
  };

  report.summary.push({
    title: "对象概览",
    summary: `共 ${objects.length} 个对象 / 类型 ${new Set(objects.map((item) => classifyObject(item).kind)).size} 类`,
    tags: ["object", "summary"],
  });

  const executableCount = objects.filter((item) => classifyObject(item).kind === "executable").length;
  const archiveCount = objects.filter((item) => classifyObject(item).kind === "archive").length;
  const documentCount = objects.filter((item) => classifyObject(item).kind === "document").length;
  report.summary.push({
    title: "高价值对象",
    summary: `可执行 ${executableCount} / 压缩 ${archiveCount} / 文档 ${documentCount}`,
    tags: ["object", "kind"],
  });

  for (const item of objects) {
    const meta = classifyObject(item);
    if (meta.kind === "executable") {
      report.evidence.push({
        title: `${item.name} 为可执行对象`,
        summary: `${item.mime} / ${item.magic || "无 magic"} / 来源 ${item.source}`,
        severity: "high",
        packetId: item.packetId,
        tags: ["object", "executable"],
      });
    } else if (meta.kind === "archive" || meta.kind === "document") {
      report.evidence.push({
        title: `${item.name} 为高价值文件对象`,
        summary: `${item.mime} / ${item.magic || "无 magic"} / 来源 ${item.source}`,
        severity: "medium",
        packetId: item.packetId,
        tags: ["object", meta.kind],
      });
    }
  }

  for (const item of objects.slice(0, 6)) {
    report.details.push({
      title: item.name,
      summary: `${magicGroupLabel(item)} / ${item.mime} / ${item.sizeBytes} bytes`,
      packetId: item.packetId,
      tags: ["object", classifyObject(item).kind],
    });
  }

  if (executableCount > 0) {
    report.recommendations.push("优先定位可执行对象对应的数据包，回到主工作区确认下载链、传输方向和上下文请求。");
  }
  if (archiveCount > 0 || documentCount > 0) {
    report.recommendations.push("对压缩包和文档类对象建议批量导出后结合 magic、扩展名和来源协议继续复核。");
  }
  if (objects.length === 0) {
    report.recommendations.push("当前尚未提取到对象文件，可先检查 HTTP/FTP 流量、压缩传输或 gzip 解包路径。");
  }

  return report;
}
