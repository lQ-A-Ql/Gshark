import type { AnalysisTone } from "../../components/analysis/AnalysisPrimitives";
import type { Dnp3SectionRow } from "./industrialDnp3SectionModel";

export function toneForIndustrialRuleLevel(level: string): AnalysisTone {
  switch (String(level ?? "").toLowerCase()) {
    case "critical":
    case "high":
      return "rose";
    case "warning":
      return "amber";
    default:
      return "blue";
  }
}

export function toneForDnp3Source(sourceType: Dnp3SectionRow["sourceType"]): AnalysisTone {
  switch (sourceType) {
    case "command":
      return "rose";
    case "rule":
      return "amber";
    default:
      return "blue";
  }
}
