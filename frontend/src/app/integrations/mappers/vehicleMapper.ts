import type { VehicleAnalysis } from "../../core/types";
import type { VehicleAnalysisWireDTO } from "../wire/vehicleWireDtos";
import { asInvestigationReport } from "./investigationReportMapper";
import { asArray, asBucket, asConversation, asPlainObject, asStringList } from "./mapperPrimitives";
import { asCANSection } from "./vehicleCanMapper";
import { asDoIPSection, asJ1939Section, asUDSSection } from "./vehicleDiagnosticMapper";

export function asVehicleAnalysis(input: unknown): VehicleAnalysis {
  const payload = asPlainObject(input) as VehicleAnalysisWireDTO | undefined;
  return {
    totalVehiclePackets: Number(payload?.total_vehicle_packets ?? 0),
    protocols: asArray(payload?.protocols).map(asBucket),
    conversations: asArray(payload?.conversations).map(asConversation),
    can: asCANSection(payload?.can),
    j1939: asJ1939Section(payload?.j1939),
    doip: asDoIPSection(payload?.doip),
    uds: asUDSSection(payload?.uds),
    recommendations: asStringList(payload?.recommendations),
    report: asInvestigationReport(payload?.report),
  };
}
