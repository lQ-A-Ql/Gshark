import type { VehicleAnalysis } from "../../core/types";
import { asBucket, asConversation, asStringList } from "./mapperPrimitives";
import { asCANSection } from "./vehicleCanMapper";
import { asDoIPSection, asJ1939Section, asUDSSection } from "./vehicleDiagnosticMapper";

export function asVehicleAnalysis(payload: any): VehicleAnalysis {
  return {
    totalVehiclePackets: Number(payload?.total_vehicle_packets ?? 0),
    protocols: Array.isArray(payload?.protocols) ? payload.protocols.map(asBucket) : [],
    conversations: Array.isArray(payload?.conversations) ? payload.conversations.map(asConversation) : [],
    can: asCANSection(payload?.can),
    j1939: asJ1939Section(payload?.j1939),
    doip: asDoIPSection(payload?.doip),
    uds: asUDSSection(payload?.uds),
    recommendations: asStringList(payload?.recommendations),
  };
}
