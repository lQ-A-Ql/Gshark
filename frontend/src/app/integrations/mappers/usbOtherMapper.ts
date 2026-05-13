import type { USBOtherAnalysis } from "../../core/types";
import { asArray, asBucket, asPlainObject, asStringList } from "./mapperPrimitives";
import { asUSBPacketRecord } from "./usbRecordMapper";

export function asUSBOtherAnalysis(input: unknown): USBOtherAnalysis {
  const payload = asPlainObject(input) ?? {};
  return {
    totalPackets: Number(payload.total_packets ?? 0),
    controlPackets: Number(payload.control_packets ?? 0),
    devices: asArray(payload.devices).map(asBucket),
    endpoints: asArray(payload.endpoints).map(asBucket),
    setupRequests: asArray(payload.setup_requests).map(asBucket),
    controlRecords: asArray(payload.control_records).map(asUSBPacketRecord),
    records: asArray(payload.records).map(asUSBPacketRecord),
    notes: asStringList(payload.notes),
  };
}
