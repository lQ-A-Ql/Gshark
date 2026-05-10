import type { USBOtherAnalysis } from "../../core/types";
import { asBucket, asStringList } from "./mapperPrimitives";
import { asUSBPacketRecord } from "./usbRecordMapper";

export function asUSBOtherAnalysis(payload: any): USBOtherAnalysis {
  return {
    totalPackets: Number(payload?.total_packets ?? 0),
    controlPackets: Number(payload?.control_packets ?? 0),
    devices: Array.isArray(payload?.devices) ? payload.devices.map(asBucket) : [],
    endpoints: Array.isArray(payload?.endpoints) ? payload.endpoints.map(asBucket) : [],
    setupRequests: Array.isArray(payload?.setup_requests) ? payload.setup_requests.map(asBucket) : [],
    controlRecords: Array.isArray(payload?.control_records) ? payload.control_records.map(asUSBPacketRecord) : [],
    records: Array.isArray(payload?.records) ? payload.records.map(asUSBPacketRecord) : [],
    notes: asStringList(payload?.notes),
  };
}
