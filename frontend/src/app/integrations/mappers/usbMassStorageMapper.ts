import type { USBMassStorageAnalysis, USBMassStorageOperation } from "../../core/types";
import { asBucket, asStringList } from "./mapperPrimitives";

export function asUSBMassStorageOperation(item: any): USBMassStorageOperation {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    device: String(item.device ?? ""),
    endpoint: String(item.endpoint ?? ""),
    lun: String(item.lun ?? ""),
    command: String(item.command ?? ""),
    operation: String(item.operation ?? "other"),
    transferLength: Number(item.transfer_length ?? 0),
    direction: String(item.direction ?? ""),
    status: String(item.status ?? ""),
    requestFrame: item.request_frame == null ? undefined : Number(item.request_frame),
    responseFrame: item.response_frame == null ? undefined : Number(item.response_frame),
    latencyMs: item.latency_ms == null ? undefined : Number(item.latency_ms),
    dataResidue: item.data_residue == null ? undefined : Number(item.data_residue),
    summary: String(item.summary ?? ""),
  };
}

export function asUSBMassStorageAnalysis(payload: any): USBMassStorageAnalysis {
  return {
    totalPackets: Number(payload?.total_packets ?? 0),
    readPackets: Number(payload?.read_packets ?? 0),
    writePackets: Number(payload?.write_packets ?? 0),
    controlPackets: Number(payload?.control_packets ?? 0),
    devices: Array.isArray(payload?.devices) ? payload.devices.map(asBucket) : [],
    luns: Array.isArray(payload?.luns) ? payload.luns.map(asBucket) : [],
    commands: Array.isArray(payload?.commands) ? payload.commands.map(asBucket) : [],
    readOperations: Array.isArray(payload?.read_operations)
      ? payload.read_operations.map(asUSBMassStorageOperation)
      : [],
    writeOperations: Array.isArray(payload?.write_operations)
      ? payload.write_operations.map(asUSBMassStorageOperation)
      : [],
    notes: asStringList(payload?.notes),
  };
}
