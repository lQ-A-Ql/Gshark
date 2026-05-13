import type { USBMassStorageAnalysis, USBMassStorageOperation } from "../../core/types";
import { asArray, asBucket, asPlainObject, asStringList } from "./mapperPrimitives";

export function asUSBMassStorageOperation(input: unknown): USBMassStorageOperation {
  const item = asPlainObject(input) ?? {};
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

export function asUSBMassStorageAnalysis(input: unknown): USBMassStorageAnalysis {
  const payload = asPlainObject(input) ?? {};
  return {
    totalPackets: Number(payload.total_packets ?? 0),
    readPackets: Number(payload.read_packets ?? 0),
    writePackets: Number(payload.write_packets ?? 0),
    controlPackets: Number(payload.control_packets ?? 0),
    devices: asArray(payload.devices).map(asBucket),
    luns: asArray(payload.luns).map(asBucket),
    commands: asArray(payload.commands).map(asBucket),
    readOperations: asArray(payload.read_operations).map(asUSBMassStorageOperation),
    writeOperations: asArray(payload.write_operations).map(asUSBMassStorageOperation),
    notes: asStringList(payload.notes),
  };
}
