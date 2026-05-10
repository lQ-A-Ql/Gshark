import type { USBAnalysis } from "../../core/types";
import { asBucket, asStringList } from "./mapperPrimitives";
import { asUSBHidAnalysis, asUSBKeyboardEvent, asUSBMouseEvent } from "./usbHidMapper";
import { asUSBMassStorageAnalysis } from "./usbMassStorageMapper";
import { asUSBOtherAnalysis } from "./usbOtherMapper";
import { asUSBPacketRecord } from "./usbRecordMapper";

export function asUSBAnalysis(payload: any): USBAnalysis {
  return {
    totalUSBPackets: Number(payload?.total_usb_packets ?? 0),
    keyboardPackets: Number(payload?.keyboard_packets ?? 0),
    mousePackets: Number(payload?.mouse_packets ?? 0),
    otherUSBPackets: Number(payload?.other_usb_packets ?? 0),
    hidPackets: Number(payload?.hid_packets ?? 0),
    massStoragePackets: Number(payload?.mass_storage_packets ?? 0),
    protocols: Array.isArray(payload?.protocols) ? payload.protocols.map(asBucket) : [],
    transferTypes: Array.isArray(payload?.transfer_types) ? payload.transfer_types.map(asBucket) : [],
    directions: Array.isArray(payload?.directions) ? payload.directions.map(asBucket) : [],
    devices: Array.isArray(payload?.devices) ? payload.devices.map(asBucket) : [],
    endpoints: Array.isArray(payload?.endpoints) ? payload.endpoints.map(asBucket) : [],
    setupRequests: Array.isArray(payload?.setup_requests) ? payload.setup_requests.map(asBucket) : [],
    records: Array.isArray(payload?.records) ? payload.records.map(asUSBPacketRecord) : [],
    keyboardEvents: Array.isArray(payload?.keyboard_events) ? payload.keyboard_events.map(asUSBKeyboardEvent) : [],
    mouseEvents: Array.isArray(payload?.mouse_events) ? payload.mouse_events.map(asUSBMouseEvent) : [],
    otherRecords: Array.isArray(payload?.other_records) ? payload.other_records.map(asUSBPacketRecord) : [],
    hid: asUSBHidAnalysis(payload?.hid),
    massStorage: asUSBMassStorageAnalysis(payload?.mass_storage),
    other: asUSBOtherAnalysis(payload?.other),
    notes: asStringList(payload?.notes),
  };
}
