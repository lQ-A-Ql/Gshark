import type { USBAnalysis } from "../../core/types";
import { asInvestigationReport } from "./investigationReportMapper";
import { asArray, asBucket, asPlainObject, asStringList } from "./mapperPrimitives";
import { asUSBHidAnalysis, asUSBKeyboardEvent, asUSBMouseEvent } from "./usbHidMapper";
import { asUSBMassStorageAnalysis } from "./usbMassStorageMapper";
import { asUSBOtherAnalysis } from "./usbOtherMapper";
import { asUSBPacketRecord } from "./usbRecordMapper";

interface USBAnalysisWire extends Record<string, unknown> {
  total_usb_packets?: unknown;
  keyboard_packets?: unknown;
  mouse_packets?: unknown;
  other_usb_packets?: unknown;
  hid_packets?: unknown;
  mass_storage_packets?: unknown;
}

export function asUSBAnalysis(input: unknown): USBAnalysis {
  const payload = asPlainObject(input) as USBAnalysisWire | undefined;
  return {
    totalUSBPackets: Number(payload?.total_usb_packets ?? 0),
    keyboardPackets: Number(payload?.keyboard_packets ?? 0),
    mousePackets: Number(payload?.mouse_packets ?? 0),
    otherUSBPackets: Number(payload?.other_usb_packets ?? 0),
    hidPackets: Number(payload?.hid_packets ?? 0),
    massStoragePackets: Number(payload?.mass_storage_packets ?? 0),
    protocols: asArray(payload?.protocols).map(asBucket),
    transferTypes: asArray(payload?.transfer_types).map(asBucket),
    directions: asArray(payload?.directions).map(asBucket),
    devices: asArray(payload?.devices).map(asBucket),
    endpoints: asArray(payload?.endpoints).map(asBucket),
    setupRequests: asArray(payload?.setup_requests).map(asBucket),
    records: asArray(payload?.records).map(asUSBPacketRecord),
    keyboardEvents: asArray(payload?.keyboard_events).map(asUSBKeyboardEvent),
    mouseEvents: asArray(payload?.mouse_events).map(asUSBMouseEvent),
    otherRecords: asArray(payload?.other_records).map(asUSBPacketRecord),
    hid: asUSBHidAnalysis(payload?.hid),
    massStorage: asUSBMassStorageAnalysis(payload?.mass_storage),
    other: asUSBOtherAnalysis(payload?.other),
    notes: asStringList(payload?.notes),
    report: asInvestigationReport(payload?.report),
  };
}
