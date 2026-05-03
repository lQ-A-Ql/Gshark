import type { TrafficBucket } from "./traffic";

export interface USBPacketRecord {
  packetId: number;
  time: string;
  protocol: string;
  busId: string;
  deviceAddress: string;
  endpoint: string;
  direction: string;
  transferType: string;
  urbType: string;
  status: string;
  dataLength: number;
  setupRequest?: string;
  payloadPreview?: string;
  summary: string;
}

export interface USBKeyboardEvent {
  packetId: number;
  time: string;
  device: string;
  endpoint: string;
  modifiers: string[];
  keys: string[];
  pressedModifiers: string[];
  releasedModifiers: string[];
  pressedKeys: string[];
  releasedKeys: string[];
  text?: string;
  summary: string;
}

export interface USBMouseEvent {
  packetId: number;
  time: string;
  device: string;
  endpoint: string;
  buttons: string[];
  pressedButtons: string[];
  releasedButtons: string[];
  xDelta: number;
  yDelta: number;
  wheelVertical: number;
  wheelHorizontal: number;
  positionX: number;
  positionY: number;
  summary: string;
}

export interface USBMassStorageOperation {
  packetId: number;
  time: string;
  device: string;
  endpoint: string;
  lun: string;
  command: string;
  operation: "read" | "write" | "other" | string;
  transferLength: number;
  direction: string;
  status: string;
  requestFrame?: number;
  responseFrame?: number;
  latencyMs?: number;
  summary?: string;
  rawRequest?: string;
  rawResponse?: string;
  dataResidue?: number;
  requestTags?: string[];
  responseTags?: string[];
  error?: string;
}

export interface USBHIDAnalysis {
  keyboardEvents: USBKeyboardEvent[];
  mouseEvents: USBMouseEvent[];
  devices: TrafficBucket[];
  notes: string[];
}

export interface USBMassStorageAnalysis {
  totalPackets: number;
  readPackets: number;
  writePackets: number;
  controlPackets: number;
  devices: TrafficBucket[];
  luns: TrafficBucket[];
  commands: TrafficBucket[];
  readOperations: USBMassStorageOperation[];
  writeOperations: USBMassStorageOperation[];
  notes: string[];
}

export interface USBOtherAnalysis {
  totalPackets: number;
  controlPackets: number;
  devices: TrafficBucket[];
  endpoints: TrafficBucket[];
  setupRequests: TrafficBucket[];
  controlRecords: USBPacketRecord[];
  records: USBPacketRecord[];
  notes: string[];
}

export interface USBAnalysis {
  totalUSBPackets: number;
  keyboardPackets: number;
  mousePackets: number;
  otherUSBPackets: number;
  hidPackets: number;
  massStoragePackets: number;
  protocols: TrafficBucket[];
  transferTypes: TrafficBucket[];
  directions: TrafficBucket[];
  devices: TrafficBucket[];
  endpoints: TrafficBucket[];
  setupRequests: TrafficBucket[];
  records: USBPacketRecord[];
  keyboardEvents: USBKeyboardEvent[];
  mouseEvents: USBMouseEvent[];
  otherRecords: USBPacketRecord[];
  hid: USBHIDAnalysis;
  massStorage: USBMassStorageAnalysis;
  other: USBOtherAnalysis;
  notes: string[];
}
