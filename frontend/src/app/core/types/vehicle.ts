import type { AnalysisConversation, TrafficBucket } from "./traffic";

export interface CANFrameSummary {
  packetId: number;
  time: string;
  identifier: string;
  busId: string;
  length: number;
  rawData?: string;
  isExtended: boolean;
  isRTR: boolean;
  isError: boolean;
  errorFlags?: string;
  summary: string;
}

export interface CANPayloadRecord {
  packetId: number;
  time: string;
  busId: string;
  identifier: string;
  protocol: string;
  frameType?: string;
  sourceAddress?: string;
  targetAddress?: string;
  service?: string;
  detail?: string;
  length: number;
  rawData?: string;
  summary: string;
}

export interface DBCProfile {
  path: string;
  name: string;
  messageCount: number;
  signalCount: number;
}

export interface CANDBCSignal {
  name: string;
  value: string;
  unit?: string;
}

export interface CANDBCMessage {
  packetId: number;
  time: string;
  busId: string;
  identifier: string;
  database: string;
  messageName: string;
  sender?: string;
  signals: CANDBCSignal[];
  summary: string;
}

export interface CANSignalSample {
  packetId: number;
  time: string;
  value: number;
  unit?: string;
  messageName?: string;
}

export interface CANSignalTimeline {
  name: string;
  samples: CANSignalSample[];
}

export interface J1939MessageSummary {
  packetId: number;
  time: string;
  canId: string;
  pgn: string;
  priority: number;
  sourceAddr: string;
  targetAddr: string;
  dataPreview?: string;
  summary: string;
}

export interface DoIPMessageSummary {
  packetId: number;
  time: string;
  source: string;
  destination: string;
  type: string;
  vin?: string;
  logicalAddress?: string;
  sourceAddress?: string;
  targetAddress?: string;
  testerAddress?: string;
  responseCode?: string;
  diagnosticState?: string;
  summary: string;
}

export interface UDSMessageSummary {
  packetId: number;
  time: string;
  serviceId: string;
  serviceName: string;
  isReply: boolean;
  subFunction?: string;
  sourceAddress?: string;
  targetAddress?: string;
  dataIdentifier?: string;
  diagnosticVIN?: string;
  dtc?: string;
  negativeCode?: string;
  summary: string;
}

export interface UDSTransaction {
  requestPacketId: number;
  responsePacketId?: number;
  requestTime: string;
  responseTime?: string;
  sourceAddress?: string;
  targetAddress?: string;
  serviceId: string;
  serviceName: string;
  subFunction?: string;
  dataIdentifier?: string;
  dtc?: string;
  status: string;
  negativeCode?: string;
  latencyMs?: number;
  requestSummary?: string;
  responseSummary?: string;
}

export interface CANAnalysis {
  totalFrames: number;
  extendedFrames: number;
  rtrFrames: number;
  errorFrames: number;
  busIds: TrafficBucket[];
  messageIds: TrafficBucket[];
  payloadProtocols: TrafficBucket[];
  payloadRecords: CANPayloadRecord[];
  dbcProfiles: DBCProfile[];
  decodedMessageDist: TrafficBucket[];
  decodedSignals: TrafficBucket[];
  decodedMessages: CANDBCMessage[];
  signalTimelines: CANSignalTimeline[];
  frames: CANFrameSummary[];
}

export interface J1939Analysis {
  totalMessages: number;
  pgns: TrafficBucket[];
  sourceAddrs: TrafficBucket[];
  targetAddrs: TrafficBucket[];
  messages: J1939MessageSummary[];
}

export interface DoIPAnalysis {
  totalMessages: number;
  messageTypes: TrafficBucket[];
  vins: TrafficBucket[];
  endpoints: TrafficBucket[];
  messages: DoIPMessageSummary[];
}

export interface UDSAnalysis {
  totalMessages: number;
  serviceIDs: TrafficBucket[];
  negativeCodes: TrafficBucket[];
  dtcs: TrafficBucket[];
  vins: TrafficBucket[];
  messages: UDSMessageSummary[];
  transactions: UDSTransaction[];
}

export interface VehicleAnalysis {
  totalVehiclePackets: number;
  protocols: TrafficBucket[];
  conversations: AnalysisConversation[];
  can: CANAnalysis;
  j1939: J1939Analysis;
  doip: DoIPAnalysis;
  uds: UDSAnalysis;
  recommendations: string[];
}
