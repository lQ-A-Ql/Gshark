import type { AnalysisConversation, TrafficBucket } from "./traffic";

export interface ModbusBitRange {
  type?: string;
  start?: number;
  count?: number;
  values?: boolean[];
  preview?: string;
}

export interface ModbusTransaction {
  packetId: number;
  time: string;
  source: string;
  destination: string;
  transactionId: number;
  unitId: number;
  functionCode: number;
  functionName: string;
  kind: string;
  reference: string;
  quantity: string;
  exceptionCode: number;
  responseTime: string;
  registerValues?: string;
  bitRange?: ModbusBitRange;
  summary: string;
}

export interface ModbusAnalysis {
  totalFrames: number;
  requests: number;
  responses: number;
  exceptions: number;
  functionCodes: TrafficBucket[];
  unitIds: TrafficBucket[];
  referenceHits: TrafficBucket[];
  exceptionCodes: TrafficBucket[];
  transactions: ModbusTransaction[];
}

export interface IndustrialProtocolRecord {
  packetId: number;
  time: string;
  source: string;
  destination: string;
  operation: string;
  target?: string;
  result?: string;
  value?: string;
  summary: string;
}

export interface IndustrialProtocolDetail {
  name: string;
  totalFrames: number;
  operations: TrafficBucket[];
  targets: TrafficBucket[];
  results: TrafficBucket[];
  records: IndustrialProtocolRecord[];
}

export interface ModbusSuspiciousWrite {
  target: string;
  unitId: number;
  functionCode: number;
  functionName: string;
  writeCount: number;
  sources: string[];
  firstTime: string;
  lastTime: string;
  sampleValues: string[];
  samplePacketId: number;
}

export interface IndustrialControlCommand {
  packetId: number;
  time: string;
  protocol: string;
  source: string;
  destination: string;
  operation: string;
  target: string;
  value: string;
  result: string;
  summary: string;
}

export interface IndustrialRuleHit {
  rule: string;
  level: "critical" | "high" | "medium" | "low";
  packetId?: number;
  time?: string;
  source?: string;
  destination?: string;
  functionCode?: number;
  functionName?: string;
  target?: string;
  evidence?: string;
  summary: string;
}

export interface IndustrialAnalysis {
  totalIndustrialPackets: number;
  protocols: TrafficBucket[];
  conversations: AnalysisConversation[];
  modbus: ModbusAnalysis;
  suspiciousWrites?: ModbusSuspiciousWrite[];
  controlCommands?: IndustrialControlCommand[];
  ruleHits?: IndustrialRuleHit[];
  details: IndustrialProtocolDetail[];
  notes: string[];
}
