export type Protocol = "TCP" | "UDP" | "HTTP" | "HTTPS" | "DNS" | "SSHv2" | "TLS" | "ARP" | "ICMP" | "ICMPV6" | "OTHER";

export interface PacketColorFeatures {
  tcpAnalysisFlags?: boolean;
  tcpWindowUpdate?: boolean;
  tcpKeepAlive?: boolean;
  tcpKeepAliveAck?: boolean;
  tcpRst?: boolean;
  tcpSyn?: boolean;
  tcpFin?: boolean;

  hsrpState?: number;
  ospfMsg?: number;
  icmpType?: number;
  icmpv6Type?: number;

  ipv4Ttl?: number;
  ipv6HopLimit?: number;

  stpTopologyChange?: boolean;
  checksumBad?: boolean;
  broadcast?: boolean;

  hasSmb?: boolean;
  hasNbss?: boolean;
  hasNbns?: boolean;
  hasNetbios?: boolean;
  hasDcerpc?: boolean;
  hasSystemdJournal?: boolean;
  hasSysdig?: boolean;
  hasHsrp?: boolean;
  hasEigrp?: boolean;
  hasOspf?: boolean;
  hasBgp?: boolean;
  hasCdp?: boolean;
  hasVrrp?: boolean;
  hasCarp?: boolean;
  hasGvrp?: boolean;
  hasIgmp?: boolean;
  hasIsmp?: boolean;
  hasRip?: boolean;
  hasGlbp?: boolean;
  hasPim?: boolean;
}

export interface Packet {
  id: number;
  time: string;
  src: string;
  srcPort: number;
  dst: string;
  dstPort: number;
  proto: Protocol;
  displayProtocol?: string;
  length: number;
  info: string;
  payload: string;
  rawHex?: string;
  statusCode?: number;
  method?: string;
  streamId?: number;
  ipHeaderLen?: number;
  l4HeaderLen?: number;
  colorFeatures?: PacketColorFeatures;
}

export interface ProtocolTreeNode {
  id: string;
  label: string;
  byteRange?: [number, number];
  children?: ProtocolTreeNode[];
}

export type ThreatLevel = "critical" | "high" | "medium" | "low";

export interface ThreatHit {
  id: number;
  packetId: number;
  category: "CTF" | "OWASP" | "Anomaly" | "Sensitive";
  rule: string;
  level: ThreatLevel;
  preview: string;
  match: string;
}

export interface ExtractedObject {
  id: number;
  packetId: number;
  name: string;
  sizeBytes: number;
  mime: string;
  source: "HTTP" | "FTP";
}

export interface StreamChunk {
  packetId: number;
  direction: "client" | "server";
  body: string;
}

export interface HttpStream {
  id: number;
  client: string;
  server: string;
  request: string;
  response: string;
  chunks: StreamChunk[];
}

export interface BinaryStream {
  id: number;
  protocol: "TCP" | "UDP";
  from: string;
  to: string;
  chunks: StreamChunk[];
  nextCursor?: number;
  totalChunks?: number;
  hasMore?: boolean;
}

export type StreamProtocol = "HTTP" | "TCP" | "UDP";

export interface StreamSwitchStat {
  count: number;
  lastMs: number;
  p50Ms: number;
  p95Ms: number;
  cacheHitRate: number;
}

export interface StreamSwitchMetrics {
  overall: StreamSwitchStat;
  byProtocol: Record<StreamProtocol, StreamSwitchStat>;
}

export interface PluginItem {
  id: number | string;
  name: string;
  tag: string;
  author: string;
  version: string;
  enabled: boolean;
  entry?: string;
  runtime?: string;
  capabilities?: string[];
}

export interface AuditEntry {
  time: string;
  method: string;
  path: string;
  action: string;
  risk: string;
  origin?: string;
  remoteAddr?: string;
  status: number;
  authenticated: boolean;
}

export interface DecryptionConfig {
  sslKeyLogPath: string;
  privateKeyPath: string;
  privateKeyIpPort: string;
}

export interface TrafficBucket {
  label: string;
  count: number;
}

export interface GlobalTrafficStats {
  totalPackets: number;
  protocolKinds: number;
  timeline: TrafficBucket[];
  protocolDist: TrafficBucket[];
  topTalkers: TrafficBucket[];
  topHostnames: TrafficBucket[];
  topDomains: TrafficBucket[];
  topSrcIPs: TrafficBucket[];
  topDstIPs: TrafficBucket[];
  topComputerNames: TrafficBucket[];
  topDestPorts: TrafficBucket[];
  topSrcPorts: TrafficBucket[];
}

export interface AnalysisConversation {
  label: string;
  protocol?: string;
  count: number;
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

export interface IndustrialAnalysis {
  totalIndustrialPackets: number;
  protocols: TrafficBucket[];
  conversations: AnalysisConversation[];
  modbus: ModbusAnalysis;
  details: IndustrialProtocolDetail[];
  notes: string[];
}

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

export interface MediaArtifact {
  token: string;
  name: string;
  codec?: string;
  format?: string;
  sizeBytes: number;
}

export interface MediaSession {
  id: string;
  family: string;
  application: string;
  source: string;
  sourcePort: number;
  destination: string;
  destinationPort: number;
  transport: string;
  ssrc?: string;
  payloadType?: string;
  codec?: string;
  clockRate?: number;
  startTime?: string;
  endTime?: string;
  packetCount: number;
  gapCount: number;
  controlSummary?: string;
  tags: string[];
  notes: string[];
  artifact?: MediaArtifact;
}

export interface MediaAnalysis {
  totalMediaPackets: number;
  protocols: TrafficBucket[];
  applications: TrafficBucket[];
  sessions: MediaSession[];
  notes: string[];
}
