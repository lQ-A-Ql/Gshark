export type Protocol = "TCP" | "UDP" | "HTTP" | "HTTPS" | "DNS" | "SSHv2" | "TLS" | "ARP" | "ICMP" | "ICMPV6" | "USB" | "OTHER";

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
  category: string;
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

export interface StreamLoadMeta {
  source?: string;
  loading?: boolean;
  cacheHit?: boolean;
  indexHit?: boolean;
  fileFallback?: boolean;
  tsharkMs?: number;
  overrideCount?: number;
}

export type StreamDecoderKind = "base64" | "behinder" | "antsword" | "godzilla" | "auto";

export interface StreamDecodeResult {
  decoder: StreamDecoderKind;
  summary: string;
  text: string;
  bytesHex: string;
  encoding: string;
}

export interface StreamPayloadCandidate {
  id: string;
  label: string;
  kind: string;
  paramName?: string;
  value: string;
  preview?: string;
  confidence?: number;
  decoderHints?: string[];
  fingerprints?: string[];
}

export interface StreamPayloadInspection {
  normalizedPayload: string;
  candidates: StreamPayloadCandidate[];
  suggestedCandidateId?: string;
  suggestedDecoder?: StreamDecoderKind | string;
  suggestedFamily?: string;
  confidence?: number;
  reasons?: string[];
}

export interface WinRMDecryptRequest {
  port: number;
  authMode: "password" | "nt_hash";
  password?: string;
  ntHash?: string;
  previewLines?: number;
  includeErrorFrames?: boolean;
  extractCommandOutput?: boolean;
}

export interface WinRMDecryptResult {
  resultId: string;
  captureName: string;
  port: number;
  authMode: string;
  previewText: string;
  previewTruncated: boolean;
  lineCount: number;
  frameCount: number;
  errorFrameCount: number;
  extractedFrameCount: number;
  exportFilename: string;
  message: string;
}

export interface SMB3RandomSessionKeyRequest {
  username: string;
  domain: string;
  ntlmHash: string;
  ntProofStr: string;
  encryptedSessionKey: string;
}

export interface SMB3SessionCandidate {
  sessionId: string;
  username: string;
  domain: string;
  ntProofStr: string;
  encryptedSessionKey: string;
  src: string;
  dst: string;
  frameNumber: string;
  timestamp: string;
  complete: boolean;
  displayLabel: string;
}

export interface NTLMSessionMaterial {
  protocol: string;
  transport?: string;
  frameNumber: string;
  timestamp?: string;
  src?: string;
  dst?: string;
  srcPort?: string;
  dstPort?: string;
  direction?: string;
  username?: string;
  domain?: string;
  userDisplay?: string;
  challenge?: string;
  ntProofStr?: string;
  encryptedSessionKey?: string;
  sessionId?: string;
  authHeader?: string;
  wwwAuthenticate?: string;
  info?: string;
  complete: boolean;
  displayLabel: string;
}

export interface HTTPLoginAttempt {
  packetId: number;
  responsePacketId?: number;
  streamId: number;
  time?: string;
  responseTime?: string;
  src?: string;
  dst?: string;
  method?: string;
  host?: string;
  path?: string;
  endpointLabel?: string;
  username?: string;
  passwordPresent?: boolean;
  tokenPresent?: boolean;
  captchaPresent?: boolean;
  requestKeys?: string[];
  requestContentType?: string;
  requestPreview?: string;
  statusCode?: number;
  responseLocation?: string;
  responseSetCookie?: boolean;
  responseTokenHint?: boolean;
  responseIndicators?: string[];
  responsePreview?: string;
  result?: string;
  reason?: string;
  possibleBruteforce?: boolean;
}

export interface HTTPLoginEndpoint {
  key: string;
  method?: string;
  host?: string;
  path?: string;
  attemptCount: number;
  successCount: number;
  failureCount: number;
  uncertainCount: number;
  possibleBruteforce?: boolean;
  usernameVariants?: number;
  passwordAttempts?: number;
  captchaCount?: number;
  setCookieCount?: number;
  tokenHintCount?: number;
  statusCodes?: TrafficBucket[];
  requestKeys?: string[];
  responseIndicators?: string[];
  samplePacketIds?: number[];
  notes?: string[];
}

export interface HTTPLoginAnalysis {
  totalAttempts: number;
  candidateEndpoints: number;
  successCount: number;
  failureCount: number;
  uncertainCount: number;
  bruteforceCount: number;
  endpoints: HTTPLoginEndpoint[];
  attempts: HTTPLoginAttempt[];
  notes: string[];
}

export interface SMTPCommandRecord {
  packetId: number;
  time?: string;
  direction?: string;
  command?: string;
  argument?: string;
  statusCode?: number;
  summary?: string;
}

export interface SMTPMessage {
  sequence: number;
  mailFrom?: string;
  rcptTo?: string[];
  subject?: string;
  from?: string;
  to?: string;
  date?: string;
  contentType?: string;
  boundary?: string;
  attachmentNames?: string[];
  bodyPreview?: string;
  packetIds?: number[];
}

export interface SMTPSession {
  streamId: number;
  client?: string;
  server?: string;
  clientPort?: number;
  serverPort?: number;
  helo?: string;
  authMechanisms?: string[];
  authUsername?: string;
  authPasswordSeen?: boolean;
  mailFrom?: string[];
  rcptTo?: string[];
  commandCount: number;
  messageCount: number;
  attachmentHints?: number;
  commands?: SMTPCommandRecord[];
  statusHints?: string[];
  messages?: SMTPMessage[];
  possibleCleartext?: boolean;
}

export interface SMTPAnalysis {
  sessionCount: number;
  messageCount: number;
  authCount: number;
  attachmentHintCount: number;
  sessions: SMTPSession[];
  notes: string[];
}

export interface MySQLQueryRecord {
  packetId: number;
  time?: string;
  command?: string;
  sql?: string;
  database?: string;
  responsePacketId?: number;
  responseKind?: string;
  responseCode?: number;
  responseSummary?: string;
}

export interface MySQLServerEvent {
  packetId: number;
  time?: string;
  sequence?: number;
  kind?: string;
  code?: number;
  summary?: string;
}

export interface MySQLSession {
  streamId: number;
  client?: string;
  server?: string;
  clientPort?: number;
  serverPort?: number;
  serverVersion?: string;
  connectionId?: number;
  username?: string;
  database?: string;
  authPlugin?: string;
  loginPacketId?: number;
  loginSuccess?: boolean;
  queryCount: number;
  okCount: number;
  errCount: number;
  resultsetCount: number;
  commandTypes?: string[];
  queries: MySQLQueryRecord[];
  serverEvents: MySQLServerEvent[];
  notes?: string[];
}

export interface MySQLAnalysis {
  sessionCount: number;
  loginCount: number;
  queryCount: number;
  errorCount: number;
  resultsetCount: number;
  sessions: MySQLSession[];
  notes: string[];
}

export interface ShiroRememberMeKeyResult {
  label: string;
  base64?: string;
  algorithm?: string;
  hit?: boolean;
  payloadClass?: string;
  preview?: string;
  reason?: string;
}

export interface ShiroRememberMeCandidate {
  packetId: number;
  streamId?: number;
  time?: string;
  src?: string;
  dst?: string;
  host?: string;
  path?: string;
  sourceHeader?: string;
  cookieName?: string;
  cookieValue?: string;
  cookiePreview?: string;
  decodeOK?: boolean;
  encryptedLength?: number;
  aesBlockAligned?: boolean;
  possibleCBC?: boolean;
  possibleGCM?: boolean;
  keyResults?: ShiroRememberMeKeyResult[];
  hitCount?: number;
  notes?: string[];
}

export interface ShiroRememberMeAnalysis {
  candidateCount: number;
  hitCount: number;
  candidates: ShiroRememberMeCandidate[];
  notes: string[];
}

export interface MiscModuleFieldOption {
  value: string;
  label: string;
}

export interface MiscModuleFormField {
  name: string;
  label: string;
  type: string;
  placeholder?: string;
  defaultValue?: string;
  helpText?: string;
  required?: boolean;
  secret?: boolean;
  rows?: number;
  options?: MiscModuleFieldOption[];
}

export interface MiscModuleFormSchema {
  description?: string;
  submitLabel?: string;
  resultTitle?: string;
  fields: MiscModuleFormField[];
}

export interface MiscModuleInterfaceSchema {
  method?: string;
  invokePath?: string;
  runtime?: string;
  entry?: string;
  hostBridge?: boolean;
}

export interface MiscModuleTableColumn {
  key: string;
  label: string;
}

export interface MiscModuleTableResult {
  columns: MiscModuleTableColumn[];
  rows: Record<string, string>[];
}

export interface MiscModuleManifest {
  id: string;
  kind: string;
  title: string;
  summary: string;
  tags: string[];
  apiPrefix: string;
  docsPath?: string;
  requiresCapture: boolean;
  protocolDomain?: string;
  supportsExport?: boolean;
  cancellable?: boolean;
  dependsOn?: string[];
  formSchema?: MiscModuleFormSchema;
  interfaceSchema?: MiscModuleInterfaceSchema;
}

export interface MiscModuleRunResult {
  message: string;
  text?: string;
  output?: unknown;
  table?: MiscModuleTableResult;
}

export interface MiscModuleImportResult {
  module: MiscModuleManifest;
  installedPath: string;
  message: string;
}

export interface SMB3RandomSessionKeyResult {
  randomSessionKey: string;
  message: string;
}

export interface HttpStream {
  id: number;
  client: string;
  server: string;
  request: string;
  response: string;
  chunks: StreamChunk[];
  loadMeta?: StreamLoadMeta;
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
  loadMeta?: StreamLoadMeta;
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

export interface DecryptionConfig {
  sslKeyLogPath: string;
  privateKeyPath: string;
  privateKeyIpPort: string;
}

export interface RecentCapture {
  path: string;
  name: string;
  sizeBytes: number;
  lastOpenedAt: string;
}

export interface AppUpdateAsset {
  name: string;
  downloadUrl: string;
  sizeBytes: number;
  contentType?: string;
}

export interface AppUpdateStatus {
  currentVersion: string;
  currentVersionDisplay: string;
  currentVersionSource: string;
  currentExecutable: string;
  localHash: string;
  repo: string;
  authMode: string;
  checkedAt: string;
  apiUrl: string;
  hasUpdate: boolean;
  upToDate: boolean;
  hashMismatch: boolean;
  latestTag: string;
  latestName: string;
  latestPublishedAt: string;
  releaseUrl: string;
  releaseNotes: string;
  selectedAsset?: AppUpdateAsset;
  canInstall: boolean;
  message: string;
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
  mediaType: string;
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

export interface SpeechToTextStatus {
  available: boolean;
  engine: string;
  language: string;
  pythonAvailable: boolean;
  pythonCommand?: string;
  ffmpegAvailable: boolean;
  voskAvailable: boolean;
  modelAvailable: boolean;
  modelPath?: string;
  message: string;
}

export interface ToolRuntimeConfig {
  tsharkPath: string;
  ffmpegPath: string;
  pythonPath: string;
  voskModelPath: string;
  yaraEnabled: boolean;
  yaraBin: string;
  yaraRules: string;
  yaraTimeoutMs: number;
}

export interface YaraToolStatus {
  available: boolean;
  enabled: boolean;
  path?: string;
  rulePath?: string;
  message: string;
  lastScanMessage?: string;
  customBin?: string;
  customRules?: string;
  usingCustomBin: boolean;
  usingCustomRules: boolean;
  timeoutMs: number;
}

export interface ToolRuntimeSnapshot {
  config: ToolRuntimeConfig;
  tshark: {
    available: boolean;
    path: string;
    message: string;
    customPath?: string;
    usingCustomPath: boolean;
  };
  ffmpeg: {
    available: boolean;
    path: string;
    message: string;
    customPath?: string;
    usingCustomPath: boolean;
  };
  speech: SpeechToTextStatus;
  yara: YaraToolStatus;
}

export interface MediaTranscriptionSegment {
  startSeconds: number;
  endSeconds: number;
  text: string;
}

export interface MediaTranscription {
  token: string;
  sessionId: string;
  title: string;
  text: string;
  language: string;
  engine: string;
  status: string;
  error?: string;
  cached: boolean;
  durationSeconds: number;
  segments: MediaTranscriptionSegment[];
}

export interface SpeechBatchTaskItem {
  token: string;
  sessionId: string;
  mediaLabel: string;
  title: string;
  status: "queued" | "running" | "completed" | "failed" | "skipped";
  error?: string;
  cached: boolean;
  text?: string;
}

export interface SpeechBatchTaskStatus {
  taskId: string;
  total: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
  skipped: number;
  currentToken?: string;
  currentLabel?: string;
  done: boolean;
  cancelled: boolean;
  items: SpeechBatchTaskItem[];
}

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
  dataResidue?: number;
  summary: string;
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
