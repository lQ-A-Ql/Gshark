import type { TrafficBucket } from "./traffic";

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

export interface SMB3RandomSessionKeyResult {
  randomSessionKey: string;
  message: string;
}
