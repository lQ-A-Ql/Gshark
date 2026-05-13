import {
  asArray,
  asPlainObject,
  asPositiveFiniteNumbers,
  asStringList,
  optionalNumber,
  optionalString,
} from "./mapperPrimitives";

export function asSMTPSession(input: unknown) {
  const item = asPlainObject(input) ?? {};
  return {
    streamId: Number(item.stream_id ?? 0),
    client: optionalString(item.client),
    server: optionalString(item.server),
    clientPort: optionalNumber(item.client_port),
    serverPort: optionalNumber(item.server_port),
    helo: optionalString(item.helo),
    authMechanisms: asStringList(item.auth_mechanisms),
    authUsername: optionalString(item.auth_username),
    authPasswordSeen: Boolean(item.auth_password_seen),
    mailFrom: asStringList(item.mail_from),
    rcptTo: asStringList(item.rcpt_to),
    commandCount: Number(item.command_count ?? 0),
    messageCount: Number(item.message_count ?? 0),
    attachmentHints: Number(item.attachment_hints ?? 0),
    commands: asArray(item.commands).map(asSMTPCommand),
    statusHints: asStringList(item.status_hints),
    messages: asArray(item.messages).map(asSMTPMessage),
    possibleCleartext: Boolean(item.possible_cleartext),
  };
}

function asSMTPCommand(input: unknown) {
  const row = asPlainObject(input) ?? {};
  return {
    packetId: Number(row.packet_id ?? 0),
    time: optionalString(row.time),
    direction: optionalString(row.direction),
    command: optionalString(row.command),
    argument: optionalString(row.argument),
    statusCode: optionalNumber(row.status_code),
    summary: optionalString(row.summary),
  };
}

function asSMTPMessage(input: unknown) {
  const row = asPlainObject(input) ?? {};
  return {
    sequence: Number(row.sequence ?? 0),
    mailFrom: optionalString(row.mail_from),
    rcptTo: asStringList(row.rcpt_to),
    subject: optionalString(row.subject),
    from: optionalString(row.from),
    to: optionalString(row.to),
    date: optionalString(row.date),
    contentType: optionalString(row.content_type),
    boundary: optionalString(row.boundary),
    attachmentNames: asStringList(row.attachment_names),
    bodyPreview: optionalString(row.body_preview),
    packetIds: asPositiveFiniteNumbers(row.packet_ids),
  };
}
