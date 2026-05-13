import {
  asArray,
  asBucket,
  asPlainObject,
  asPositiveFiniteNumbers,
  asStringList,
  optionalNumber,
  optionalString,
} from "./mapperPrimitives";

export function asHTTPLoginEndpoint(input: unknown) {
  const item = asPlainObject(input) ?? {};
  return {
    key: String(item.key ?? ""),
    method: optionalString(item.method),
    host: optionalString(item.host),
    path: optionalString(item.path),
    attemptCount: Number(item.attempt_count ?? 0),
    successCount: Number(item.success_count ?? 0),
    failureCount: Number(item.failure_count ?? 0),
    uncertainCount: Number(item.uncertain_count ?? 0),
    possibleBruteforce: Boolean(item.possible_bruteforce),
    usernameVariants: optionalNumber(item.username_variants),
    passwordAttempts: optionalNumber(item.password_attempts),
    captchaCount: optionalNumber(item.captcha_count),
    setCookieCount: optionalNumber(item.set_cookie_count),
    tokenHintCount: optionalNumber(item.token_hint_count),
    statusCodes: asArray(item.status_codes).map(asBucket),
    requestKeys: asStringList(item.request_keys),
    responseIndicators: asStringList(item.response_indicators),
    samplePacketIds: asPositiveFiniteNumbers(item.sample_packet_ids),
    notes: asStringList(item.notes),
  };
}

export function asHTTPLoginAttempt(input: unknown) {
  const item = asPlainObject(input) ?? {};
  return {
    packetId: Number(item.packet_id ?? 0),
    responsePacketId: optionalNumber(item.response_packet_id),
    streamId: Number(item.stream_id ?? 0),
    time: optionalString(item.time),
    responseTime: optionalString(item.response_time),
    src: optionalString(item.src),
    dst: optionalString(item.dst),
    method: optionalString(item.method),
    host: optionalString(item.host),
    path: optionalString(item.path),
    endpointLabel: optionalString(item.endpoint_label),
    username: optionalString(item.username),
    passwordPresent: Boolean(item.password_present),
    tokenPresent: Boolean(item.token_present),
    captchaPresent: Boolean(item.captcha_present),
    requestKeys: asStringList(item.request_keys),
    requestContentType: optionalString(item.request_content_type),
    requestPreview: optionalString(item.request_preview),
    statusCode: optionalNumber(item.status_code),
    responseLocation: optionalString(item.response_location),
    responseSetCookie: Boolean(item.response_set_cookie),
    responseTokenHint: Boolean(item.response_token_hint),
    responseIndicators: asStringList(item.response_indicators),
    responsePreview: optionalString(item.response_preview),
    result: optionalString(item.result),
    reason: optionalString(item.reason),
    possibleBruteforce: Boolean(item.possible_bruteforce),
  };
}
