import { asArray, asBucket, asPlainObject } from "./mapperPrimitives";
import { asCANDBCMessage, asCANSignalTimeline, asDBCProfile } from "./vehicleCanDbcMapper";
import { asCANFrameSummary, asCANPayloadRecord } from "./vehicleCanRecordMapper";

export function asCANSection(input: unknown) {
  const payload = asPlainObject(input) ?? {};
  return {
    totalFrames: Number(payload.total_frames ?? 0),
    extendedFrames: Number(payload.extended_frames ?? 0),
    rtrFrames: Number(payload.rtr_frames ?? 0),
    errorFrames: Number(payload.error_frames ?? 0),
    busIds: asArray(payload.bus_ids).map(asBucket),
    messageIds: asArray(payload.message_ids).map(asBucket),
    payloadProtocols: asArray(payload.payload_protocols).map(asBucket),
    payloadRecords: asArray(payload.payload_records).map(asCANPayloadRecord),
    dbcProfiles: asArray(payload.dbc_profiles).map(asDBCProfile),
    decodedMessageDist: asArray(payload.decoded_message_dist).map(asBucket),
    decodedSignals: asArray(payload.decoded_signals).map(asBucket),
    decodedMessages: asArray(payload.decoded_messages).map(asCANDBCMessage),
    signalTimelines: asArray(payload.signal_timelines).map(asCANSignalTimeline),
    frames: asArray(payload.frames).map(asCANFrameSummary),
  };
}
