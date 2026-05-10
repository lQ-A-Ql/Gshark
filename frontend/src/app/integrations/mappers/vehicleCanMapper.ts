import { asBucket } from "./mapperPrimitives";
import { asCANDBCMessage, asCANSignalTimeline, asDBCProfile } from "./vehicleCanDbcMapper";
import { asCANFrameSummary, asCANPayloadRecord } from "./vehicleCanRecordMapper";

export function asCANSection(input: any) {
  return {
    totalFrames: Number(input?.total_frames ?? 0),
    extendedFrames: Number(input?.extended_frames ?? 0),
    rtrFrames: Number(input?.rtr_frames ?? 0),
    errorFrames: Number(input?.error_frames ?? 0),
    busIds: Array.isArray(input?.bus_ids) ? input.bus_ids.map(asBucket) : [],
    messageIds: Array.isArray(input?.message_ids) ? input.message_ids.map(asBucket) : [],
    payloadProtocols: Array.isArray(input?.payload_protocols) ? input.payload_protocols.map(asBucket) : [],
    payloadRecords: Array.isArray(input?.payload_records) ? input.payload_records.map(asCANPayloadRecord) : [],
    dbcProfiles: Array.isArray(input?.dbc_profiles) ? input.dbc_profiles.map(asDBCProfile) : [],
    decodedMessageDist: Array.isArray(input?.decoded_message_dist) ? input.decoded_message_dist.map(asBucket) : [],
    decodedSignals: Array.isArray(input?.decoded_signals) ? input.decoded_signals.map(asBucket) : [],
    decodedMessages: Array.isArray(input?.decoded_messages) ? input.decoded_messages.map(asCANDBCMessage) : [],
    signalTimelines: Array.isArray(input?.signal_timelines) ? input.signal_timelines.map(asCANSignalTimeline) : [],
    frames: Array.isArray(input?.frames) ? input.frames.map(asCANFrameSummary) : [],
  };
}
