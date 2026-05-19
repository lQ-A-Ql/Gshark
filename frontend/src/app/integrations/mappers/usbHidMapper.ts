import type { USBHIDAnalysis, USBKeyboardEvent, USBMouseEvent } from "../../core/types";
import { asArray, asBucket, asPlainObject, asStringList } from "./mapperPrimitives";

export function asUSBKeyboardEvent(input: unknown): USBKeyboardEvent {
  const item = asPlainObject(input) ?? {};
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    device: String(item.device ?? ""),
    endpoint: String(item.endpoint ?? ""),
    modifiers: asStringList(item.modifiers),
    keys: asStringList(item.keys),
    pressedModifiers: asStringList(item.pressed_modifiers),
    releasedModifiers: asStringList(item.released_modifiers),
    pressedKeys: asStringList(item.pressed_keys),
    releasedKeys: asStringList(item.released_keys),
    text: String(item.text ?? "") || undefined,
    summary: String(item.summary ?? ""),
  };
}

export function asUSBMouseEvent(input: unknown): USBMouseEvent {
  const item = asPlainObject(input) ?? {};
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    device: String(item.device ?? ""),
    endpoint: String(item.endpoint ?? ""),
    source: String(item.source ?? "") || undefined,
    layout: String(item.layout ?? "") || undefined,
    buttons: asStringList(item.buttons),
    pressedButtons: asStringList(item.pressed_buttons),
    releasedButtons: asStringList(item.released_buttons),
    xDelta: Number(item.x_delta ?? 0),
    yDelta: Number(item.y_delta ?? 0),
    wheelVertical: Number(item.wheel_vertical ?? 0),
    wheelHorizontal: Number(item.wheel_horizontal ?? 0),
    positionX: Number(item.position_x ?? 0),
    positionY: Number(item.position_y ?? 0),
    summary: String(item.summary ?? ""),
  };
}

export function asUSBHidAnalysis(input: unknown): USBHIDAnalysis {
  const payload = asPlainObject(input) ?? {};
  return {
    keyboardEvents: asArray(payload.keyboard_events).map(asUSBKeyboardEvent),
    mouseEvents: asArray(payload.mouse_events).map(asUSBMouseEvent),
    devices: asArray(payload.devices).map(asBucket),
    notes: asStringList(payload.notes),
  };
}
