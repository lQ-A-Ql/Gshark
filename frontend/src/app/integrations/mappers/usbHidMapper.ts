import type { USBHIDAnalysis, USBKeyboardEvent, USBMouseEvent } from "../../core/types";
import { asBucket, asStringList } from "./mapperPrimitives";

export function asUSBKeyboardEvent(item: any): USBKeyboardEvent {
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

export function asUSBMouseEvent(item: any): USBMouseEvent {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    device: String(item.device ?? ""),
    endpoint: String(item.endpoint ?? ""),
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

export function asUSBHidAnalysis(payload: any): USBHIDAnalysis {
  return {
    keyboardEvents: Array.isArray(payload?.keyboard_events) ? payload.keyboard_events.map(asUSBKeyboardEvent) : [],
    mouseEvents: Array.isArray(payload?.mouse_events) ? payload.mouse_events.map(asUSBMouseEvent) : [],
    devices: Array.isArray(payload?.devices) ? payload.devices.map(asBucket) : [],
    notes: asStringList(payload?.notes),
  };
}
