import type { USBKeyboardEvent, USBMouseEvent } from "../core/types";

export const keyboardEventsFixture: USBKeyboardEvent[] = [
  keyboardEvent(1, ["Left Shift"], ["A"], ["Left Shift"], [], ["A"], [], "A", "press Left Shift + A"),
  keyboardEvent(6, [], ["B"], [], ["Left Shift"], ["B"], ["A"], "b", "press B"),
  keyboardEvent(7, [], ["Backspace"], [], [], ["Backspace"], ["B"], undefined, "press Backspace"),
  keyboardEvent(8, [], ["CapsLock"], [], [], ["CapsLock"], ["Backspace"], undefined, "press CapsLock"),
  keyboardEvent(9, [], ["C"], [], [], ["C"], ["CapsLock"], "c", "press C"),
  keyboardEvent(10, [], [], [], [], [], ["C"], undefined, "release C"),
];

export const mouseEventsFixture: USBMouseEvent[] = [
  mouseEvent(2, ["Left"], ["Left"], [], [8, 2], [8, 2], "press Left / move=(+8,+2)"),
  mouseEvent(3, ["Right"], ["Right"], ["Left"], [4, -3], [12, -1], "press Right / release Left"),
  mouseEvent(4, [], [], ["Right"], [5, 1], [17, 0], "release Right / move=(+5,+1)"),
  mouseEvent(5, [], [], [], [2, 2], [19, 2], "move=(+2,+2)"),
];

function keyboardEvent(
  packetId: number,
  modifiers: string[],
  keys: string[],
  pressedModifiers: string[],
  releasedModifiers: string[],
  pressedKeys: string[],
  releasedKeys: string[],
  text: string | undefined,
  summary: string,
): USBKeyboardEvent {
  return {
    packetId,
    time: `1.${packetId}00000`,
    device: "Keyboard A",
    endpoint: "EP 0x81 (IN)",
    modifiers,
    keys,
    pressedModifiers,
    releasedModifiers,
    pressedKeys,
    releasedKeys,
    text,
    summary,
  };
}

function mouseEvent(
  packetId: number,
  buttons: string[],
  pressedButtons: string[],
  releasedButtons: string[],
  delta: [number, number],
  position: [number, number],
  summary: string,
): USBMouseEvent {
  return {
    packetId,
    time: `1.${packetId}00000`,
    device: "Mouse A",
    endpoint: "EP 0x82 (IN)",
    source: "usbhid.data",
    layout: "github-8",
    buttons,
    pressedButtons,
    releasedButtons,
    xDelta: delta[0],
    yDelta: delta[1],
    wheelVertical: 0,
    wheelHorizontal: 0,
    positionX: position[0],
    positionY: position[1],
    summary,
  };
}
