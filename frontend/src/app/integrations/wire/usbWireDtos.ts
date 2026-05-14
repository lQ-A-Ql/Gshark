export interface USBAnalysisWireDTO extends Record<string, unknown> {
  total_usb_packets?: unknown;
  keyboard_packets?: unknown;
  mouse_packets?: unknown;
  other_usb_packets?: unknown;
  hid_packets?: unknown;
  mass_storage_packets?: unknown;
  protocols?: unknown;
  transfer_types?: unknown;
  directions?: unknown;
  devices?: unknown;
  endpoints?: unknown;
  setup_requests?: unknown;
  records?: unknown;
  keyboard_events?: unknown;
  mouse_events?: unknown;
  other_records?: unknown;
  hid?: unknown;
  mass_storage?: unknown;
  other?: unknown;
  notes?: unknown;
  report?: unknown;
}
