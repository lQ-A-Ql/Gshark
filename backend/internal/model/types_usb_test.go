package model

import "testing"

func TestNormalizeUSBHIDSourceMode(t *testing.T) {
	tests := []struct {
		raw    string
		want   USBHIDSourceMode
		wantOK bool
	}{
		{raw: "", want: USBHIDSourceAuto, wantOK: true},
		{raw: " AUTO ", want: USBHIDSourceAuto, wantOK: true},
		{raw: "usbhid", want: USBHIDSourceUSBHID, wantOK: true},
		{raw: "capdata", want: USBHIDSourceCapData, wantOK: true},
		{raw: "btatt", want: USBHIDSourceBTATT, wantOK: true},
		{raw: "raw", want: USBHIDSourceRaw, wantOK: true},
		{raw: "unknown", want: USBHIDSourceAuto, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, ok := NormalizeUSBHIDSourceMode(tt.raw)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("NormalizeUSBHIDSourceMode(%q) = %q/%v, want %q/%v", tt.raw, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestNormalizeUSBHIDEventLimit(t *testing.T) {
	tests := []struct {
		raw  int
		want int
	}{
		{raw: 0, want: DefaultUSBHIDEventLimit},
		{raw: -1, want: DefaultUSBHIDEventLimit},
		{raw: MinUSBHIDEventLimit - 1, want: MinUSBHIDEventLimit},
		{raw: MinUSBHIDEventLimit, want: MinUSBHIDEventLimit},
		{raw: 1500, want: 1500},
		{raw: MaxUSBHIDEventLimit + 1, want: MaxUSBHIDEventLimit},
		{raw: MaxUSBHIDEventLimit, want: MaxUSBHIDEventLimit},
	}
	for _, tt := range tests {
		if got := NormalizeUSBHIDEventLimit(tt.raw); got != tt.want {
			t.Fatalf("NormalizeUSBHIDEventLimit(%d) = %d, want %d", tt.raw, got, tt.want)
		}
	}
}
