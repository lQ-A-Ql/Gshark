package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestObjectsWithContextRetriesAfterExportFailure(t *testing.T) {
	svc := NewService(NopEmitter{})
	svc.captureCtl.mu.Lock()
	svc.captureCtl.pcap = "capture.pcap"
	svc.captureCtl.mu.Unlock()

	originalExport := exportObjectsContextFn
	t.Cleanup(func() {
		exportObjectsContextFn = originalExport
	})

	calls := 0
	exportObjectsContextFn = func(ctx context.Context, pcapPath, exportDir string) error {
		calls++
		if calls == 1 {
			return errors.New("temporary export failure")
		}
		return os.WriteFile(filepath.Join(exportDir, "payload.bin"), []byte("payload"), 0o644)
	}

	if objects := svc.ObjectsWithContext(context.Background()); len(objects) != 0 {
		t.Fatalf("first ObjectsWithContext() returned %d objects, want 0", len(objects))
	}
	if svc.objectCtl.objectsLoaded {
		t.Fatal("export failure should not mark objects as loaded")
	}

	objects := svc.ObjectsWithContext(context.Background())
	if len(objects) != 1 {
		t.Fatalf("second ObjectsWithContext() returned %d objects, want 1", len(objects))
	}
	if objects[0].Name != "payload.bin" {
		t.Fatalf("object name = %q, want payload.bin", objects[0].Name)
	}
	if calls != 2 {
		t.Fatalf("export called %d times, want 2", calls)
	}
}
