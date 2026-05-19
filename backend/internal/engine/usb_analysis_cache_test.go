package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

func TestUSBAnalysisWithOptionsReusesRawScanAcrossSourceAndLimitChanges(t *testing.T) {
	oldRunner := tshark.USBAnalysisScanRunnerForTesting()
	t.Cleanup(func() {
		tshark.SetUSBAnalysisScanRunnerForTesting(oldRunner)
		tshark.ClearUSBAnalysisRawScanCache()
	})
	tshark.ClearUSBAnalysisRawScanCache()

	var scans int32
	tshark.SetUSBAnalysisScanRunnerForTesting(func(filePath string) (tshark.USBAnalysisRawScan, error) {
		atomic.AddInt32(&scans, 1)
		return tshark.USBAnalysisRawScan{Rows: [][]string{make([]string, 0)}}, nil
	})

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "capture.pcapng"

	if _, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{HIDSourceMode: model.USBHIDSourceAuto, HIDEventLimit: 500}); err != nil {
		t.Fatalf("first USBAnalysisWithOptions() error = %v", err)
	}
	if _, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{HIDSourceMode: model.USBHIDSourceUSBHID, HIDEventLimit: 500}); err != nil {
		t.Fatalf("second USBAnalysisWithOptions() error = %v", err)
	}
	if _, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{HIDSourceMode: model.USBHIDSourceUSBHID, HIDEventLimit: 1000}); err != nil {
		t.Fatalf("third USBAnalysisWithOptions() error = %v", err)
	}

	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("expected one raw USB scan per capture, got %d", got)
	}
}

func TestUSBAnalysisCacheInvalidatedByCaptureReplacement(t *testing.T) {
	oldRunner := tshark.USBAnalysisScanRunnerForTesting()
	t.Cleanup(func() {
		tshark.SetUSBAnalysisScanRunnerForTesting(oldRunner)
		tshark.ClearUSBAnalysisRawScanCache()
	})
	tshark.ClearUSBAnalysisRawScanCache()

	var scans int32
	tshark.SetUSBAnalysisScanRunnerForTesting(func(filePath string) (tshark.USBAnalysisRawScan, error) {
		atomic.AddInt32(&scans, 1)
		return tshark.USBAnalysisRawScan{Rows: [][]string{make([]string, 0)}}, nil
	})

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "capture.pcapng"

	if _, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{}); err != nil {
		t.Fatalf("first USBAnalysisWithOptions() error = %v", err)
	}
	svc.PrepareCaptureReplacement()
	svc.mu.Lock()
	svc.pcap = "capture.pcapng"
	svc.mu.Unlock()

	if _, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{}); err != nil {
		t.Fatalf("second USBAnalysisWithOptions() error = %v", err)
	}
	if got := atomic.LoadInt32(&scans); got != 2 {
		t.Fatalf("expected capture replacement to invalidate USB raw scan cache, got %d scans", got)
	}
}

func TestUSBAnalysisRawScanCacheInvalidatedByCaptureCommit(t *testing.T) {
	oldRunner := tshark.USBAnalysisScanRunnerForTesting()
	t.Cleanup(func() {
		tshark.SetUSBAnalysisScanRunnerForTesting(oldRunner)
		tshark.ClearUSBAnalysisRawScanCache()
	})
	tshark.ClearUSBAnalysisRawScanCache()

	var scans int32
	tshark.SetUSBAnalysisScanRunnerForTesting(func(filePath string) (tshark.USBAnalysisRawScan, error) {
		atomic.AddInt32(&scans, 1)
		return tshark.USBAnalysisRawScan{Rows: [][]string{make([]string, 0)}}, nil
	})

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "capture.pcapng"

	if _, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{}); err != nil {
		t.Fatalf("first USBAnalysisWithOptions() error = %v", err)
	}
	nextStore, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore() error = %v", err)
	}
	defer nextStore.Close()
	if err := svc.commitLoadedCapture("capture.pcapng", nextStore, nil); err != nil {
		t.Fatalf("commitLoadedCapture() error = %v", err)
	}

	if _, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{}); err != nil {
		t.Fatalf("second USBAnalysisWithOptions() error = %v", err)
	}
	if got := atomic.LoadInt32(&scans); got != 2 {
		t.Fatalf("expected capture commit to invalidate USB raw scan cache, got %d scans", got)
	}
}

func TestUSBAnalysisDoesNotCacheResultAfterCaptureChanges(t *testing.T) {
	oldRunner := tshark.USBAnalysisScanRunnerForTesting()
	t.Cleanup(func() {
		tshark.SetUSBAnalysisScanRunnerForTesting(oldRunner)
		tshark.ClearUSBAnalysisRawScanCache()
	})
	tshark.ClearUSBAnalysisRawScanCache()

	scanStarted := make(chan struct{})
	releaseScan := make(chan struct{})
	var scans int32
	tshark.SetUSBAnalysisScanRunnerForTesting(func(filePath string) (tshark.USBAnalysisRawScan, error) {
		atomic.AddInt32(&scans, 1)
		if filePath == "old.pcapng" {
			close(scanStarted)
			<-releaseScan
		}
		return tshark.USBAnalysisRawScan{Rows: [][]string{make([]string, 0)}}, nil
	})

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "old.pcapng"

	errs := make(chan error, 1)
	go func() {
		_, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{})
		errs <- err
	}()

	select {
	case <-scanStarted:
	case <-time.After(time.Second):
		t.Fatal("expected old USB scan to start")
	}
	svc.mu.Lock()
	svc.pcap = "new.pcapng"
	svc.mu.Unlock()
	close(releaseScan)

	if err := <-errs; err != context.Canceled {
		t.Fatalf("expected stale USB analysis to be canceled, got %v", err)
	}

	svc.mu.RLock()
	cachedDefault := svc.usbAnalysis
	sourceCacheSize := len(svc.usbAnalysisBySource)
	svc.mu.RUnlock()
	if cachedDefault != nil || sourceCacheSize != 0 {
		t.Fatalf("expected stale USB analysis not to populate cache, default=%v sourceCacheSize=%d", cachedDefault != nil, sourceCacheSize)
	}
	if _, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{}); err != nil {
		t.Fatalf("new capture USBAnalysisWithOptions() error = %v", err)
	}
	if got := atomic.LoadInt32(&scans); got != 2 {
		t.Fatalf("expected new capture to trigger a fresh scan, got %d scans", got)
	}
}

func TestUSBAnalysisConcurrentRequestsShareOneRawScan(t *testing.T) {
	oldRunner := tshark.USBAnalysisScanRunnerForTesting()
	t.Cleanup(func() {
		tshark.SetUSBAnalysisScanRunnerForTesting(oldRunner)
		tshark.ClearUSBAnalysisRawScanCache()
	})
	tshark.ClearUSBAnalysisRawScanCache()

	started := make(chan struct{})
	release := make(chan struct{})
	var scans int32
	tshark.SetUSBAnalysisScanRunnerForTesting(func(filePath string) (tshark.USBAnalysisRawScan, error) {
		atomic.AddInt32(&scans, 1)
		close(started)
		<-release
		return tshark.USBAnalysisRawScan{Rows: [][]string{make([]string, 0)}}, nil
	})

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "capture.pcapng"

	errs := make(chan error, 2)
	go func() {
		_, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{})
		errs <- err
	}()
	go func() {
		_, err := svc.USBAnalysisWithOptions(context.Background(), model.USBAnalysisOptions{})
		errs <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("expected USB scan to start")
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("unexpected USBAnalysisWithOptions() error = %v", err)
		}
	}
	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("expected concurrent USB requests to share one scan, got %d", got)
	}
}
