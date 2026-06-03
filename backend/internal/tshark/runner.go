package tshark

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func StreamPackets(ctx context.Context, opts model.ParseOptions, onPacket func(model.Packet) error, onProgress func(processed int)) error {
	maxPackets := opts.MaxPackets

	cmd, err := CommandContext(ctx, BuildArgs(opts)...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}
	log.Printf("tshark stream ek: binary=%q file=%q filter=%q", cmd.Path, opts.FilePath, opts.DisplayFilter)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	reader := bufio.NewReaderSize(stdout, 256*1024)
	var packetCount int64
	processedFrames := 0
	for {
		lineBytes, readErr := reader.ReadBytes('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = cmd.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read tshark output: %w", readErr)
		}
		if len(lineBytes) == 0 && errors.Is(readErr, io.EOF) {
			break
		}

		select {
		case <-ctx.Done():
			_ = cmd.Wait()
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}
		if strings.Contains(line, `"index"`) && !strings.Contains(line, `"layers"`) {
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		processedFrames++
		if onProgress != nil && (processedFrames == 1 || processedFrames%2000 == 0) {
			onProgress(processedFrames)
		}

		packet, parseErr := ParsePacketFromEK(line, packetCount+1)
		if parseErr != nil {
			if maxPackets > 0 && processedFrames >= maxPackets {
				break
			}
			continue
		}
		packetCount++
		if err := onPacket(packet); err != nil {
			_ = cmd.Wait()
			return err
		}
		if maxPackets > 0 && processedFrames >= maxPackets {
			break
		}

		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	if onProgress != nil {
		onProgress(processedFrames)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("wait tshark: %w: %s", err, detail)
		}
		return fmt.Errorf("wait tshark: %w", err)
	}
	return nil
}

func StreamPacketsFast(ctx context.Context, opts model.ParseOptions, onPacket func(model.Packet) error, onProgress func(processed int)) error {
	maxPackets := opts.MaxPackets
	args, plan, err := buildFastListScanArgs(opts)
	if err != nil {
		return fmt.Errorf("plan tshark fast fields: %w", err)
	}
	cmd, err := CommandContext(ctx, args...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}
	log.Printf("tshark stream fast_list: binary=%q file=%q filter=%q", cmd.Path, opts.FilePath, opts.DisplayFilter)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	reader := bufio.NewReaderSize(stdout, 128*1024)
	processed := 0
	for {
		lineBytes, readErr := reader.ReadBytes('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = cmd.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read tshark fields output: %w", readErr)
		}
		if len(lineBytes) == 0 && errors.Is(readErr, io.EOF) {
			break
		}

		select {
		case <-ctx.Done():
			_ = cmd.Wait()
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		processed++
		if onProgress != nil && (processed == 1 || processed%2000 == 0) {
			onProgress(processed)
		}

		line = projectPacketListLine(line, plan)
		packet, parseErr := parseFastListLine(line)
		if parseErr == nil {
			if err := onPacket(packet); err != nil {
				_ = cmd.Wait()
				return err
			}
		}

		if maxPackets > 0 && processed >= maxPackets {
			break
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	if onProgress != nil {
		onProgress(processed)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("wait tshark fields: %w: %s", err, detail)
		}
		return fmt.Errorf("wait tshark fields: %w", err)
	}
	return nil
}

func StreamPacketsFirstScreen(ctx context.Context, opts model.ParseOptions, onPacket func(model.Packet) error, onProgress func(processed int)) error {
	maxPackets := opts.MaxPackets
	args, plan, err := buildFirstScreenListScanArgs(opts)
	if err != nil {
		return fmt.Errorf("plan tshark first-screen fields: %w", err)
	}
	cmd, err := CommandContext(ctx, args...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}
	log.Printf("tshark stream first_screen: binary=%q file=%q filter=%q", cmd.Path, opts.FilePath, opts.DisplayFilter)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	reader := bufio.NewReaderSize(stdout, 64*1024)
	processed := 0
	for {
		lineBytes, readErr := reader.ReadBytes('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = cmd.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read tshark first-screen output: %w", readErr)
		}
		if len(lineBytes) == 0 && errors.Is(readErr, io.EOF) {
			break
		}

		select {
		case <-ctx.Done():
			_ = cmd.Wait()
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		processed++
		if onProgress != nil && (processed == 1 || processed%2000 == 0) {
			onProgress(processed)
		}

		line = projectPacketListLine(line, plan)
		packet, parseErr := parseCompatListLine(line)
		if parseErr == nil {
			if err := onPacket(packet); err != nil {
				_ = cmd.Wait()
				return err
			}
		}

		if maxPackets > 0 && processed >= maxPackets {
			break
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	if onProgress != nil {
		onProgress(processed)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("wait tshark first-screen fields: %w: %s", err, detail)
		}
		return fmt.Errorf("wait tshark first-screen fields: %w", err)
	}
	return nil
}

func StreamPacketsCompat(ctx context.Context, opts model.ParseOptions, onPacket func(model.Packet) error, onProgress func(processed int)) error {
	maxPackets := opts.MaxPackets
	args, plan, err := buildCompatListScanArgs(opts)
	if err != nil {
		return fmt.Errorf("plan tshark compat fields: %w", err)
	}
	cmd, err := CommandContext(ctx, args...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}
	log.Printf("tshark stream compat_fields: binary=%q file=%q filter=%q", cmd.Path, opts.FilePath, opts.DisplayFilter)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	reader := bufio.NewReaderSize(stdout, 64*1024)
	processed := 0
	for {
		lineBytes, readErr := reader.ReadBytes('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = cmd.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read tshark compat output: %w", readErr)
		}
		if len(lineBytes) == 0 && errors.Is(readErr, io.EOF) {
			break
		}

		select {
		case <-ctx.Done():
			_ = cmd.Wait()
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		processed++
		if onProgress != nil && (processed == 1 || processed%2000 == 0) {
			onProgress(processed)
		}

		line = projectPacketListLine(line, plan)
		packet, parseErr := parseCompatListLine(line)
		if parseErr == nil {
			if err := onPacket(packet); err != nil {
				_ = cmd.Wait()
				return err
			}
		}

		if maxPackets > 0 && processed >= maxPackets {
			break
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	if onProgress != nil {
		onProgress(processed)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("wait tshark compat fields: %w: %s", err, detail)
		}
		return fmt.Errorf("wait tshark compat fields: %w", err)
	}
	return nil
}

func EstimatePackets(ctx context.Context, opts model.ParseOptions) (int, error) {
	args := []string{"-n", "-r", opts.FilePath}
	if opts.DisplayFilter != "" {
		args = append(args, "-Y", opts.DisplayFilter)
	}
	plannedScan, err := BuildPlannedFieldArgs(append(args, "-T", "fields"), []string{"frame.number"})
	if err != nil {
		return 0, fmt.Errorf("plan tshark estimate fields: %w", err)
	}

	cmd, err := CommandContext(ctx, plannedScan.Args...)
	if err != nil {
		return 0, fmt.Errorf("resolve tshark for estimate: %w", err)
	}
	log.Printf("tshark estimate: binary=%q file=%q filter=%q", cmd.Path, opts.FilePath, opts.DisplayFilter)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("create stdout pipe for estimate: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start tshark for estimate: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	count := 0
	for scanner.Scan() {
		parts := plannedScan.ProjectRow(strings.Split(scanner.Text(), "\t"))
		if strings.TrimSpace(safeTrim(parts, 0)) == "" {
			continue
		}
		count++
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return 0, fmt.Errorf("scan tshark estimate output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return 0, fmt.Errorf("wait tshark estimate: %w: %s", err, detail)
		}
		return 0, fmt.Errorf("wait tshark estimate: %w", err)
	}

	return count, nil
}

func ExportObjects(pcapPath, exportDir string) error {
	return ExportObjectsContext(context.Background(), pcapPath, exportDir)
}

func ExportObjectsContext(ctx context.Context, pcapPath, exportDir string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd, err := CommandContext(ctx, "-r", pcapPath, "-q",
		"--export-objects", "http,"+exportDir,
		"--export-objects", "smb,"+exportDir,
		"--export-objects", "tftp,"+exportDir,
		"--export-objects", "dicom,"+exportDir,
		"--export-objects", "imf,"+exportDir,
	)
	if err != nil {
		return fmt.Errorf("resolve tshark for export objects: %w", err)
	}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

func ExportObjectsLegacy(pcapPath, exportDir string) error {
	cmd, err := Command("-r", pcapPath, "-q",
		"--export-objects", "http,"+exportDir,
		"--export-objects", "smb,"+exportDir,
		"--export-objects", "tftp,"+exportDir,
		"--export-objects", "dicom,"+exportDir,
		"--export-objects", "imf,"+exportDir,
	)
	if err != nil {
		return fmt.Errorf("resolve tshark for export objects: %w", err)
	}
	return cmd.Run()
}
