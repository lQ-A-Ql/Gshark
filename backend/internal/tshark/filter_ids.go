package tshark

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func ScanFrameIDs(ctx context.Context, opts model.ParseOptions, onID func(int64)) error {
	args := []string{"-n", "-r", opts.FilePath}
	if strings.TrimSpace(opts.DisplayFilter) != "" {
		args = append(args, "-Y", strings.TrimSpace(opts.DisplayFilter))
	}
	args = appendTLSArgs(args, opts.TLS)
	args = append(args,
		"-T", "fields",
		"-E", "header=n",
		"-E", "occurrence=f",
		"-E", "separator=\t",
		"-E", "quote=n",
	)
	plannedScan, err := BuildPlannedFieldArgs(args, []string{"frame.number"})
	if err != nil {
		return fmt.Errorf("plan tshark frame id fields: %w", err)
	}

	cmd, err := CommandContext(ctx, plannedScan.Args...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		parts := plannedScan.ProjectRow(strings.Split(scanner.Text(), "\t"))
		value := strings.TrimSpace(safeTrim(parts, 0))
		if value == "" {
			continue
		}
		id, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil || id <= 0 {
			continue
		}
		if onID != nil {
			onID(id)
		}
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("scan tshark output: %w", err)
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

func FilterFrameIDs(ctx context.Context, opts model.ParseOptions) ([]int64, error) {
	ids := make([]int64, 0, 1024)
	if err := ScanFrameIDs(ctx, opts, func(id int64) {
		ids = append(ids, id)
	}); err != nil {
		return nil, err
	}
	return ids, nil
}
