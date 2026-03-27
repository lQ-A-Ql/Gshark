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

func FilterFrameIDs(ctx context.Context, opts model.ParseOptions) ([]int64, error) {
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
		"-e", "frame.number",
	)

	cmd, err := CommandContext(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("resolve tshark: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tshark: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	ids := make([]int64, 0, 1024)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		id, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil || id <= 0 {
			continue
		}
		ids = append(ids, id)
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return nil, fmt.Errorf("scan tshark output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return nil, fmt.Errorf("wait tshark: %w: %s", err, detail)
		}
		return nil, fmt.Errorf("wait tshark: %w", err)
	}

	return ids, nil
}
