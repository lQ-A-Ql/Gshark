package miscpkg

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func readPackageManifest(reader *zip.Reader) (model.MiscModulePackageManifest, error) {
	root := detectZipRoot(reader)
	for _, file := range reader.File {
		if strings.EqualFold(stripZipRoot(file.Name, root), "manifest.json") {
			rc, err := file.Open()
			if err != nil {
				return model.MiscModulePackageManifest{}, fmt.Errorf("open module manifest: %w", err)
			}
			defer rc.Close()

			raw, err := io.ReadAll(io.LimitReader(rc, int64(maxModuleZipFileBytes)+1))
			if err != nil {
				return model.MiscModulePackageManifest{}, fmt.Errorf("read module manifest: %w", err)
			}
			if len(raw) > maxModuleZipFileBytes {
				return model.MiscModulePackageManifest{}, fmt.Errorf("module manifest.json exceeds size limit %d bytes", maxModuleZipFileBytes)
			}
			var manifest model.MiscModulePackageManifest
			if err := json.Unmarshal(raw, &manifest); err != nil {
				return model.MiscModulePackageManifest{}, fmt.Errorf("parse module manifest: %w", err)
			}
			manifest.ID = strings.TrimSpace(manifest.ID)
			manifest.Title = strings.TrimSpace(manifest.Title)
			return manifest, nil
		}
	}
	return model.MiscModulePackageManifest{}, fmt.Errorf("manifest.json not found in module zip")
}

func extractZipToDir(reader *zip.Reader, dir string) error {
	root := detectZipRoot(reader)
	fileCount := 0
	var totalBytes uint64
	for _, file := range reader.File {
		relative := stripZipRoot(file.Name, root)
		if relative == "" {
			continue
		}
		targetPath, err := resolveManagedPath(dir, relative)
		if err != nil {
			return err
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("create module subdir: %w", err)
			}
			continue
		}
		fileCount++
		if fileCount > maxModuleZipFiles {
			return fmt.Errorf("misc module zip contains too many files: limit %d", maxModuleZipFiles)
		}
		if file.UncompressedSize64 > maxModuleZipFileBytes {
			return fmt.Errorf("misc module zip file %q exceeds size limit %d bytes", relative, maxModuleZipFileBytes)
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return fmt.Errorf("create module file dir: %w", err)
		}
		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("open zipped file: %w", err)
		}
		content, readErr := io.ReadAll(io.LimitReader(rc, int64(maxModuleZipFileBytes)+1))
		_ = rc.Close()
		if readErr != nil {
			return fmt.Errorf("read zipped file: %w", readErr)
		}
		if len(content) > maxModuleZipFileBytes {
			return fmt.Errorf("misc module zip file %q exceeds size limit %d bytes", relative, maxModuleZipFileBytes)
		}
		totalBytes += uint64(len(content))
		if totalBytes > maxModuleZipTotalBytes {
			return fmt.Errorf("misc module zip exceeds total uncompressed size limit %d bytes", maxModuleZipTotalBytes)
		}
		if err := os.WriteFile(targetPath, content, 0o644); err != nil {
			return fmt.Errorf("write extracted file: %w", err)
		}
	}
	return nil
}

func detectZipRoot(reader *zip.Reader) string {
	var first string
	for _, file := range reader.File {
		cleaned := filepath.ToSlash(strings.TrimSpace(file.Name))
		cleaned = strings.TrimPrefix(cleaned, "/")
		if cleaned == "" {
			continue
		}
		parts := strings.Split(cleaned, "/")
		if len(parts) == 1 {
			return ""
		}
		if strings.EqualFold(parts[0], "manifest.json") {
			return ""
		}
		if first == "" {
			first = parts[0]
			continue
		}
		if first != parts[0] {
			return ""
		}
	}
	return first
}

func stripZipRoot(name, root string) string {
	cleaned := filepath.ToSlash(strings.TrimSpace(name))
	cleaned = strings.TrimPrefix(cleaned, "/")
	if root == "" {
		return cleaned
	}
	prefix := root + "/"
	return strings.TrimPrefix(cleaned, prefix)
}
