package miscpkg

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const miscPublicKeyEnvVar = "MEOW_TRAFFIC_MISC_PUBLIC_KEY"

func loadMISCPublicKey() (ed25519.PublicKey, error) {
	value := strings.TrimSpace(os.Getenv(miscPublicKeyEnvVar))
	if value == "" {
		return nil, nil
	}
	return decodeMISCPublicKey(value)
}

func decodeMISCPublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty public key")
	}
	var raw []byte
	var err error
	// Accept either hex (64 chars) or base64.
	if len(value) == ed25519.PublicKeySize*2 {
		raw, err = hex.DecodeString(value)
	} else {
		raw, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil {
		return nil, fmt.Errorf("decode misc public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid misc public key length: got %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func verifyMISCPackageSignature(reader *zip.Reader, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid MISC public key configured")
	}

	payload, err := packageSignaturePayload(reader)
	if err != nil {
		return err
	}

	sigBytes, err := readSignatureFile(reader)
	if err != nil {
		return err
	}

	return verifyMISCSignature(publicKey, payload, sigBytes)
}

func verifyMISCSignature(publicKey ed25519.PublicKey, payload, sigBytes []byte) error {
	digest := sha256.Sum256(payload)
	if !ed25519.Verify(publicKey, digest[:], sigBytes) {
		return errors.New("MISC package signature verification failed")
	}
	return nil
}

// verifyModuleDirSignature validates the on-disk signature for an already
// extracted MISC module directory. It uses the same canonical payload as zip
// import so that a valid zip package remains valid once extracted.
func verifyModuleDirSignature(dir string, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid MISC public key configured")
	}

	files := make(map[string][]byte)
	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.EqualFold(rel, "signature") {
			return nil
		}
		if info.Size() > maxModuleZipFileBytes {
			return fmt.Errorf("module file %q exceeds size limit %d bytes", rel, maxModuleZipFileBytes)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read module file %q: %w", rel, err)
		}
		files[rel] = data
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("walk module dir: %w", walkErr)
	}

	payload := buildMISCModuleSignaturePayload(files)

	sigBytes, err := readModuleDirSignature(dir)
	if err != nil {
		return err
	}

	return verifyMISCSignature(publicKey, payload, sigBytes)
}

func readModuleDirSignature(dir string) ([]byte, error) {
	path := filepath.Join(dir, "signature")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("module signature file not found")
		}
		return nil, fmt.Errorf("read module signature: %w", err)
	}
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err == nil {
		return decoded, nil
	}
	return raw, nil
}

// packageSignaturePayload builds a canonical, collision-resistant payload from
// all files in the zip except the signature file. Changing any file (including
// manifest.json) invalidates the signature.
func packageSignaturePayload(reader *zip.Reader) ([]byte, error) {
	root := detectZipRoot(reader)
	files := make(map[string][]byte, len(reader.File))

	for _, file := range reader.File {
		rel := stripZipRoot(file.Name, root)
		if rel == "" || strings.EqualFold(rel, "signature") {
			continue
		}
		if file.FileInfo().IsDir() {
			continue
		}
		if file.UncompressedSize64 > maxModuleZipFileBytes {
			return nil, fmt.Errorf("misc module zip file %q exceeds size limit %d bytes", rel, maxModuleZipFileBytes)
		}

		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open zipped file %q: %w", rel, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, int64(maxModuleZipFileBytes)+1))
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read zipped file %q: %w", rel, err)
		}
		if len(data) > maxModuleZipFileBytes {
			return nil, fmt.Errorf("misc module zip file %q exceeds size limit %d bytes", rel, maxModuleZipFileBytes)
		}
		files[rel] = data
	}

	return buildMISCModuleSignaturePayload(files), nil
}

// buildMISCModuleSignaturePayload builds the canonical signed payload from a
// map of relative file paths to contents. The map keys must already be relative
// to the module root and use forward slashes.
func buildMISCModuleSignaturePayload(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}

	sort.Strings(names)
	var buf bytes.Buffer
	for _, name := range names {
		buf.WriteString(name)
		buf.WriteByte(0)
		buf.Write(files[name])
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func readSignatureFile(reader *zip.Reader) ([]byte, error) {
	root := detectZipRoot(reader)
	for _, file := range reader.File {
		if strings.EqualFold(stripZipRoot(file.Name, root), "signature") {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("open module signature: %w", err)
			}
			defer rc.Close()
			raw, err := io.ReadAll(io.LimitReader(rc, 1024))
			if err != nil {
				return nil, fmt.Errorf("read module signature: %w", err)
			}
			// Signature file may be base64-encoded or raw bytes.
			if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err == nil {
				return decoded, nil
			}
			return raw, nil
		}
	}
	return nil, errors.New("signature file not found in module zip")
}
