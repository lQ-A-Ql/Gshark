package miscpkg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestMISCPackageSignatureVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	t.Run("signed package imports when public key is configured", func(t *testing.T) {
		t.Setenv(miscPublicKeyEnvVar, hex.EncodeToString(pub))
		t.Setenv("MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC", "")
		manager := NewManager()
		baseDir := t.TempDir()
		if err := manager.LoadFromDir(baseDir); err != nil {
			t.Fatalf("LoadFromDir() error = %v", err)
		}

		files := minimalModuleFiles("signed-demo")
		payload := signModuleZip(t, files, "signed-demo", priv)
		result, err := manager.ImportZipBytes(payload)
		if err != nil {
			t.Fatalf("ImportZipBytes() error = %v", err)
		}
		if result.Module.ID != "signed-demo" {
			t.Fatalf("unexpected module id: %v", result.Module.ID)
		}
	})

	t.Run("unsigned package rejected when public key configured", func(t *testing.T) {
		t.Setenv(miscPublicKeyEnvVar, hex.EncodeToString(pub))
		t.Setenv("MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC", "")
		manager := NewManager()
		if err := manager.LoadFromDir(t.TempDir()); err != nil {
			t.Fatalf("LoadFromDir() error = %v", err)
		}

		payload := createModuleZip(t, minimalModuleFiles("unsigned-demo"))
		if _, err := manager.ImportZipBytes(payload); err == nil {
			t.Fatal("expected unsigned package to be rejected")
		}
	})

	t.Run("tampered package rejected", func(t *testing.T) {
		t.Setenv(miscPublicKeyEnvVar, hex.EncodeToString(pub))
		t.Setenv("MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC", "")
		manager := NewManager()
		if err := manager.LoadFromDir(t.TempDir()); err != nil {
			t.Fatalf("LoadFromDir() error = %v", err)
		}

		files := minimalModuleFiles("tamper-demo")
		_ = signModuleZip(t, files, "tamper-demo", priv)
		// Tamper with a signed file after signing; signature no longer matches.
		files["tamper-demo/manifest.json"] = `{"id":"tamper-demo","title":"Tampered"}`
		payload := createModuleZip(t, files)
		if _, err := manager.ImportZipBytes(payload); err == nil {
			t.Fatal("expected tampered package to be rejected")
		}
	})

	t.Run("unsigned package rejected when no key and unsigned disallowed", func(t *testing.T) {
		t.Setenv(miscPublicKeyEnvVar, "")
		t.Setenv("MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC", "")
		manager := NewManager()
		if err := manager.LoadFromDir(t.TempDir()); err != nil {
			t.Fatalf("LoadFromDir() error = %v", err)
		}

		payload := createModuleZip(t, minimalModuleFiles("nokey-demo"))
		if _, err := manager.ImportZipBytes(payload); err == nil {
			t.Fatal("expected unsigned package to be rejected when unsigned is disallowed")
		}
	})

	t.Run("LoadFromDir verifies signatures for installed modules", func(t *testing.T) {
		t.Setenv(miscPublicKeyEnvVar, hex.EncodeToString(pub))
		t.Setenv("MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC", "")

		manager := NewManager()
		baseDir := t.TempDir()
		if err := manager.LoadFromDir(baseDir); err != nil {
			t.Fatalf("LoadFromDir() error = %v", err)
		}

		files := minimalModuleFiles("disk-demo")
		payload := signModuleZip(t, files, "disk-demo", priv)
		if _, err := manager.ImportZipBytes(payload); err != nil {
			t.Fatalf("ImportZipBytes() error = %v", err)
		}

		// Simulate a service restart by loading the same directory with a fresh manager.
		restarted := NewManager()
		if err := restarted.LoadFromDir(baseDir); err != nil {
			t.Fatalf("restart LoadFromDir() error = %v", err)
		}
		items := restarted.List()
		if len(items) != 1 || items[0].ID != "disk-demo" {
			t.Fatalf("expected signed module to load after restart, got %+v", items)
		}
	})

	t.Run("LoadFromDir rejects tampered installed modules", func(t *testing.T) {
		t.Setenv(miscPublicKeyEnvVar, hex.EncodeToString(pub))
		t.Setenv("MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC", "")

		manager := NewManager()
		baseDir := t.TempDir()
		if err := manager.LoadFromDir(baseDir); err != nil {
			t.Fatalf("LoadFromDir() error = %v", err)
		}

		files := minimalModuleFiles("disk-tamper-demo")
		payload := signModuleZip(t, files, "disk-tamper-demo", priv)
		if _, err := manager.ImportZipBytes(payload); err != nil {
			t.Fatalf("ImportZipBytes() error = %v", err)
		}

		// Tamper with the installed module after import.
		moduleDir := filepath.Join(baseDir, "disk-tamper-demo")
		if err := os.WriteFile(filepath.Join(moduleDir, "manifest.json"), []byte(`{"id":"disk-tamper-demo","title":"Tampered"}`), 0o644); err != nil {
			t.Fatalf("tamper manifest: %v", err)
		}

		restarted := NewManager()
		if err := restarted.LoadFromDir(baseDir); err != nil {
			t.Fatalf("restart LoadFromDir() error = %v", err)
		}
		items := restarted.List()
		if len(items) != 0 {
			t.Fatalf("expected tampered module to be skipped, got %+v", items)
		}
	})
}

func TestDecodeMISCPublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	t.Run("hex", func(t *testing.T) {
		decoded, err := decodeMISCPublicKey(hex.EncodeToString(pub))
		if err != nil {
			t.Fatalf("decode hex key: %v", err)
		}
		if string(decoded) != string(pub) {
			t.Fatal("hex decoded key mismatch")
		}
	})

	t.Run("base64", func(t *testing.T) {
		decoded, err := decodeMISCPublicKey(base64.StdEncoding.EncodeToString(pub))
		if err != nil {
			t.Fatalf("decode base64 key: %v", err)
		}
		if string(decoded) != string(pub) {
			t.Fatal("base64 decoded key mismatch")
		}
	})

	t.Run("invalid", func(t *testing.T) {
		if _, err := decodeMISCPublicKey("not-a-key"); err == nil {
			t.Fatal("expected invalid key to be rejected")
		}
	})
}

func signModuleZip(t *testing.T, files map[string]string, id string, privateKey ed25519.PrivateKey) []byte {
	t.Helper()

	rootPrefix := detectMapRoot(files)
	rel := func(name string) string {
		if rootPrefix == "" {
			return name
		}
		return strings.TrimPrefix(name, rootPrefix+"/")
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	for _, name := range names {
		buf.WriteString(rel(name))
		buf.WriteByte(0)
		buf.WriteString(files[name])
		buf.WriteByte(0)
	}

	digest := sha256.Sum256(buf.Bytes())
	sig := ed25519.Sign(privateKey, digest[:])
	if rootPrefix == "" {
		files["signature"] = base64.StdEncoding.EncodeToString(sig)
	} else {
		files[rootPrefix+"/signature"] = base64.StdEncoding.EncodeToString(sig)
	}
	return createModuleZip(t, files)
}

func detectMapRoot(files map[string]string) string {
	var root string
	for name := range files {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) < 2 {
			return ""
		}
		if root == "" {
			root = parts[0]
			continue
		}
		if root != parts[0] {
			return ""
		}
	}
	return root
}
