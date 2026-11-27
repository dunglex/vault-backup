package mkcert

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGetCAROOTUsesEnvironment(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CAROOT", root)
	if got := GetCAROOT(); got != root {
		t.Fatalf("GetCAROOT() = %q, want %q", got, root)
	}
}

func TestGetCAROOTUsesPlatformDefault(t *testing.T) {
	t.Setenv("CAROOT", "")
	home := t.TempDir()
	t.Setenv("HOME", home)

	got := GetCAROOT()
	var want string
	switch runtime.GOOS {
	case "windows":
		localAppData := t.TempDir()
		t.Setenv("LocalAppData", localAppData)
		got = GetCAROOT()
		want = filepath.Join(localAppData, "mkcert")
	case "darwin":
		want = filepath.Join(home, "Library", "Application Support", "mkcert")
	default:
		want = filepath.Join(home, ".local", "share", "mkcert")
	}
	if got != want {
		t.Fatalf("GetCAROOT() = %q, want %q", got, want)
	}
}

func TestStoreEnabled(t *testing.T) {
	t.Setenv("TRUST_STORES", "")
	for _, name := range []string{"system", "nss", "java"} {
		if !storeEnabled(name) {
			t.Errorf("storeEnabled(%q) = false with TRUST_STORES unset", name)
		}
	}

	t.Setenv("TRUST_STORES", "system,java")
	if !storeEnabled("system") || !storeEnabled("java") {
		t.Fatal("configured system or Java trust store was disabled")
	}
	if storeEnabled("nss") {
		t.Fatal("unconfigured NSS trust store was enabled")
	}
}

func TestPathAndBinaryExists(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(existing, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if !pathExists(existing) {
		t.Fatal("pathExists rejected an existing file")
	}
	if pathExists(existing + "-missing") {
		t.Fatal("pathExists accepted a missing file")
	}
	if !binaryExists("go") {
		t.Fatal("go executable was not found")
	}
	if binaryExists("vault-backup-command-that-does-not-exist") {
		t.Fatal("missing executable was found")
	}
}
