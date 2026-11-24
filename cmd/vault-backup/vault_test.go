package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

func TestFormatVaultErrorForLockedSetup(t *testing.T) {
	err := &vault.ResponseError{
		StatusCode: http.StatusLocked,
		Errors:     []string{"setup window expired"},
	}

	got := formatVaultError(err)
	if got != "Vault setup is locked (423): setup window expired" {
		t.Fatalf("formatVaultError() = %q", got)
	}
}

func TestFormatVaultErrorPreservesOtherErrors(t *testing.T) {
	err := &vault.ResponseError{
		StatusCode: http.StatusForbidden,
		Errors:     []string{"permission denied"},
	}

	got := formatVaultError(err)
	if !strings.Contains(got, "permission denied") {
		t.Fatalf("formatVaultError() = %q", got)
	}
}

func TestWriteSecretFileUsesRestrictedPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(path, []byte("old secret"), 0644); err != nil {
		t.Fatal(err)
	}

	const secret = "DATABASE_PASSWORD=new-secret"
	if err := writeSecretFile(path, []byte(secret)); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("secret file mode = %o, want 600", got)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != secret {
		t.Fatalf("secret file contents = %q, want %q", contents, secret)
	}
}

func TestWriteOutputCreatesRestrictedDirectory(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "backups", "database")
	writeOutput(
		map[string]any{"data": map[string]any{"password": "secret"}},
		"file",
		"json",
		outputPath,
		"database.json",
	)

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Fatalf("output directory mode = %o, want 700", got)
	}
}
