package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

func newTestVaultClient(t *testing.T, handler http.Handler) *vault.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetAddress(server.URL); err != nil {
		t.Fatal(err)
	}
	return client
}

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

func TestFormatVaultErrorExplainsClientCertificateHandshakeFailure(t *testing.T) {
	for _, alert := range []string{
		"tls: bad certificate",
		"tls: unknown certificate authority",
		"tls: expired certificate",
		"tls: certificate required",
	} {
		err := &url.Error{
			Op:  "Get",
			URL: "https://vault.example",
			Err: &net.OpError{Op: "remote error", Err: errors.New(alert)},
		}
		got := formatVaultError(err)
		for _, expected := range []string{
			"rejected the client certificate",
			"TLS handshake",
			"trusted by the Vault server",
		} {
			if !strings.Contains(got, expected) {
				t.Errorf("formatVaultError(%q) = %q, want it to contain %q", alert, got, expected)
			}
		}
		if strings.Contains(got, "remote error:") || strings.Contains(got, "tls:") {
			t.Errorf("formatVaultError(%q) exposed the raw TLS alert: %q", alert, got)
		}
	}
}

func TestFormatVaultErrorPreservesUnrelatedTLSFailures(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "https://vault.example",
		Err: &net.OpError{Op: "remote error", Err: errors.New("tls: protocol version not supported")},
	}

	got := formatVaultError(err)
	if !strings.Contains(got, "protocol version not supported") {
		t.Fatalf("formatVaultError() = %q, want the protocol error preserved", got)
	}
	if strings.Contains(got, "rejected the client certificate") {
		t.Fatalf("formatVaultError() misclassified an unrelated TLS failure: %q", got)
	}
}

func TestFormatVaultAPIErrorExplainsUnauthorizedCredentials(t *testing.T) {
	err := &vault.ResponseError{StatusCode: http.StatusUnauthorized}

	got := formatVaultAPIError(err)
	for _, expected := range []string{
		"401 Unauthorized",
		"managed API token",
		"expired",
		"revoked",
		"client certificate",
		"mTLS",
	} {
		if !strings.Contains(got, expected) {
			t.Errorf("formatVaultAPIError() = %q, want it to contain %q", got, expected)
		}
	}
	if strings.Contains(got, "Error making API request") || strings.Contains(got, "Errors:") {
		t.Fatalf("formatVaultAPIError() retained the unhelpful raw response: %q", got)
	}
}

func TestFormatVaultAPIErrorExplainsForbiddenAuthorization(t *testing.T) {
	err := &vault.ResponseError{StatusCode: http.StatusForbidden}

	got := formatVaultAPIError(err)
	for _, expected := range []string{"403 Forbidden", "authenticated token", "permission"} {
		if !strings.Contains(got, expected) {
			t.Errorf("formatVaultAPIError() = %q, want it to contain %q", got, expected)
		}
	}
	if strings.Contains(got, "client certificate") || strings.Contains(got, "mTLS") {
		t.Errorf("403 explanation incorrectly suggests an authentication problem: %q", got)
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

func TestBackupSecretsReturnsErrorForPartialRecursiveBackup(t *testing.T) {
	client := newTestVaultClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimSuffix(r.URL.Path, "/")
		isList := r.Method == "LIST" || (r.Method == http.MethodGet && r.URL.Query().Get("list") == "true")
		switch {
		case isList && path == "/v1/kv/metadata/app":
			_, _ = w.Write([]byte(`{"data":{"keys":["good","nested/","broken"]}}`))
		case isList && path == "/v1/kv/metadata/app/nested":
			_, _ = w.Write([]byte(`{"data":{"keys":["deep"]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/kv/data/app/good":
			_, _ = w.Write([]byte(`{"data":{"data":{"value":"good"}}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/kv/data/app/nested/deep":
			_, _ = w.Write([]byte(`{"data":{"data":{"value":"deep"}}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/kv/data/app/broken":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"errors":["read failed"]}`))
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))

	outputPath := filepath.Join(t.TempDir(), "backup")
	err := backupSecrets(client, Arguments{
		SecretName:   "kv",
		SecretPath:   "app/",
		OutputMode:   "file",
		OutputFormat: "json",
		OutputPath:   outputPath,
	})
	if err == nil || !strings.Contains(err.Error(), "app/broken") {
		t.Fatalf("backup error = %v, want failed app/broken", err)
	}
	for _, path := range []string{
		filepath.Join(outputPath, "app", "good.json"),
		filepath.Join(outputPath, "app", "nested", "deep.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("successful backup file %s missing: %v", path, err)
		}
	}
}

func TestRestoreSecretsReturnsErrorAfterPartialRestore(t *testing.T) {
	var restored int
	client := newTestVaultClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/kv/data/app/valid" {
			restored++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))

	inputPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(inputPath, "valid.env"), []byte("VALUE=restored\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inputPath, "invalid.json"), []byte("{invalid"), 0600); err != nil {
		t.Fatal(err)
	}

	err := restoreSecrets(client, Arguments{
		InputPath:  inputPath,
		SecretName: "kv",
		SecretPath: "app/",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid.json") {
		t.Fatalf("restore error = %v, want invalid.json failure", err)
	}
	if restored != 1 {
		t.Fatalf("successful restores = %d, want 1", restored)
	}
}
