package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerLogWriterDuplicatesToDailyFilesAndCleansOldLogs(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer
	writer := newServerLogWriter(&stdout, filepath.Join(dir, "vault-server"))
	now := time.Date(2026, time.January, 8, 12, 0, 0, 0, time.UTC)
	writer.now = func() time.Time { return now }

	if _, err := writer.Write([]byte("stdout only\n")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("files created while file logging disabled: %v", entries)
	}

	oldLog := filepath.Join(dir, "vault-server-2010-01-01.log")
	if err := os.WriteFile(oldLog, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldTime := now.Add(-serverLogRetention - time.Minute)
	if err := os.Chtimes(oldLog, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnableFileLogging(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := writer.DisableFileLogging(); err != nil {
			t.Errorf("disable file logging: %v", err)
		}
	})
	if _, err := writer.Write([]byte("duplicated\n")); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(oldLog); !os.IsNotExist(err) {
		t.Fatalf("expired log still exists, stat error = %v", err)
	}
	firstLog := filepath.Join(dir, "vault-server-2026-01-08.log")
	content, err := os.ReadFile(firstLog)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "duplicated\n" {
		t.Fatalf("file log contents = %q", content)
	}
	info, err := os.Stat(firstLog)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("log file permissions = %04o, want 0600", info.Mode().Perm())
	}
	if stdout.String() != "stdout only\nduplicated\n" {
		t.Fatalf("stdout contents = %q", stdout.String())
	}

	now = now.Add(24 * time.Hour)
	if _, err := writer.Write([]byte("next day\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault-server-2026-01-09.log")); err != nil {
		t.Fatalf("next day's rotated log was not created: %v", err)
	}
}

func TestAccessLoggingUsesRequestPathAndOmitsQueryString(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/{mount}/data/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	var output bytes.Buffer
	handler := withAccessLogging(http.TimeoutHandler(mux, time.Second, "timed out"), &output)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/kv/data/private/secret?token=do-not-log",
		nil,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusCreated)
	}
	logLine := output.String()
	if !strings.Contains(logLine, `route="/api/v1/kv/data/private/secret"`) ||
		!strings.Contains(logLine, "status=201") {
		t.Fatalf("access log missing request path or status: %q", logLine)
	}
	if strings.Contains(logLine, "do-not-log") || strings.Contains(logLine, "?token=") {
		t.Fatalf("access log contains query string: %q", logLine)
	}
}
