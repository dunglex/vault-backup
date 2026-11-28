package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		if err := writer.Close(); err != nil {
			t.Errorf("close log writer: %v", err)
		}
	})
	if _, err := writer.Write([]byte("duplicated\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.DisableFileLogging(); err != nil {
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
	if err := writer.EnableFileLogging(); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("next day\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.DisableFileLogging(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault-server-2026-01-09.log")); err != nil {
		t.Fatalf("next day's rotated log was not created: %v", err)
	}
}

func TestServerLogWriterCreatesLogDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	writer := newServerLogWriter(&bytes.Buffer{}, filepath.Join(dir, "vault-server"))
	writer.now = func() time.Time {
		return time.Date(2026, time.January, 8, 12, 0, 0, 0, time.UTC)
	}

	if err := writer.EnableFileLogging(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Errorf("close log writer: %v", err)
		}
	})

	info, err := os.Stat(filepath.Join(dir, "vault-server-2026-01-08.log"))
	if err != nil {
		t.Fatalf("log file was not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("log file permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestServerLogWriterBatchesAndFlushesFileWrites(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer
	writer := newServerLogWriter(&stdout, filepath.Join(dir, "vault-server"))
	writer.now = func() time.Time {
		return time.Date(2026, time.January, 8, 12, 0, 0, 0, time.UTC)
	}
	if err := writer.EnableFileLogging(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Errorf("close log writer: %v", err)
		}
	})

	var writes sync.WaitGroup
	for i := 0; i < 100; i++ {
		writes.Add(1)
		go func(i int) {
			defer writes.Done()
			line := fmt.Sprintf("log line %03d\n", i)
			if _, err := writer.Write([]byte(line)); err != nil {
				t.Errorf("write log line: %v", err)
			}
		}(i)
	}
	writes.Wait()
	if err := writer.DisableFileLogging(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "vault-server-2026-01-08.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, stdout.Bytes()) {
		t.Fatalf("batched file contents do not match stdout: got %d bytes, want %d", len(content), stdout.Len())
	}
}

func TestAccessLoggingUsesRequestPathAndOmitsQueryString(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/{mount}/data/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	var output bytes.Buffer
	handler := withAccessLogging(http.TimeoutHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordDBOperationMetrics(r, 20*time.Millisecond, 1, "api_token_validation")
		recordDBMetrics(r, 17*time.Millisecond, 2)
		mux.ServeHTTP(w, r)
	}), time.Second, "timed out"), &output, true, func() bool { return true })
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
		!strings.Contains(logLine, "status=201") ||
		!strings.Contains(logLine, "request_duration=") ||
		!strings.Contains(logLine, "db_duration=37ms") ||
		!strings.Contains(logLine, "db_query_count=3") ||
		!strings.Contains(logLine, `db_operation_durations="api_token_validation=20ms,other=17ms"`) {
		t.Fatalf("access log missing request path or status: %q", logLine)
	}
	if strings.Contains(logLine, "db_wait_duration=") {
		t.Fatalf("access log contains the old DB wait field: %q", logLine)
	}
	if strings.Contains(logLine, "do-not-log") || strings.Contains(logLine, "?token=") {
		t.Fatalf("access log contains query string: %q", logLine)
	}
}

func TestAccessLoggingOmitsDBMetricsByDefault(t *testing.T) {
	var output bytes.Buffer
	handler := withAccessLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordDBOperationMetrics(r, 20*time.Millisecond, 1, "api_token_validation")
		w.WriteHeader(http.StatusOK)
	}), &output, false, func() bool { return true })

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/kv/metadata", nil))

	logLine := output.String()
	if !strings.Contains(logLine, "request_duration=") {
		t.Fatalf("access log missing request duration: %q", logLine)
	}
	for _, field := range []string{"db_duration=", "db_query_count=", "db_operation_durations="} {
		if strings.Contains(logLine, field) {
			t.Fatalf("default access log contains %q: %q", field, logLine)
		}
	}
}

func TestAccessLoggingCanBeDisabled(t *testing.T) {
	var output bytes.Buffer
	handler := withAccessLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}), &output, false, func() bool { return false })
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/kv/metadata", nil))

	if response.Code != http.StatusAccepted {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusAccepted)
	}
	if output.Len() != 0 {
		t.Fatalf("access log was written while disabled: %q", output.String())
	}
}

func TestAccessLoggingSuppressesSuccessfulHealthChecks(t *testing.T) {
	var output bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /health-failure", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	handler := withAccessLogging(mux, &output, false, func() bool { return true })
	for _, path := range []string{"/health", "/health-failure"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}

	logLine := output.String()
	if strings.Contains(logLine, `route="/health"`) {
		t.Fatalf("successful health check was logged: %q", logLine)
	}
	if !strings.Contains(logLine, `route="/health-failure"`) || !strings.Contains(logLine, "status=503") {
		t.Fatalf("non-health or failed health access log missing: %q", logLine)
	}
}
