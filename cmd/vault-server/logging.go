package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	serverFileLoggingSetting = "file_logging"
	serverLogRetention       = 7 * 24 * time.Hour
)

type serverLogWriter struct {
	mu       sync.Mutex
	stdout   io.Writer
	basePath string
	now      func() time.Time

	file        *os.File
	fileEnabled bool
	fileDate    string
	lastError   string
}

func newServerLogWriter(stdout io.Writer, basePath string) *serverLogWriter {
	return &serverLogWriter{
		stdout:   stdout,
		basePath: basePath,
		now:      time.Now,
	}
}

func (w *serverLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	stdoutBytes, stdoutErr := w.stdout.Write(p)
	if !w.fileEnabled {
		return stdoutBytes, stdoutErr
	}
	if err := w.rotateLocked(); err != nil {
		w.reportFileErrorLocked(err)
		return stdoutBytes, stdoutErr
	}
	if _, err := w.file.Write(p); err != nil {
		w.reportFileErrorLocked(err)
		return stdoutBytes, stdoutErr
	}
	w.lastError = ""
	return stdoutBytes, stdoutErr
}

func (w *serverLogWriter) EnableFileLogging() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.fileEnabled = true
	if err := w.rotateLocked(); err != nil {
		w.fileEnabled = false
		if w.file != nil {
			_ = w.file.Close()
			w.file = nil
			w.fileDate = ""
		}
		return fmt.Errorf("enable log file %s: %w", w.basePath, err)
	}
	return nil
}

func (w *serverLogWriter) DisableFileLogging() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.fileEnabled = false
	w.fileDate = ""
	if w.file == nil {
		return nil
	}
	file := w.file
	w.file = nil
	if err := file.Close(); err != nil {
		return fmt.Errorf("close log file %s: %w", file.Name(), err)
	}
	return nil
}

func (w *serverLogWriter) rotateLocked() error {
	today := w.now().UTC().Format("2006-01-02")
	if w.file != nil && w.fileDate == today {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(w.basePath), 0700); err != nil {
		return err
	}
	path := w.basePath + "-" + today + ".log"
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	oldFile := w.file
	w.file = file
	w.fileDate = today
	if oldFile != nil {
		if err := oldFile.Close(); err != nil {
			return err
		}
	}
	return w.cleanupLocked(w.now().Add(-serverLogRetention))
}

func (w *serverLogWriter) cleanupLocked(cutoff time.Time) error {
	directory := filepath.Dir(w.basePath)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	baseName := filepath.Base(w.basePath)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, baseName+"-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		date := strings.TrimSuffix(strings.TrimPrefix(name, baseName+"-"), ".log")
		if _, err := time.Parse("2006-01-02", date); err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(directory, name)); err != nil {
			return err
		}
	}
	return nil
}

func (w *serverLogWriter) reportFileErrorLocked(err error) {
	message := err.Error()
	if message == w.lastError {
		return
	}
	_, _ = fmt.Fprintf(w.stdout, "ERROR: file logging failed for %s: %v\n", w.basePath, err)
	w.lastError = message
}

func (s *server) fileLoggingEnabled() (bool, error) {
	return readFileLoggingSetting(s.db)
}

func readFileLoggingSetting(db *sql.DB) (bool, error) {
	var value string
	err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", serverFileLoggingSetting).Scan(&value)
	if err == nil {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return false, fmt.Errorf("invalid %s setting: %w", serverFileLoggingSetting, err)
		}
		return enabled, nil
	}
	if err == sql.ErrNoRows {
		return false, nil
	}
	return false, fmt.Errorf("read %s setting: %w", serverFileLoggingSetting, err)
}

func withAccessLogging(next http.Handler, output io.Writer) http.Handler {
	accessLogger := log.New(output, "ACCESS ", log.LstdFlags)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &accessLogResponseWriter{ResponseWriter: w}
		started := time.Now()
		route := r.URL.EscapedPath()
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		if route == "" {
			route = "/"
		}
		if route == "/health" && status == http.StatusOK {
			return
		}
		accessLogger.Printf("method=%s route=%q status=%d duration=%s",
			r.Method, route, status, time.Since(started).Round(time.Microsecond))
	})
}

type accessLogResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *accessLogResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *accessLogResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *accessLogResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
