package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	serverFileLoggingSetting       = "file_logging"
	serverAccessLogDisabledSetting = "disable_access_log"
	serverLogRetention             = 7 * 24 * time.Hour
	serverLogQueueCapacity         = 1024
	serverLogBatchMaxBytes         = 64 * 1024
	serverLogBatchWindow           = 10 * time.Millisecond
)

type serverLogCommandKind uint8

const (
	serverLogWrite serverLogCommandKind = iota
	serverLogEnable
	serverLogDisable
	serverLogClose
)

type serverLogCommand struct {
	kind     serverLogCommandKind
	data     []byte
	date     string
	response chan error
}

type serverLogWriter struct {
	mu       sync.Mutex
	stdoutMu sync.Mutex
	stdout   io.Writer
	basePath string
	now      func() time.Time

	file              *os.File
	fileDate          string
	lastError         string
	fileEnabled       bool
	closed            bool
	commands          chan serverLogCommand
	workerDone        chan struct{}
	accessLogsEnabled atomic.Bool
}

func newServerLogWriter(stdout io.Writer, basePath string) *serverLogWriter {
	writer := &serverLogWriter{
		stdout:     stdout,
		basePath:   basePath,
		now:        time.Now,
		commands:   make(chan serverLogCommand, serverLogQueueCapacity),
		workerDone: make(chan struct{}),
	}
	writer.accessLogsEnabled.Store(true)
	go writer.runFileWriter()
	return writer
}

func (w *serverLogWriter) setAccessLoggingEnabled(enabled bool) {
	w.accessLogsEnabled.Store(enabled)
}

func (w *serverLogWriter) accessLoggingEnabled() bool {
	return w.accessLogsEnabled.Load()
}

func (w *serverLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.stdoutMu.Lock()
	stdoutBytes, stdoutErr := w.stdout.Write(p)
	w.stdoutMu.Unlock()
	if !w.fileEnabled || w.closed || len(p) == 0 {
		return stdoutBytes, stdoutErr
	}
	data := append([]byte(nil), p...)
	w.commands <- serverLogCommand{
		kind: serverLogWrite,
		data: data,
		date: w.now().UTC().Format("2006-01-02"),
	}
	return stdoutBytes, stdoutErr
}

func (w *serverLogWriter) EnableFileLogging() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("enable log file %s: writer is closed", w.basePath)
	}
	if w.fileEnabled {
		return nil
	}
	err := w.sendFileCommand(serverLogCommand{
		kind: serverLogEnable,
		date: w.now().UTC().Format("2006-01-02"),
	})
	if err != nil {
		return fmt.Errorf("enable log file %s: %w", w.basePath, err)
	}
	w.fileEnabled = true
	return nil
}

func (w *serverLogWriter) DisableFileLogging() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed || !w.fileEnabled {
		return nil
	}
	w.fileEnabled = false
	if err := w.sendFileCommand(serverLogCommand{kind: serverLogDisable}); err != nil {
		return err
	}
	return nil
}

func (w *serverLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.fileEnabled = false
	err := w.sendFileCommand(serverLogCommand{kind: serverLogClose})
	w.closed = true
	<-w.workerDone
	return err
}

func (w *serverLogWriter) sendFileCommand(command serverLogCommand) error {
	command.response = make(chan error, 1)
	w.commands <- command
	return <-command.response
}

func (w *serverLogWriter) runFileWriter() {
	defer close(w.workerDone)
	var pending *serverLogCommand
	for {
		var command serverLogCommand
		if pending != nil {
			command = *pending
			pending = nil
		} else {
			command = <-w.commands
		}
		switch command.kind {
		case serverLogWrite:
			pending = w.writeLogBatch(command)
		case serverLogEnable:
			err := w.rotateFile(command.date)
			if err != nil {
				err = errors.Join(err, w.closeFile())
			}
			command.response <- err
		case serverLogDisable:
			command.response <- w.closeFile()
		case serverLogClose:
			command.response <- w.closeFile()
			return
		}
	}
}

func (w *serverLogWriter) writeLogBatch(first serverLogCommand) *serverLogCommand {
	batch := append([]byte(nil), first.data...)
	batchDate := first.date
	timer := time.NewTimer(serverLogBatchWindow)
	var pending *serverLogCommand
	collecting := true
	for collecting && len(batch) < serverLogBatchMaxBytes {
		select {
		case command := <-w.commands:
			if command.kind == serverLogWrite &&
				command.date == batchDate &&
				len(batch)+len(command.data) <= serverLogBatchMaxBytes {
				batch = append(batch, command.data...)
				continue
			}
			pending = &command
			collecting = false
		case <-timer.C:
			collecting = false
		}
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	w.writeLogBatchToFile(batchDate, batch)
	return pending
}

func (w *serverLogWriter) writeLogBatchToFile(date string, batch []byte) {
	if err := w.rotateFile(date); err != nil {
		w.reportFileError(err)
		if w.file == nil || w.fileDate != date {
			return
		}
	}
	for len(batch) > 0 {
		n, err := w.file.Write(batch)
		batch = batch[n:]
		if err != nil {
			w.reportFileError(err)
			return
		}
		if n == 0 {
			w.reportFileError(io.ErrShortWrite)
			return
		}
	}
	w.lastError = ""
}

func (w *serverLogWriter) rotateFile(date string) error {
	if w.file != nil && w.fileDate == date {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(w.basePath), 0700); err != nil {
		return err
	}
	path := w.basePath + "-" + date + ".log"
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		return errors.Join(err, file.Close())
	}
	oldFile := w.file
	w.file = file
	w.fileDate = date
	var closeErr error
	if oldFile != nil {
		closeErr = oldFile.Close()
	}
	cleanupErr := w.cleanupLogs(w.now().Add(-serverLogRetention))
	return errors.Join(closeErr, cleanupErr)
}

func (w *serverLogWriter) cleanupLogs(cutoff time.Time) error {
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

func (w *serverLogWriter) closeFile() error {
	if w.file == nil {
		return nil
	}
	file := w.file
	w.file = nil
	w.fileDate = ""
	if err := file.Close(); err != nil {
		return fmt.Errorf("close log file %s: %w", file.Name(), err)
	}
	return nil
}

func (w *serverLogWriter) reportFileError(err error) {
	message := err.Error()
	if message == w.lastError {
		return
	}
	w.stdoutMu.Lock()
	_, _ = fmt.Fprintf(w.stdout, "ERROR: file logging failed for %s: %v\n", w.basePath, err)
	w.stdoutMu.Unlock()
	w.lastError = message
}

func (s *server) fileLoggingEnabled() (bool, error) {
	return readFileLoggingSetting(s.db)
}

func readFileLoggingSetting(db *sql.DB) (bool, error) {
	return readBooleanServerSetting(db, serverFileLoggingSetting)
}

func readAccessLogDisabledSetting(db *sql.DB) (bool, error) {
	return readBooleanServerSetting(db, serverAccessLogDisabledSetting)
}

func readBooleanServerSetting(db *sql.DB, setting string) (bool, error) {
	var value string
	err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", setting).Scan(&value)
	if err == nil {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return false, fmt.Errorf("invalid %s setting: %w", setting, err)
		}
		return enabled, nil
	}
	if err == sql.ErrNoRows {
		return false, nil
	}
	return false, fmt.Errorf("read %s setting: %w", setting, err)
}

type requestDBMetricsKey struct{}

type requestDBMetrics struct {
	mu         sync.Mutex
	duration   time.Duration
	queryCount int
	operations map[string]time.Duration
}

type requestTrackedRows struct {
	rows      *sql.Rows
	request   *http.Request
	operation string
	started   time.Time
	once      sync.Once
}

func trackDBRows(r *http.Request, query func() (*sql.Rows, error)) (*requestTrackedRows, error) {
	return trackDBRowsNamed(r, "other", query)
}

func trackDBRowsNamed(r *http.Request, operation string, query func() (*sql.Rows, error)) (*requestTrackedRows, error) {
	started := time.Now()
	rows, err := query()
	if err != nil {
		recordDBOperationMetrics(r, time.Since(started), 1, operation)
		return nil, err
	}
	return &requestTrackedRows{rows: rows, request: r, operation: operation, started: started}, nil
}

func (rows *requestTrackedRows) Next() bool {
	return rows.rows.Next()
}

func (rows *requestTrackedRows) Scan(dest ...any) error {
	return rows.rows.Scan(dest...)
}

func (rows *requestTrackedRows) Err() error {
	return rows.rows.Err()
}

func (rows *requestTrackedRows) Close() error {
	err := rows.rows.Close()
	rows.once.Do(func() {
		recordDBOperationMetrics(rows.request, time.Since(rows.started), 1, rows.operation)
	})
	return err
}

func recordDBMetrics(r *http.Request, duration time.Duration, queryCount int) {
	recordDBOperationMetrics(r, duration, queryCount, "other")
}

func recordDBOperationMetrics(r *http.Request, duration time.Duration, queryCount int, operation string) {
	metrics := requestDBMetricsFromRequest(r)
	if metrics == nil {
		return
	}
	metrics.mu.Lock()
	metrics.duration += duration
	metrics.queryCount += queryCount
	if metrics.operations == nil {
		metrics.operations = make(map[string]time.Duration)
	}
	metrics.operations[operation] += duration
	metrics.mu.Unlock()
}

func requestDBMetricsFromRequest(r *http.Request) *requestDBMetrics {
	if r == nil {
		return nil
	}
	metrics, ok := r.Context().Value(requestDBMetricsKey{}).(*requestDBMetrics)
	if !ok {
		return nil
	}
	return metrics
}

func measureDBOperation(r *http.Request, fn func() error) error {
	return measureDBOperationNamed(r, "other", fn)
}

func measureDBOperationNamed(r *http.Request, operation string, fn func() error) error {
	if requestDBMetricsFromRequest(r) == nil {
		return fn()
	}
	started := time.Now()
	err := fn()
	recordDBOperationMetrics(r, time.Since(started), 0, operation)
	return err
}

func measureDBQuery[T any](r *http.Request, fn func() (T, error)) (T, error) {
	return measureDBQueryNamed(r, "other", fn)
}

func measureDBQueryNamed[T any](r *http.Request, operation string, fn func() (T, error)) (T, error) {
	if requestDBMetricsFromRequest(r) == nil {
		return fn()
	}
	started := time.Now()
	result, err := fn()
	recordDBOperationMetrics(r, time.Since(started), 1, operation)
	return result, err
}

func formatDBOperationDurations(operations map[string]time.Duration) string {
	names := make([]string, 0, len(operations))
	for name := range operations {
		names = append(names, name)
	}
	sort.Strings(names)
	formatted := make([]string, 0, len(names))
	for _, name := range names {
		formatted = append(formatted, name+"="+operations[name].Round(time.Microsecond).String())
	}
	return strings.Join(formatted, ",")
}

func withAccessLogging(next http.Handler, output io.Writer, logAPIDBMetrics bool, accessLoggingEnabled func() bool) http.Handler {
	accessLogger := log.New(output, "ACCESS ", log.LstdFlags)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !accessLoggingEnabled() {
			next.ServeHTTP(w, r)
			return
		}
		recorder := &accessLogResponseWriter{ResponseWriter: w}
		started := time.Now()
		route := r.URL.EscapedPath()
		metrics := &requestDBMetrics{}
		ctx := r.Context()
		if logAPIDBMetrics && strings.HasPrefix(r.URL.Path, "/api/") {
			ctx = context.WithValue(ctx, requestDBMetricsKey{}, metrics)
		}
		next.ServeHTTP(recorder, r.WithContext(ctx))
		requestDuration := time.Since(started)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		if route == "" {
			route = "/"
		}
		if (route == "/health" || route == "/live") && status == http.StatusOK {
			return
		}
		if !logAPIDBMetrics {
			accessLogger.Printf("method=%s route=%q status=%d request_duration=%s",
				r.Method, route, status, requestDuration.Round(time.Microsecond))
			return
		}
		metrics.mu.Lock()
		dbDuration, dbQueryCount := metrics.duration, metrics.queryCount
		dbOperationDurations := formatDBOperationDurations(metrics.operations)
		metrics.mu.Unlock()
		accessLogger.Printf("method=%s route=%q status=%d request_duration=%s db_duration=%s db_query_count=%d db_operation_durations=%q",
			r.Method, route, status, requestDuration.Round(time.Microsecond), dbDuration.Round(time.Microsecond), dbQueryCount, dbOperationDurations)
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
