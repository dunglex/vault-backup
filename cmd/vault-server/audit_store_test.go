package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAnnualAuditStoreMigratesLegacyEventsAndSealsPastYears(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "audit.db")
	legacyDB, err := openAuditDatabase(basePath)
	if err != nil {
		t.Fatal(err)
	}
	pastYearTime := time.Date(time.Now().UTC().Year()-1, time.January, 2, 3, 4, 5, 0, time.UTC)
	if _, err := legacyDB.Exec(`
		INSERT INTO audit_events(created_at, action, outcome, actor, client_ip, source, resource, detail)
		VALUES (?, 'read', 'success', 'admin', '127.0.0.1', 'web', 'secret', '')`,
		pastYearTime.Unix(),
	); err != nil {
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := openAnnualAuditStore(basePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if info, err := os.Stat(basePath); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0400 {
		t.Fatalf("legacy audit database permissions = %04o, want 0400", info.Mode().Perm())
	}

	pastYear := pastYearTime.Year()
	var migratedCount int
	if err := store.withYear(pastYear, func(db *sql.DB) error {
		return db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE resource = 'secret'").Scan(&migratedCount)
	}); err != nil {
		t.Fatalf("read migrated audit events: %v", err)
	}
	if migratedCount != 1 {
		t.Fatalf("migrated event count = %d, want 1", migratedCount)
	}

	if err := store.withYear(pastYear, func(db *sql.DB) error {
		_, err := db.Exec("DELETE FROM audit_events")
		return err
	}); err == nil {
		t.Fatal("expected archived audit database to reject writes")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = openAnnualAuditStore(basePath)
	if err != nil {
		t.Fatalf("reopen annual audit store: %v", err)
	}
	defer store.Close()
	migratedCount = 0
	if err := store.withYear(pastYear, func(db *sql.DB) error {
		return db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE resource = 'secret'").Scan(&migratedCount)
	}); err != nil {
		t.Fatalf("read migrated events after restart: %v", err)
	}
	if migratedCount != 1 {
		t.Fatalf("migrated event count after restart = %d, want 1", migratedCount)
	}
}

func TestAnnualAuditStoreRecordsInCurrentYearFile(t *testing.T) {
	store, err := openAnnualAuditStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC().Unix()
	if err := store.Record(now, "login", "success", "admin", "127.0.0.1", "web", "", ""); err != nil {
		t.Fatal(err)
	}
	year := time.Unix(now, 0).UTC().Year()
	if err := store.withYear(year, func(db *sql.DB) error {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action = 'login'").Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Errorf("current-year audit event count = %d, want 1", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditRecordMeasuresQueueAndBatchWrite(t *testing.T) {
	store, err := openAnnualAuditStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	metrics := &requestDBMetrics{}
	request := httptest.NewRequest("GET", "/api/v1/kv/metadata", nil).
		WithContext(context.WithValue(context.Background(), requestDBMetricsKey{}, metrics))
	now := time.Now().UTC().Unix()
	if err := store.recordForRequest(request, now, "list", "success", "admin", "127.0.0.1", "api", "kv", ""); err != nil {
		t.Fatal(err)
	}

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.queryCount != 1 {
		t.Fatalf("audit SQL query count = %d, want 1", metrics.queryCount)
	}
	for _, operation := range []string{"audit_queue_wait", "audit_batch_write"} {
		if _, ok := metrics.operations[operation]; !ok {
			t.Errorf("missing %q duration in request metrics", operation)
		}
	}
}

func TestAuditStoreSynchronouslyPersistsConcurrentRecords(t *testing.T) {
	store, err := openAnnualAuditStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const eventCount = 32
	now := time.Now().UTC().Unix()
	errors := make(chan error, eventCount)
	var writers sync.WaitGroup
	for index := 0; index < eventCount; index++ {
		writers.Add(1)
		go func(index int) {
			defer writers.Done()
			errors <- store.Record(now, "batch_test", "success", fmt.Sprintf("actor-%d", index), "127.0.0.1", "api", "kv", "")
		}(index)
	}
	writers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Errorf("write concurrent audit event: %v", err)
		}
	}

	year := time.Unix(now, 0).UTC().Year()
	if err := store.withYear(year, func(db *sql.DB) error {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action = 'batch_test'").Scan(&count); err != nil {
			return err
		}
		if count != eventCount {
			t.Errorf("persisted audit event count = %d, want %d", count, eventCount)
		}
		return nil
	}); err != nil {
		t.Fatalf("read persisted audit events: %v", err)
	}
}
