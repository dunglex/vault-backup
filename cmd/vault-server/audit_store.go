package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	auditBatchMaxEvents = 64
	auditBatchWindow    = 2 * time.Millisecond
	auditQueueCapacity  = 1024
	auditInsertSQL      = `INSERT INTO audit_events(created_at, action, outcome, actor, client_ip, source, resource, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
)

type auditStore struct {
	mu         sync.Mutex
	submitMu   sync.RWMutex
	closeOnce  sync.Once
	basePath   string
	activeDB   *sql.DB
	activeYear int
	writeQueue chan *auditWriteRequest
	writerDone chan struct{}
	closed     bool
	closeErr   error
}

type auditWriteRequest struct {
	createdAt int64
	action    string
	outcome   string
	actor     string
	clientIP  string
	source    string
	resource  string
	detail    string
	queuedAt  time.Time
	result    chan auditWriteResult
}

type auditWriteResult struct {
	err          error
	queueWait    time.Duration
	rotationTime time.Duration
	writeTime    time.Duration
	queryCount   int
}

func openAnnualAuditStore(basePath string) (*auditStore, error) {
	if err := migrateLegacyAuditDatabase(basePath); err != nil {
		return nil, err
	}

	year := time.Now().UTC().Year()
	path := annualAuditPath(basePath, year)
	if err := os.Chmod(path, 0600); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("restrict active audit database permissions: %w", err)
	}
	db, err := openAuditDatabase(path)
	if err != nil {
		return nil, fmt.Errorf("open active audit database for %d: %w", year, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("restrict active audit database permissions: %w", err)
	}

	store := &auditStore{
		basePath:   basePath,
		activeDB:   db,
		activeYear: year,
		writeQueue: make(chan *auditWriteRequest, auditQueueCapacity),
		writerDone: make(chan struct{}),
	}
	go store.runAuditWriter()
	if err := store.sealOlderDatabases(year); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func annualAuditPath(basePath string, year int) string {
	extension := filepath.Ext(basePath)
	name := strings.TrimSuffix(filepath.Base(basePath), extension)
	return filepath.Join(filepath.Dir(basePath), fmt.Sprintf("%s-%04d%s", name, year, extension))
}

func migrateLegacyAuditDatabase(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect legacy audit database: %w", err)
	}

	legacyDB, err := openAuditDatabaseReadOnly(path)
	if err == nil {
		var markerExists int
		if queryErr := legacyDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'audit_store_migrations'").Scan(&markerExists); queryErr != nil {
			_ = legacyDB.Close()
			return fmt.Errorf("inspect legacy audit migration state: %w", queryErr)
		}
		if markerExists != 0 {
			var migrated int
			queryErr := legacyDB.QueryRow("SELECT migrated FROM audit_store_migrations WHERE name = 'annual-audit-v1'").Scan(&migrated)
			_ = legacyDB.Close()
			if queryErr == nil && migrated == 1 {
				if err := os.Chmod(path, 0400); err != nil {
					return fmt.Errorf("make migrated legacy audit database read-only: %w", err)
				}
				return nil
			}
			if queryErr != nil && queryErr != sql.ErrNoRows {
				return fmt.Errorf("read legacy audit migration state: %w", queryErr)
			}
			legacyDB = nil
		} else {
			_ = legacyDB.Close()
			legacyDB = nil
		}
	}
	if legacyDB == nil {
		legacyDB, err = openAuditDatabase(path)
		if err != nil {
			return fmt.Errorf("open legacy audit database for migration: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("open legacy audit database read-only: %w", err)
	}
	defer legacyDB.Close()

	if _, err := legacyDB.Exec(`CREATE TABLE IF NOT EXISTS audit_store_migrations (
		name TEXT PRIMARY KEY,
		migrated INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("prepare legacy audit migration: %w", err)
	}

	rows, err := legacyDB.Query(`
		SELECT id, created_at, action, outcome, actor, client_ip, source, resource, detail
		FROM audit_events
		ORDER BY created_at, id`)
	if err != nil {
		return fmt.Errorf("read legacy audit events: %w", err)
	}

	var targetYear int
	var targetDB *sql.DB
	var targetTx *sql.Tx
	closeTarget := func() error {
		if targetTx != nil {
			if err := targetTx.Commit(); err != nil {
				return err
			}
			targetTx = nil
		}
		if targetDB != nil {
			if _, err := targetDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
				return err
			}
			err := targetDB.Close()
			targetDB = nil
			return err
		}
		return nil
	}
	for rows.Next() {
		var id, createdAt int64
		var action, outcome, actor, clientIP, source, resource, detail string
		if err := rows.Scan(&id, &createdAt, &action, &outcome, &actor, &clientIP, &source, &resource, &detail); err != nil {
			_ = rows.Close()
			_ = closeTarget()
			return fmt.Errorf("scan legacy audit event: %w", err)
		}
		year := time.Unix(createdAt, 0).UTC().Year()
		if targetDB == nil || year != targetYear {
			if err := closeTarget(); err != nil {
				_ = rows.Close()
				return fmt.Errorf("commit migrated audit events: %w", err)
			}
			targetYear = year
			targetPath := annualAuditPath(path, year)
			if err := os.Chmod(targetPath, 0600); err != nil && !os.IsNotExist(err) {
				_ = rows.Close()
				return fmt.Errorf("prepare annual audit database permissions: %w", err)
			}
			targetDB, err = openAuditDatabase(targetPath)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("open annual audit database for %d: %w", year, err)
			}
			targetTx, err = targetDB.Begin()
			if err != nil {
				_ = rows.Close()
				_ = targetDB.Close()
				return fmt.Errorf("begin annual audit migration for %d: %w", year, err)
			}
		}
		if _, err := targetTx.Exec(`
			INSERT OR IGNORE INTO audit_events(id, created_at, action, outcome, actor, client_ip, source, resource, detail)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, createdAt, action, outcome, actor, clientIP, source, resource, detail,
		); err != nil {
			_ = rows.Close()
			_ = targetTx.Rollback()
			_ = targetDB.Close()
			return fmt.Errorf("migrate legacy audit event %d: %w", id, err)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		_ = closeTarget()
		return fmt.Errorf("iterate legacy audit events: %w", err)
	}
	if err := rows.Close(); err != nil {
		_ = closeTarget()
		return fmt.Errorf("close legacy audit events: %w", err)
	}
	if err := closeTarget(); err != nil {
		return fmt.Errorf("commit migrated audit events: %w", err)
	}

	if _, err := legacyDB.Exec(`
		INSERT INTO audit_store_migrations(name, migrated) VALUES ('annual-audit-v1', 1)
		ON CONFLICT(name) DO UPDATE SET migrated = 1`); err != nil {
		return fmt.Errorf("mark legacy audit migration complete: %w", err)
	}
	if _, err := legacyDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpoint legacy audit database: %w", err)
	}
	if err := legacyDB.Close(); err != nil {
		return fmt.Errorf("close legacy audit database: %w", err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		return fmt.Errorf("make legacy audit database read-only: %w", err)
	}
	return nil
}

func openAuditDatabaseReadOnly(path string) (*sql.DB, error) {
	u := &url.URL{Scheme: "file", Path: path}
	query := u.Query()
	query.Set("mode", "ro")
	query.Set("_pragma", "query_only(1)")
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func (s *auditStore) sealOlderDatabases(currentYear int) error {
	years, err := s.availableYearsLocked()
	if err != nil {
		return err
	}
	for _, year := range years {
		if year == currentYear {
			continue
		}
		path := annualAuditPath(s.basePath, year)
		if err := os.Chmod(path, 0400); err != nil {
			return fmt.Errorf("make archived audit database %d read-only: %w", year, err)
		}
		db, err := openAuditDatabaseReadOnly(path)
		if err == nil {
			if err := db.Close(); err != nil {
				return fmt.Errorf("close archived audit database %d: %w", year, err)
			}
			continue
		}
		if err := os.Chmod(path, 0600); err != nil {
			return fmt.Errorf("prepare archived audit database %d for recovery: %w", year, err)
		}
		db, err = openAuditDatabase(path)
		if err != nil {
			return fmt.Errorf("open archived audit database %d for recovery: %w", year, err)
		}
		if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			_ = db.Close()
			return fmt.Errorf("checkpoint archived audit database %d: %w", year, err)
		}
		if err := db.Close(); err != nil {
			return fmt.Errorf("close archived audit database %d: %w", year, err)
		}
		if err := os.Chmod(path, 0400); err != nil {
			return fmt.Errorf("make archived audit database %d read-only: %w", year, err)
		}
	}
	return nil
}

func (s *auditStore) availableYearsLocked() ([]int, error) {
	extension := filepath.Ext(s.basePath)
	name := strings.TrimSuffix(filepath.Base(s.basePath), extension)
	entries, err := os.ReadDir(filepath.Dir(s.basePath))
	if err != nil {
		return nil, fmt.Errorf("list audit databases: %w", err)
	}
	prefix := name + "-"
	suffix := extension
	years := make(map[int]struct{})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filename := entry.Name()
		if !strings.HasPrefix(filename, prefix) || !strings.HasSuffix(filename, suffix) {
			continue
		}
		yearText := strings.TrimSuffix(strings.TrimPrefix(filename, prefix), suffix)
		if len(yearText) != 4 {
			continue
		}
		year, err := strconv.Atoi(yearText)
		if err == nil {
			years[year] = struct{}{}
		}
	}
	years[time.Now().UTC().Year()] = struct{}{}
	result := make([]int, 0, len(years))
	for year := range years {
		result = append(result, year)
	}
	sort.Ints(result)
	return result, nil
}

func (s *auditStore) AvailableYears() ([]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.availableYearsLocked()
}

func (s *auditStore) withYear(year int, fn func(*sql.DB) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	currentYear := time.Now().UTC().Year()
	if year == currentYear {
		if s.activeYear != currentYear {
			if err := s.rotateLocked(currentYear); err != nil {
				return err
			}
		}
		return fn(s.activeDB)
	}
	path := annualAuditPath(s.basePath, year)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("audit database for %d does not exist", year)
	} else if err != nil {
		return fmt.Errorf("inspect audit database for %d: %w", year, err)
	}
	db, err := openAuditDatabaseReadOnly(path)
	if err != nil {
		return fmt.Errorf("open read-only audit database for %d: %w", year, err)
	}
	queryErr := fn(db)
	closeErr := db.Close()
	if queryErr != nil {
		return queryErr
	}
	if closeErr != nil {
		return fmt.Errorf("close read-only audit database for %d: %w", year, closeErr)
	}
	return nil
}

func (s *auditStore) rotateLocked(year int) error {
	if s.activeDB != nil {
		if _, err := s.activeDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			return fmt.Errorf("checkpoint audit database for %d: %w", s.activeYear, err)
		}
		if err := s.activeDB.Close(); err != nil {
			return fmt.Errorf("close audit database for %d: %w", s.activeYear, err)
		}
		if err := os.Chmod(annualAuditPath(s.basePath, s.activeYear), 0400); err != nil {
			return fmt.Errorf("make audit database for %d read-only: %w", s.activeYear, err)
		}
	}
	path := annualAuditPath(s.basePath, year)
	if err := os.Chmod(path, 0600); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("prepare audit database for %d: %w", year, err)
	}
	db, err := openAuditDatabase(path)
	if err != nil {
		return fmt.Errorf("open audit database for %d: %w", year, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = db.Close()
		return fmt.Errorf("restrict audit database permissions: %w", err)
	}
	s.activeDB = db
	s.activeYear = year
	return nil
}

func (s *auditStore) Record(createdAt int64, action, outcome, actor, clientIP, source, resource, detail string) error {
	return s.recordForRequest(nil, createdAt, action, outcome, actor, clientIP, source, resource, detail)
}

func (s *auditStore) recordForRequest(r *http.Request, createdAt int64, action, outcome, actor, clientIP, source, resource, detail string) error {
	request := &auditWriteRequest{
		createdAt: createdAt,
		action:    action,
		outcome:   outcome,
		actor:     actor,
		clientIP:  clientIP,
		source:    source,
		resource:  resource,
		detail:    detail,
		queuedAt:  time.Now(),
		result:    make(chan auditWriteResult, 1),
	}
	s.submitMu.RLock()
	if s.closed {
		s.submitMu.RUnlock()
		return fmt.Errorf("audit store is closed")
	}
	s.writeQueue <- request
	s.submitMu.RUnlock()

	result := <-request.result
	recordDBOperationMetrics(r, result.queueWait, 0, "audit_queue_wait")
	if result.rotationTime > 0 {
		recordDBOperationMetrics(r, result.rotationTime, 0, "audit_store_rotation")
	}
	recordDBOperationMetrics(r, result.writeTime, result.queryCount, "audit_batch_write")
	return result.err
}

func (s *auditStore) runAuditWriter() {
	defer close(s.writerDone)
	for first := range s.writeQueue {
		batch := []*auditWriteRequest{first}
		timer := time.NewTimer(auditBatchWindow)
		collecting := true
		for collecting && len(batch) < auditBatchMaxEvents {
			select {
			case request, ok := <-s.writeQueue:
				if !ok {
					collecting = false
					continue
				}
				batch = append(batch, request)
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
		s.writeAuditBatch(batch)
	}
}

func (s *auditStore) writeAuditBatch(batch []*auditWriteRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for start := 0; start < len(batch); {
		year := time.Unix(batch[start].createdAt, 0).UTC().Year()
		end := start + 1
		for end < len(batch) && time.Unix(batch[end].createdAt, 0).UTC().Year() == year {
			end++
		}

		group := batch[start:end]
		writeStarted := time.Now()
		rotationTime := time.Duration(0)
		var err error
		if s.activeDB == nil || s.activeYear != year {
			rotationStarted := time.Now()
			err = s.rotateLocked(year)
			rotationTime = time.Since(rotationStarted)
		}

		transactionTime := time.Duration(0)
		queryCounts := make([]int, len(group))
		if err == nil {
			transactionStarted := time.Now()
			queryCounts, err = s.insertAuditEvents(group)
			transactionTime = time.Since(transactionStarted)
		}

		for index, request := range group {
			request.result <- auditWriteResult{
				err:          err,
				queueWait:    writeStarted.Sub(request.queuedAt),
				rotationTime: rotationTime,
				writeTime:    transactionTime,
				queryCount:   queryCounts[index],
			}
		}
		start = end
	}
}

func (s *auditStore) insertAuditEvents(batch []*auditWriteRequest) ([]int, error) {
	queryCounts := make([]int, len(batch))
	tx, err := s.activeDB.Begin()
	if err != nil {
		return queryCounts, fmt.Errorf("begin audit batch transaction: %w", err)
	}
	defer tx.Rollback()

	statement, err := tx.Prepare(auditInsertSQL)
	if err != nil {
		return queryCounts, fmt.Errorf("prepare audit batch insert: %w", err)
	}
	statementOpen := true
	defer func() {
		if statementOpen {
			_ = statement.Close()
		}
	}()

	for index, request := range batch {
		queryCounts[index] = 1
		if _, err := statement.Exec(
			request.createdAt,
			request.action,
			request.outcome,
			request.actor,
			request.clientIP,
			request.source,
			request.resource,
			request.detail,
		); err != nil {
			return queryCounts, fmt.Errorf("insert audit event: %w", err)
		}
	}
	if err := statement.Close(); err != nil {
		statementOpen = false
		return queryCounts, fmt.Errorf("close audit batch insert: %w", err)
	}
	statementOpen = false
	if err := tx.Commit(); err != nil {
		return queryCounts, fmt.Errorf("commit audit batch: %w", err)
	}
	return queryCounts, nil
}

func (s *auditStore) Close() error {
	s.closeOnce.Do(func() {
		s.submitMu.Lock()
		s.closed = true
		close(s.writeQueue)
		s.submitMu.Unlock()

		<-s.writerDone
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.activeDB == nil {
			return
		}
		if _, err := s.activeDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			_ = s.activeDB.Close()
			s.activeDB = nil
			s.closeErr = fmt.Errorf("checkpoint active audit database: %w", err)
			return
		}
		if err := s.activeDB.Close(); err != nil {
			s.activeDB = nil
			s.closeErr = fmt.Errorf("close active audit database: %w", err)
			return
		}
		s.activeDB = nil
		if err := os.Chmod(annualAuditPath(s.basePath, s.activeYear), 0400); err != nil {
			s.closeErr = fmt.Errorf("make stopped audit database read-only: %w", err)
		}
	})
	return s.closeErr
}
