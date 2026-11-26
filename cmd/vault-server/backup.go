package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-co-op/gocron/v2"
)

const (
	serverBackupEnabledSetting = "automatic_server_backup"
	serverBackupCronSetting    = "server_backup_cron"
	serverBackupLastSetting    = "server_backup_last_success"
	defaultServerBackupCron    = "0 0 2 * * *"
	serverBackupRetention      = 30 * 24 * time.Hour
)

type serverBackupConfig struct {
	dataDir        string
	backupDir      string
	dbPath         string
	secretsDBPath  string
	operatorDBPath string
	auditDBPath    string
	masterKey      []byte
	secretsKey     []byte
	operatorKey    []byte
	allowPlaintext bool
}

type serverBackupMetadata struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Operators int       `json:"operators"`
	Secrets   int       `json:"secrets"`
	APITokens int       `json:"api_tokens"`
}

type serverBackupSummary struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Operators *int      `json:"operators"`
	Secrets   *int      `json:"secrets"`
	APITokens *int      `json:"api_tokens"`
}

func (s *server) listServerBackups(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	entries, err := os.ReadDir(s.backupConfig.backupDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list server backups"})
		return
	}
	backups := make([]serverBackupSummary, 0)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "vault-server-backup-") || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		path := filepath.Join(s.backupConfig.backupDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not inspect server backups"})
			return
		}
		if !info.Mode().IsRegular() {
			continue
		}
		summary, err := readServerBackupSummary(path, entry.Name(), info.ModTime())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read server backup metadata"})
			return
		}
		backups = append(backups, summary)
	}
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})
	writeJSON(w, http.StatusOK, map[string]any{"backups": backups})
}

func readServerBackupSummary(path, name string, modifiedAt time.Time) (serverBackupSummary, error) {
	summary := serverBackupSummary{Name: name, CreatedAt: modifiedAt.UTC()}
	file, err := os.Open(path)
	if err != nil {
		return serverBackupSummary{}, fmt.Errorf("open server backup: %w", err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return serverBackupSummary{}, fmt.Errorf("open compressed server backup: %w", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return summary, nil
		}
		if err != nil {
			return serverBackupSummary{}, fmt.Errorf("read server backup entry: %w", err)
		}
		if header.Name == "vault-server/metadata.json" && header.Typeflag == tar.TypeReg {
			const maxMetadataSize = 64 * 1024
			if header.Size < 0 || header.Size > maxMetadataSize {
				return serverBackupSummary{}, fmt.Errorf("server backup metadata is too large")
			}
			data, err := io.ReadAll(io.LimitReader(reader, maxMetadataSize+1))
			if err != nil {
				return serverBackupSummary{}, fmt.Errorf("read server backup metadata: %w", err)
			}
			var metadata serverBackupMetadata
			if err := json.Unmarshal(data, &metadata); err != nil {
				return serverBackupSummary{}, fmt.Errorf("decode server backup metadata: %w", err)
			}
			if metadata.Operators < 0 || metadata.Secrets < 0 || metadata.APITokens < 0 || metadata.CreatedAt.IsZero() {
				return serverBackupSummary{}, fmt.Errorf("server backup metadata contains invalid values")
			}
			summary.CreatedAt = metadata.CreatedAt.UTC()
			summary.Operators = &metadata.Operators
			summary.Secrets = &metadata.Secrets
			summary.APITokens = &metadata.APITokens
			return summary, nil
		}
		if strings.HasPrefix(header.Name, "vault-server/data/") && header.Typeflag == tar.TypeReg {
			return summary, nil
		}
	}
}

func (s *server) serverBackupMetadata(createdAt time.Time) (serverBackupMetadata, error) {
	metadata := serverBackupMetadata{
		CreatedAt: createdAt.UTC(),
	}
	if s.operatorDB != nil {
		if err := s.operatorDB.QueryRow("SELECT COUNT(*) FROM accounts WHERE role = 'operator'").Scan(&metadata.Operators); err != nil {
			return serverBackupMetadata{}, fmt.Errorf("count server backup operators: %w", err)
		}
	}
	if err := s.secretsDB.QueryRow("SELECT COUNT(*) FROM secrets").Scan(&metadata.Secrets); err != nil {
		return serverBackupMetadata{}, fmt.Errorf("count server backup secrets: %w", err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM api_tokens").Scan(&metadata.APITokens); err != nil {
		return serverBackupMetadata{}, fmt.Errorf("count server backup API tokens: %w", err)
	}
	return metadata, nil
}

func readServerBackupSettings(db *sql.DB) (bool, string, string, error) {
	enabled := false
	var enabledValue string
	err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", serverBackupEnabledSetting).Scan(&enabledValue)
	if err != nil && err != sql.ErrNoRows {
		return false, "", "", fmt.Errorf("read automatic server backup setting: %w", err)
	}
	if err == nil {
		if enabledValue != "true" && enabledValue != "false" {
			return false, "", "", fmt.Errorf("invalid %s setting", serverBackupEnabledSetting)
		}
		enabled = enabledValue == "true"
	}

	cronExpression := defaultServerBackupCron
	var configuredCron string
	err = db.QueryRow("SELECT value FROM server_settings WHERE key = ?", serverBackupCronSetting).Scan(&configuredCron)
	if err != nil && err != sql.ErrNoRows {
		return false, "", "", fmt.Errorf("read server backup cron setting: %w", err)
	}
	if err == nil && strings.TrimSpace(configuredCron) != "" {
		cronExpression = configuredCron
	}

	lastSuccess := ""
	err = db.QueryRow("SELECT value FROM server_settings WHERE key = ?", serverBackupLastSetting).Scan(&lastSuccess)
	if err != nil && err != sql.ErrNoRows {
		return false, "", "", fmt.Errorf("read last server backup time: %w", err)
	}
	return enabled, cronExpression, lastSuccess, nil
}

func validateServerBackupCron(expression string) error {
	fields := strings.Fields(expression)
	if len(fields) != 6 || strings.ContainsAny(expression, "\r\n") {
		return fmt.Errorf("backup schedule must be a six-field cron expression (second minute hour day month weekday)")
	}
	scheduler, err := gocron.NewScheduler(gocron.WithLocation(time.UTC))
	if err != nil {
		return fmt.Errorf("create backup schedule validator: %w", err)
	}
	_, jobErr := scheduler.NewJob(gocron.CronJob(expression, true), gocron.NewTask(func() {}))
	shutdownErr := scheduler.Shutdown()
	if jobErr != nil {
		return fmt.Errorf("invalid backup cron expression: %w", jobErr)
	}
	if shutdownErr != nil {
		return fmt.Errorf("stop backup schedule validator: %w", shutdownErr)
	}
	return nil
}

func (s *server) startBackupScheduler() error {
	scheduler, err := gocron.NewScheduler(
		gocron.WithLocation(time.UTC),
		gocron.WithLimitConcurrentJobs(1, gocron.LimitModeReschedule),
	)
	if err != nil {
		return fmt.Errorf("create server backup scheduler: %w", err)
	}
	s.backupCron = scheduler
	enabled, expression, _, err := readServerBackupSettings(s.db)
	if err != nil {
		_ = scheduler.Shutdown()
		return err
	}
	if enabled {
		if err := validateBackupDatabaseScope(s.backupConfig); err != nil {
			_ = scheduler.Shutdown()
			return err
		}
		if err := validateServerBackupCron(expression); err != nil {
			_ = scheduler.Shutdown()
			return err
		}
		job, err := scheduler.NewJob(
			gocron.CronJob(expression, true),
			gocron.NewTask(s.performScheduledBackup),
			gocron.WithName("automatic-vault-server-backup"),
		)
		if err != nil {
			_ = scheduler.Shutdown()
			return fmt.Errorf("schedule automatic server backup: %w", err)
		}
		s.backupJob = job
	}
	scheduler.Start()
	return nil
}

func (s *server) stopBackupScheduler() error {
	if s.backupCron == nil {
		return nil
	}
	return s.backupCron.Shutdown()
}

func (s *server) configureBackupSchedule(enabled bool, expression string) error {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()

	if enabled {
		if err := validateBackupDatabaseScope(s.backupConfig); err != nil {
			return err
		}
		if err := validateServerBackupCron(expression); err != nil {
			return err
		}
		if s.backupJob != nil {
			job, err := s.backupCron.Update(
				s.backupJob.ID(),
				gocron.CronJob(expression, true),
				gocron.NewTask(s.performScheduledBackup),
				gocron.WithName("automatic-vault-server-backup"),
			)
			if err != nil {
				return fmt.Errorf("update automatic server backup schedule: %w", err)
			}
			s.backupJob = job
			return nil
		}
		job, err := s.backupCron.NewJob(
			gocron.CronJob(expression, true),
			gocron.NewTask(s.performScheduledBackup),
			gocron.WithName("automatic-vault-server-backup"),
		)
		if err != nil {
			return fmt.Errorf("schedule automatic server backup: %w", err)
		}
		s.backupJob = job
		return nil
	}
	if s.backupJob == nil {
		return nil
	}
	if err := s.backupCron.RemoveJob(s.backupJob.ID()); err != nil {
		return fmt.Errorf("remove automatic server backup schedule: %w", err)
	}
	s.backupJob = nil
	return nil
}

func validateBackupDatabaseScope(config serverBackupConfig) error {
	if config.dataDir == "" {
		return nil
	}
	dataDir, err := filepath.EvalSymlinks(config.dataDir)
	if err != nil {
		return fmt.Errorf("resolve backup data directory: %w", err)
	}
	paths := []string{config.dbPath, config.dbPath + ".key", config.secretsDBPath, config.secretsDBPath + ".key", config.auditDBPath}
	if config.operatorDBPath != "" {
		paths = append(paths, config.operatorDBPath, config.operatorDBPath+".key")
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
				if parentErr != nil {
					return fmt.Errorf("resolve database directory for scheduled backup: %w", parentErr)
				}
				resolved = filepath.Join(parent, filepath.Base(path))
			} else {
				return fmt.Errorf("resolve database path for scheduled backup: %w", err)
			}
		}
		relative, err := filepath.Rel(dataDir, resolved)
		if err != nil {
			return fmt.Errorf("compare database path with backup data directory: %w", err)
		}
		if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("scheduled backups require all database files to be inside data directory %q", dataDir)
		}
	}
	return nil
}

func (s *server) performScheduledBackup() {
	if !s.backupRunMu.TryLock() {
		log.Printf("WARNING: skipping overlapping scheduled server backup")
		return
	}
	defer s.backupRunMu.Unlock()

	if err := os.MkdirAll(s.backupConfig.backupDir, 0700); err != nil {
		log.Printf("ERROR: could not create server backup directory: %v", err)
		s.recordServerBackupAudit("failure", "backup_directory_unavailable")
		return
	}
	log.Printf("Starting scheduled server backup maintenance")
	s.recordServerBackupAudit("started", "maintenance_started")
	s.beginMaintenance()
	reopened := false
	defer func() {
		if reopened {
			s.endMaintenance()
		}
	}()

	createdAt := time.Now().UTC()
	metadata, err := s.serverBackupMetadata(createdAt)
	if err != nil {
		log.Printf("ERROR: could not collect server backup metadata: %v", err)
		s.recordServerBackupAudit("failure", "metadata_collection_failed")
		reopened = true
		return
	}
	if err := s.closeDatabaseFiles(); err != nil {
		log.Printf("ERROR: could not close database files for server backup: %v", err)
		if reopenErr := s.reopenDatabaseFiles(); reopenErr != nil {
			log.Printf("CRITICAL: could not reopen database files after failed backup setup: %v", reopenErr)
			s.failMaintenance()
			return
		}
		reopened = true
		s.recordServerBackupAudit("failure", "database_close_failed")
		return
	}

	archivePath, backupErr := createServerDataBackupWithMetadata(s.backupConfig.dataDir, s.backupConfig.backupDir, metadata)
	reopenErr := s.reopenDatabaseFiles()
	if reopenErr != nil {
		log.Printf("CRITICAL: could not reopen database files after server backup: %v", reopenErr)
		s.failMaintenance()
		return
	}
	reopened = true

	if backupErr != nil {
		log.Printf("ERROR: scheduled server backup failed: %v", backupErr)
		s.recordServerBackupAudit("failure", "archive_failed")
		return
	}
	if err := s.saveServerBackupSuccess(time.Now().UTC()); err != nil {
		log.Printf("ERROR: server backup completed but its success time could not be saved: %v", err)
	}
	if err := pruneServerBackups(s.backupConfig.backupDir, time.Now().UTC().Add(-serverBackupRetention)); err != nil {
		log.Printf("WARNING: server backup completed but old backups could not be pruned: %v", err)
	}
	log.Printf("Scheduled server backup completed: %s", archivePath)
	s.recordServerBackupAudit("success", "archive_created")
}

func (s *server) closeDatabaseFiles() error {
	var failures []error
	if s.auditStore != nil {
		if err := s.auditStore.Close(); err != nil {
			failures = append(failures, fmt.Errorf("close audit database: %w", err))
		}
		s.auditStore = nil
	}
	if s.secretsDB != nil {
		if err := s.secretsDB.Close(); err != nil {
			failures = append(failures, fmt.Errorf("close secrets database: %w", err))
		}
		s.secretsDB = nil
	}
	if s.operatorDB != nil {
		if err := s.operatorDB.Close(); err != nil {
			failures = append(failures, fmt.Errorf("close operator database: %w", err))
		}
		s.operatorDB = nil
	}
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			failures = append(failures, fmt.Errorf("close application database: %w", err))
		}
		s.db = nil
	}
	return errors.Join(failures...)
}

func (s *server) reopenDatabaseFiles() error {
	db, _, err := openDatabaseWithOptions(s.backupConfig.dbPath, s.backupConfig.masterKey, s.backupConfig.allowPlaintext)
	if err != nil {
		return fmt.Errorf("reopen application database: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return fmt.Errorf("verify reopened application database: %w", err)
	}
	secretsDB, _, err := openDatabaseWithOptions(s.backupConfig.secretsDBPath, s.backupConfig.secretsKey, false)
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("reopen secrets database: %w", err)
	}
	if err := secretsDB.Ping(); err != nil {
		_ = db.Close()
		_ = secretsDB.Close()
		return fmt.Errorf("verify reopened secrets database: %w", err)
	}
	var operatorDB *sql.DB
	if s.backupConfig.operatorDBPath != "" {
		operatorDB, _, err = openDatabaseWithOptions(
			s.backupConfig.operatorDBPath,
			s.backupConfig.operatorKey,
			false,
		)
		if err != nil {
			_ = db.Close()
			_ = secretsDB.Close()
			return fmt.Errorf("reopen operator database: %w", err)
		}
		if err := operatorDB.Ping(); err != nil {
			_ = db.Close()
			_ = secretsDB.Close()
			_ = operatorDB.Close()
			return fmt.Errorf("verify reopened operator database: %w", err)
		}
	}
	auditStore, err := openAnnualAuditStore(s.backupConfig.auditDBPath)
	if err != nil {
		_ = db.Close()
		_ = secretsDB.Close()
		if operatorDB != nil {
			_ = operatorDB.Close()
		}
		return fmt.Errorf("reopen audit database: %w", err)
	}
	s.db = db
	s.secretsDB = secretsDB
	s.operatorDB = operatorDB
	s.auditStore = auditStore
	return nil
}

func (s *server) saveServerBackupSuccess(at time.Time) error {
	value := at.UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		serverBackupLastSetting,
		value,
	); err != nil {
		return fmt.Errorf("save server backup completion time: %w", err)
	}
	return nil
}

func (s *server) recordServerBackupAudit(outcome, detail string) {
	if s.auditStore == nil {
		log.Printf("WARNING: could not audit server backup: audit store unavailable")
		return
	}
	if err := s.auditStore.Record(time.Now().UTC().Unix(), "server_backup", outcome, "system", "", "system", "server-data", detail); err != nil {
		log.Printf("WARNING: could not audit server backup outcome: %v", err)
	}
}

func createServerDataBackup(dataDir, backupDir string, now time.Time) (string, error) {
	return createServerDataBackupWithMetadata(dataDir, backupDir, serverBackupMetadata{CreatedAt: now.UTC()})
}

func createServerDataBackupWithMetadata(dataDir, backupDir string, metadata serverBackupMetadata) (string, error) {
	source, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return "", fmt.Errorf("resolve server data directory: %w", err)
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return "", fmt.Errorf("inspect server data directory: %w", err)
	}
	if !sourceInfo.IsDir() {
		return "", fmt.Errorf("server data path %q is not a directory", source)
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", fmt.Errorf("create server backup directory: %w", err)
	}
	if err := os.Chmod(backupDir, 0700); err != nil {
		return "", fmt.Errorf("restrict server backup directory permissions: %w", err)
	}
	backupDir, err = filepath.EvalSymlinks(backupDir)
	if err != nil {
		return "", fmt.Errorf("resolve server backup directory: %w", err)
	}
	relativeBackup, err := filepath.Rel(source, backupDir)
	if err != nil {
		return "", fmt.Errorf("compare server data and backup directories: %w", err)
	}
	if relativeBackup == "." {
		return "", fmt.Errorf("server backup directory must differ from the data directory")
	}
	backupInsideData := relativeBackup != ".." && !strings.HasPrefix(relativeBackup, ".."+string(filepath.Separator))

	var files []string
	err = filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk server data directory: %w", walkErr)
		}
		if path == source {
			return nil
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return fmt.Errorf("resolve server data entry: %w", err)
		}
		if backupInsideData && (relative == relativeBackup || strings.HasPrefix(relative, relativeBackup+string(filepath.Separator))) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect server data entry: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("server data directory contains a symbolic link: %q", relative)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("server data directory contains a non-regular file: %q", relative)
		}
		if strings.ContainsAny(filepath.ToSlash(relative), "\r\n\\") {
			return fmt.Errorf("server data file path cannot be represented in the backup manifest: %q", relative)
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", fmt.Errorf("server data directory contains no files")
	}
	sort.Strings(files)
	archivePath := filepath.Join(backupDir, "vault-server-backup-"+metadata.CreatedAt.UTC().Format("20060102-150405.000000000")+".tar.gz")
	metadata.Name = filepath.Base(archivePath)
	metadata.CreatedAt = metadata.CreatedAt.UTC()
	if err := writeServerDataArchive(source, archivePath, files, metadata); err != nil {
		return "", err
	}
	return archivePath, nil
}

func writeServerDataArchive(source, archivePath string, files []string, metadata serverBackupMetadata) (resultErr error) {
	temp, err := os.CreateTemp(filepath.Dir(archivePath), ".vault-server-backup-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary server backup: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		if resultErr != nil {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0600); err != nil {
		return fmt.Errorf("restrict temporary backup permissions: %w", err)
	}

	gz := gzip.NewWriter(temp)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "vault-server/", Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
		return fmt.Errorf("write archive root directory: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "vault-server/data/", Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
		return fmt.Errorf("write archive data directory: %w", err)
	}
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encode server backup metadata: %w", err)
	}
	metadataBytes = append(metadataBytes, '\n')
	if err := tw.WriteHeader(&tar.Header{
		Name: "vault-server/metadata.json", Mode: 0600, Size: int64(len(metadataBytes)),
	}); err != nil {
		return fmt.Errorf("write server backup metadata header: %w", err)
	}
	if _, err := tw.Write(metadataBytes); err != nil {
		return fmt.Errorf("write server backup metadata: %w", err)
	}
	checksums := map[string]string{
		"metadata.json": fmt.Sprintf("%x", sha256.Sum256(metadataBytes)),
	}
	directories := make(map[string]struct{})
	for _, path := range files {
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return fmt.Errorf("resolve server data file: %w", err)
		}
		relative = filepath.ToSlash(relative)
		parent := filepath.ToSlash(filepath.Dir(relative))
		for parent != "." && parent != "" {
			directories[parent] = struct{}{}
			parent = filepath.ToSlash(filepath.Dir(parent))
		}
	}
	directoryNames := make([]string, 0, len(directories))
	for directory := range directories {
		directoryNames = append(directoryNames, directory)
	}
	sort.Strings(directoryNames)
	for _, directory := range directoryNames {
		name := filepath.ToSlash(filepath.Join("vault-server", "data", directory)) + "/"
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
			return fmt.Errorf("write backup directory %q: %w", name, err)
		}
	}
	for _, path := range files {
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return fmt.Errorf("resolve server data file: %w", err)
		}
		relative = filepath.ToSlash(relative)
		if err := addServerBackupFile(tw, path, relative, checksums); err != nil {
			return err
		}
	}
	if err := writeServerBackupManifest(tw, checksums, metadata.CreatedAt); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("finish backup tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("finish compressed server backup: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync server backup: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close server backup: %w", err)
	}
	if err := os.Rename(tempPath, archivePath); err != nil {
		return fmt.Errorf("install server backup: %w", err)
	}
	if err := os.Chmod(archivePath, 0600); err != nil {
		return fmt.Errorf("restrict server backup permissions: %w", err)
	}
	return nil
}

func addServerBackupFile(tw *tar.Writer, path, relative string, checksums map[string]string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect server data file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return fmt.Errorf("server data entry changed during backup: %q", relative)
	}
	input, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open server data file: %w", err)
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened server data file: %w", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("recheck server data file: %w", err)
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return fmt.Errorf("server data entry changed during backup: %q", relative)
	}
	name := filepath.ToSlash(filepath.Join("vault-server", "data", relative))
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: opened.Size(), ModTime: opened.ModTime()}); err != nil {
		return fmt.Errorf("write server backup file header: %w", err)
	}
	digest := sha256.New()
	if copied, err := io.CopyN(io.MultiWriter(tw, digest), input, opened.Size()); err != nil {
		return fmt.Errorf("write server backup file: %w", err)
	} else if copied != opened.Size() {
		return fmt.Errorf("server data file changed during backup: %q", relative)
	}
	checksums[filepath.ToSlash(filepath.Join("data", relative))] = fmt.Sprintf("%x", digest.Sum(nil))
	return nil
}

func writeServerBackupManifest(tw *tar.Writer, checksums map[string]string, createdAt time.Time) error {
	paths := make([]string, 0, len(checksums))
	for path := range checksums {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var contents strings.Builder
	fmt.Fprintf(&contents, "# Vault server data backup\n# Created-UTC: %s\n", createdAt.Format(time.RFC3339))
	for _, path := range paths {
		fmt.Fprintf(&contents, "%s  %s\n", checksums[path], path)
	}
	data := contents.String()
	if err := tw.WriteHeader(&tar.Header{Name: "vault-server/manifest.txt", Mode: 0600, Size: int64(len(data))}); err != nil {
		return fmt.Errorf("write server backup manifest header: %w", err)
	}
	if _, err := io.WriteString(tw, data); err != nil {
		return fmt.Errorf("write server backup manifest: %w", err)
	}
	return nil
}

func pruneServerBackups(directory string, cutoff time.Time) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read server backup directory: %w", err)
	}
	var failures []error
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "vault-server-backup-") || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			failures = append(failures, fmt.Errorf("inspect backup %q: %w", entry.Name(), err))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(path); err != nil {
			failures = append(failures, fmt.Errorf("remove expired backup %q: %w", entry.Name(), err))
		}
	}
	return errors.Join(failures...)
}
