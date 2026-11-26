package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vault-backup/internal/backup"

	"github.com/go-co-op/gocron/v2"
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
type serverBackupMetadata = backup.Metadata
type serverBackupSummary = backup.Summary

const (
	serverBackupEnabledSetting = backup.AutomaticSetting
	serverBackupCronSetting    = backup.CronSetting
	serverBackupLastSetting    = backup.LastSuccessSetting
	defaultServerBackupCron    = backup.DefaultCron
	serverBackupRetention      = backup.Retention
)

func readServerBackupSummary(path, name string, modifiedAt time.Time) (serverBackupSummary, error) {
	return backup.ReadSummary(path, name, modifiedAt)
}

func readServerBackupSettings(db *sql.DB) (bool, string, string, error) {
	return backup.ReadSettings(db)
}

func validateServerBackupCron(expression string) error {
	return backup.ValidateCron(expression)
}

func validateBackupDatabaseScope(config serverBackupConfig) error {
	return backup.ValidateDatabaseScope(backup.Config{
		DataDir: config.dataDir, BackupDir: config.backupDir, DBPath: config.dbPath,
		SecretsDBPath: config.secretsDBPath, OperatorDBPath: config.operatorDBPath,
		AuditDBPath: config.auditDBPath, MasterKey: config.masterKey, SecretsKey: config.secretsKey,
		OperatorKey: config.operatorKey, AllowPlaintext: config.allowPlaintext,
	})
}

func createServerDataBackup(dataDir, backupDir string, now time.Time) (string, error) {
	return backup.Create(dataDir, backupDir, now)
}

func createServerDataBackupWithMetadata(dataDir, backupDir string, metadata serverBackupMetadata) (string, error) {
	return backup.CreateWithMetadata(dataDir, backupDir, metadata)
}

func pruneServerBackups(directory string, cutoff time.Time) error {
	return backup.Prune(directory, cutoff)
}

func (s *server) getBackupSettings(w http.ResponseWriter, r *http.Request) {
	if !s.backupEnabled {
		http.Error(w, "backup management is not enabled", http.StatusNotFound)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	enabled, cronExpression, lastSuccess, err := readServerBackupSettings(s.db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read backup settings"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"automatic_server_backup":    enabled,
		"server_backup_cron":         cronExpression,
		"server_backup_last_success": lastSuccess,
	})
}

func (s *server) updateBackupSettings(w http.ResponseWriter, r *http.Request) {
	if !s.backupEnabled {
		http.Error(w, "backup management is not enabled", http.StatusNotFound)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to change backup settings"})
		return
	}
	var request struct {
		AutomaticServerBackup *bool   `json:"automatic_server_backup"`
		ServerBackupCron      *string `json:"server_backup_cron"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid backup settings"})
		return
	}
	if request.AutomaticServerBackup == nil && request.ServerBackupCron == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no backup settings provided"})
		return
	}
	enabled, cronExpression, _, err := readServerBackupSettings(s.db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read backup settings"})
		return
	}
	if request.AutomaticServerBackup != nil {
		enabled = *request.AutomaticServerBackup
	}
	if request.ServerBackupCron != nil {
		cronExpression = strings.TrimSpace(*request.ServerBackupCron)
	}
	if len(cronExpression) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "server backup cron expression is too long"})
		return
	}
	if err := validateServerBackupCron(cronExpression); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if enabled {
		if err := validateBackupDatabaseScope(s.backupConfig); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save backup settings"})
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		serverBackupEnabledSetting,
		strconv.FormatBool(enabled),
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save backup settings"})
		return
	}
	if _, err := tx.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		serverBackupCronSetting,
		cronExpression,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save backup settings"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save backup settings"})
		return
	}
	if err := s.configureBackupSchedule(enabled, cronExpression); err != nil {
		log.Printf("ERROR: backup settings saved but schedule could not be updated: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "settings were saved but the backup schedule could not be applied; restart the server to apply it"})
		return
	}
	s.recordAuditEvent(r, "update_settings", "success", s.auditRequestActor(r, "web"), "web", "backup-settings",
		serverBackupEnabledSetting+"="+strconv.FormatBool(enabled)+","+serverBackupCronSetting+"="+cronExpression)
	_, _, lastSuccess, err := readServerBackupSettings(s.db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "backup settings were saved but could not be reloaded"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"automatic_server_backup":    enabled,
		"server_backup_cron":         cronExpression,
		"server_backup_last_success": lastSuccess,
	})
}

func (s *server) listServerBackups(w http.ResponseWriter, r *http.Request) {
	if !s.backupEnabled {
		http.Error(w, "backup management is not enabled", http.StatusNotFound)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	backups, err := backup.List(s.backupConfig.backupDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read server backups"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backups": backups})
}

func (s *server) createServerBackupNow(w http.ResponseWriter, r *http.Request) {
	if !s.backupEnabled {
		http.Error(w, "backup management is not enabled", http.StatusNotFound)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to create server backups"})
		return
	}
	if s.backupRunMu.TryLock() {
		defer s.backupRunMu.Unlock()
	} else {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a server backup or restore is already in progress"})
		return
	}
	if err := os.MkdirAll(s.backupConfig.backupDir, 0700); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create server backup directory"})
		return
	}
	s.beginMaintenance()
	defer s.endMaintenance()
	createdAt := time.Now().UTC()
	metadata, err := s.serverBackupMetadata(createdAt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not collect server backup metadata"})
		return
	}
	if err := s.closeDatabaseFiles(); err != nil {
		_ = s.reopenDatabaseFiles()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not pause databases for server backup"})
		return
	}
	archivePath, backupErr := createServerDataBackupWithMetadata(s.backupConfig.dataDir, s.backupConfig.backupDir, metadata)
	reopenErr := s.reopenDatabaseFiles()
	if backupErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create server backup"})
		return
	}
	if reopenErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server backup created but databases could not be reopened"})
		return
	}
	if err := s.saveServerBackupSuccess(time.Now().UTC()); err != nil {
		log.Printf("ERROR: server backup completed but success time could not be saved: %v", err)
	}
	_ = pruneServerBackups(s.backupConfig.backupDir, time.Now().UTC().Add(-serverBackupRetention))
	writeJSON(w, http.StatusCreated, map[string]string{"name": filepath.Base(archivePath)})
}

func (s *server) restoreServerBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupEnabled {
		http.Error(w, "backup management is not enabled", http.StatusNotFound)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to restore server backups"})
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid restore request"})
		return
	}
	if s.backupRunMu.TryLock() {
		defer s.backupRunMu.Unlock()
	} else {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a server backup or restore is already in progress"})
		return
	}
	s.beginMaintenance()
	defer s.endMaintenance()
	if err := s.closeDatabaseFiles(); err != nil {
		_ = s.reopenDatabaseFiles()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not pause databases for server restore"})
		return
	}
	restoreErr := backup.Restore(s.backupConfig.backupDir, s.backupConfig.dataDir, request.Name)
	reopenErr := s.reopenDatabaseFiles()
	if restoreErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": restoreErr.Error()})
		return
	}
	if reopenErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server data restored but databases could not be reopened"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": request.Name})
}

func (s *server) serverBackupMetadata(createdAt time.Time) (serverBackupMetadata, error) {
	metadata := serverBackupMetadata{CreatedAt: createdAt.UTC()}
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

func (s *server) startBackupScheduler() error {
	enabledExtension, err := backup.ReadExtensionEnabled(s.db)
	if err != nil {
		return err
	}
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
	if enabledExtension && enabled {
		if err := validateBackupDatabaseScope(s.backupConfig); err != nil {
			_ = scheduler.Shutdown()
			return err
		}
		job, err := scheduler.NewJob(gocron.CronJob(expression, true), gocron.NewTask(s.performScheduledBackup), gocron.WithName("automatic-vault-server-backup"))
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
	if s.backupCron == nil {
		return nil
	}
	if enabled {
		if err := validateBackupDatabaseScope(s.backupConfig); err != nil {
			return err
		}
		if s.backupJob != nil {
			job, err := s.backupCron.Update(s.backupJob.ID(), gocron.CronJob(expression, true), gocron.NewTask(s.performScheduledBackup), gocron.WithName("automatic-vault-server-backup"))
			if err != nil {
				return err
			}
			s.backupJob = job
			return nil
		}
		job, err := s.backupCron.NewJob(gocron.CronJob(expression, true), gocron.NewTask(s.performScheduledBackup), gocron.WithName("automatic-vault-server-backup"))
		if err != nil {
			return err
		}
		s.backupJob = job
		return nil
	}
	if s.backupJob != nil {
		if err := s.backupCron.RemoveJob(s.backupJob.ID()); err != nil {
			return err
		}
		s.backupJob = nil
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
		return
	}
	s.beginMaintenance()
	defer s.endMaintenance()
	createdAt := time.Now().UTC()
	metadata, err := s.serverBackupMetadata(createdAt)
	if err != nil {
		log.Printf("ERROR: could not collect server backup metadata: %v", err)
		return
	}
	if err := s.closeDatabaseFiles(); err != nil {
		_ = s.reopenDatabaseFiles()
		return
	}
	archivePath, backupErr := createServerDataBackupWithMetadata(s.backupConfig.dataDir, s.backupConfig.backupDir, metadata)
	reopenErr := s.reopenDatabaseFiles()
	if backupErr != nil {
		log.Printf("ERROR: scheduled server backup failed: %v", backupErr)
		return
	}
	if reopenErr != nil {
		log.Printf("CRITICAL: could not reopen databases after server backup: %v", reopenErr)
		s.failMaintenance()
		return
	}
	if err := s.saveServerBackupSuccess(time.Now().UTC()); err != nil {
		log.Printf("ERROR: server backup completed but success time could not be saved: %v", err)
	}
	_ = pruneServerBackups(s.backupConfig.backupDir, time.Now().UTC().Add(-serverBackupRetention))
	log.Printf("Scheduled server backup completed: %s", archivePath)
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
	secretsDB, _, err := openDatabaseWithOptions(s.backupConfig.secretsDBPath, s.backupConfig.secretsKey, false)
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("reopen secrets database: %w", err)
	}
	var operatorDB *sql.DB
	if s.backupConfig.operatorDBPath != "" {
		operatorDB, _, err = openDatabaseWithOptions(s.backupConfig.operatorDBPath, s.backupConfig.operatorKey, false)
		if err != nil {
			_ = db.Close()
			_ = secretsDB.Close()
			return fmt.Errorf("reopen operator database: %w", err)
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
	if operatorDB != nil {
		s.operatorHandler = s.newOperatorHandler()
	}
	s.auditStore = auditStore
	return nil
}

func (s *server) saveServerBackupSuccess(at time.Time) error {
	_, err := s.db.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		serverBackupLastSetting,
		at.UTC().Format(time.RFC3339),
	)
	return err
}
