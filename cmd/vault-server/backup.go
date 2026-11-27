package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"vault-backup/internal/backup"
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

const serverBackupLastSetting = backup.LastSuccessSetting

func readServerBackupSummary(path, name string, modifiedAt time.Time) (serverBackupSummary, error) {
	return backup.ReadSummary(path, name, modifiedAt)
}

func validateServerBackupCron(expression string) error {
	return backup.ValidateCron(expression)
}

func backupConfig(config serverBackupConfig) backup.Config {
	return backup.Config{
		DataDir:        config.dataDir,
		BackupDir:      config.backupDir,
		DBPath:         config.dbPath,
		SecretsDBPath:  config.secretsDBPath,
		OperatorDBPath: config.operatorDBPath,
		AuditDBPath:    config.auditDBPath,
		MasterKey:      config.masterKey,
		SecretsKey:     config.secretsKey,
		OperatorKey:    config.operatorKey,
		AllowPlaintext: config.allowPlaintext,
	}
}

func createServerDataBackupWithMetadata(dataDir, backupDir string, metadata serverBackupMetadata) (string, error) {
	return backup.CreateWithMetadata(dataDir, backupDir, metadata)
}

func pruneServerBackups(directory string, cutoff time.Time) error {
	return backup.Prune(directory, cutoff)
}

func (s *server) newServerBackupHandler() *backup.Handler {
	return backup.NewHandler(s.db, backupConfig(s.backupConfig), backup.Dependencies{
		RequireAdmin:     s.requireAdmin,
		RequestHTTPS:     s.requestIsHTTPS,
		Enabled:          func() bool { return s.backupEnabled },
		Audit:            func(r *http.Request, action, outcome, detail string) { s.recordServerBackupAudit(r, outcome, detail) },
		Metadata:         s.serverBackupMetadata,
		CloseDatabases:   s.closeDatabaseFiles,
		ReopenDatabases:  s.reopenDatabaseFiles,
		BeginMaintenance: s.beginMaintenance,
		EndMaintenance:   s.endMaintenance,
		FailMaintenance:  s.failMaintenance,
		SaveSuccess:      s.saveServerBackupSuccess,
	})
}

func (s *server) backupHandlerOrNew() *backup.Handler {
	if s.backupHandler != nil {
		return s.backupHandler
	}
	s.backupHandler = s.newServerBackupHandler()
	return s.backupHandler
}

func (s *server) recordServerBackupAudit(r *http.Request, outcome, detail string) {
	if s.auditStore == nil {
		return
	}
	actor, source, clientIP := "system", "system", ""
	if r != nil {
		actor = s.auditRequestActor(r, "web")
		source = "web"
		clientIP = s.clientIP(r)
	}
	if err := s.auditStore.Record(
		time.Now().UTC().Unix(), "server_backup", outcome, actor, clientIP, source, "server-backup", detail,
	); err != nil {
		log.Printf("WARNING: could not write server backup audit event %s: %v", outcome, err)
	}
}

func (s *server) getBackupSettings(w http.ResponseWriter, r *http.Request) {
	s.backupHandlerOrNew().GetSettings(w, r)
}

func (s *server) updateBackupSettings(w http.ResponseWriter, r *http.Request) {
	s.backupHandlerOrNew().UpdateSettings(w, r)
}

func (s *server) testS3Connection(w http.ResponseWriter, r *http.Request) {
	s.backupHandlerOrNew().TestS3(w, r)
}

func (s *server) listServerBackups(w http.ResponseWriter, r *http.Request) {
	s.backupHandlerOrNew().List(w, r)
}

func (s *server) createServerBackupNow(w http.ResponseWriter, r *http.Request) {
	s.backupHandlerOrNew().Create(w, r)
}

func (s *server) restoreServerBackup(w http.ResponseWriter, r *http.Request) {
	s.backupHandlerOrNew().Restore(w, r)
}

func (s *server) serverBackupMetadata(createdAt time.Time) (serverBackupMetadata, error) {
	metadata := serverBackupMetadata{CreatedAt: createdAt.UTC(), SigningKey: s.backupConfig.masterKey}
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
	handler := s.backupHandlerOrNew()
	if err := handler.StartScheduler(); err != nil {
		return err
	}
	s.backupCron = handler.Scheduler()
	return nil
}

func (s *server) stopBackupScheduler() error {
	return s.backupHandlerOrNew().StopScheduler()
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
	if s.backupHandler == nil {
		s.backupHandler = s.newServerBackupHandler()
	} else {
		s.backupHandler.SetDB(db)
	}
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
