package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"vault-backup/internal/operator"
)

const operatorExtensionEnabledSetting = "operator_extension_enabled"

func resolveOperatorDatabasePath(db *sql.DB, config serverConfig) (string, bool, error) {
	if config.OperatorDBPath != "" {
		return config.OperatorDBPath, false, nil
	}

	var value string
	err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", operatorExtensionEnabledSetting).Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", false, fmt.Errorf("read operator extension setting: %w", err)
	}
	if err == nil && value != "true" && value != "false" {
		return "", false, fmt.Errorf("invalid %s setting", operatorExtensionEnabledSetting)
	}
	if value == "false" {
		return "", false, nil
	}

	path := defaultOperatorDatabasePath(config.DBPath)
	if path == config.SecretsDBPath || path == config.AuditDBPath || path == config.DBPath {
		if value == "true" {
			return "", false, fmt.Errorf("operator database path must differ from the app, secrets, and audit database paths")
		}
		return "", false, nil
	}
	if value == "" {
		var adminExists bool
		if err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM accounts WHERE role = 'admin')").Scan(&adminExists); err != nil {
			return "", false, fmt.Errorf("check operator extension setup: %w", err)
		}
		if !adminExists {
			return "", false, nil
		}
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		} else if err != nil {
			return "", false, fmt.Errorf("check operator database: %w", err)
		}
	}
	for _, file := range []string{path, path + ".key"} {
		if _, err := os.Stat(file); err != nil {
			return "", false, fmt.Errorf("operator extension requires existing database and key: %w", err)
		}
	}
	return path, value == "", nil
}

func (s *server) enableOperatorsExtension() error {
	if s.operatorDB != nil {
		return nil
	}
	if s.operatorDBPath == "" {
		return os.ErrInvalid
	}
	if s.operatorDBPath == s.backupConfig.dbPath || s.operatorDBPath == s.backupConfig.secretsDBPath || s.operatorDBPath == s.backupConfig.auditDBPath {
		return fmt.Errorf("operator database path must differ from the app, secrets, and audit database paths")
	}
	masterKey, err := loadOrCreateKey(s.operatorDBPath+".key", s.dbPassword)
	if err != nil {
		return err
	}
	db, _, err := openDatabaseWithOptions(s.operatorDBPath, masterKey, false)
	if err != nil {
		return err
	}
	if err := operator.Initialize(db); err != nil {
		_ = db.Close()
		return err
	}
	if err := os.Chmod(s.operatorDBPath, 0600); err != nil {
		_ = db.Close()
		return err
	}
	s.operatorDB = db
	s.operatorMasterKey = masterKey
	s.operatorHandler = s.newOperatorHandler()
	s.backupConfig.operatorDBPath = s.operatorDBPath
	s.backupConfig.operatorKey = masterKey
	return nil
}

func (s *server) newOperatorHandler() *operator.Handler {
	return operator.NewHandler(s.operatorDB, operator.Dependencies{
		RequireAdmin:   s.requireAdmin,
		Audit:          s.recordAuditEvent,
		Actor:          s.auditRequestActor,
		AccountExists:  s.accountExists,
		RevokeTokens:   s.revokeOperatorTokens,
		RevokeSessions: s.removeOperatorSessionsFromCache,
		ValidPath:      validSecretPath,
		ValidMount:     validSecretMount,
		MountExists: func(mount string) (bool, error) {
			return s.mountExists(mount, false)
		},
	})
}

func (s *server) removeOperatorSessionsFromCache(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, session := range s.sessions {
		if session.username == username {
			delete(s.sessions, token)
		}
	}
}

func (s *server) revokeOperatorTokens(username string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	if _, err := tx.Exec(
		"UPDATE managed_client_certificates SET revoked_at = ? WHERE token_id IN (SELECT id FROM api_tokens WHERE created_by = ?) AND revoked_at IS NULL",
		now, username,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(
		"UPDATE api_tokens SET revoked_at = ? WHERE created_by = ? AND revoked_at IS NULL",
		now, username,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *server) operatorHandlerOrUnavailable(w http.ResponseWriter) *operator.Handler {
	if s.operatorHandler == nil {
		http.Error(w, "operator management is not enabled", http.StatusNotFound)
		return nil
	}
	return s.operatorHandler
}

func (s *server) listOperators(w http.ResponseWriter, r *http.Request) {
	if handler := s.operatorHandlerOrUnavailable(w); handler != nil {
		handler.ListOperators(w, r)
	}
}

func (s *server) listOperatorDetails(w http.ResponseWriter, r *http.Request) {
	if handler := s.operatorHandlerOrUnavailable(w); handler != nil {
		handler.ListOperatorDetails(w, r)
	}
}

func (s *server) updateOperatorSecretMounts(w http.ResponseWriter, r *http.Request) {
	if handler := s.operatorHandlerOrUnavailable(w); handler != nil {
		handler.UpdateSecretMounts(w, r)
	}
}

func (s *server) setOperatorLock(w http.ResponseWriter, r *http.Request) {
	if handler := s.operatorHandlerOrUnavailable(w); handler != nil {
		handler.SetOperatorLock(w, r)
	}
}

func (s *server) removeOperatorTOTP(w http.ResponseWriter, r *http.Request) {
	if handler := s.operatorHandlerOrUnavailable(w); handler != nil {
		handler.RemoveOperatorTOTP(w, r)
	}
}

func (s *server) createOperator(w http.ResponseWriter, r *http.Request) {
	if handler := s.operatorHandlerOrUnavailable(w); handler != nil {
		handler.CreateOperator(w, r)
	}
}

func (s *server) resetOperatorPassword(w http.ResponseWriter, r *http.Request) {
	if handler := s.operatorHandlerOrUnavailable(w); handler != nil {
		handler.ResetOperatorPassword(w, r)
	}
}

func (s *server) deleteOperator(w http.ResponseWriter, r *http.Request) {
	if handler := s.operatorHandlerOrUnavailable(w); handler != nil {
		handler.DeleteOperator(w, r)
	}
}
