package main

import (
	"net/http"
	"os"
	"time"

	"vault-backup/internal/operator"
)

func (s *server) enableOperatorsExtension() error {
	if s.operatorDB != nil {
		return nil
	}
	if s.operatorDBPath == "" {
		return os.ErrInvalid
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

func (s *server) updateOperatorSecretPrefixes(w http.ResponseWriter, r *http.Request) {
	if handler := s.operatorHandlerOrUnavailable(w); handler != nil {
		handler.UpdateSecretPrefixes(w, r)
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
