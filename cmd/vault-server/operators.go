package main

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type operatorRequest struct {
	Username             string `json:"username"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"password_confirmation"`
}

type operatorSummary struct {
	Username      string `json:"username"`
	Locked        bool   `json:"locked"`
	MFAEnabled    bool   `json:"mfa_enabled"`
	MFAConfigured bool   `json:"mfa_configured"`
}

func (s *server) listOperators(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	rows, err := s.db.Query("SELECT username FROM accounts WHERE role = 'operator' ORDER BY username")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
		return
	}
	defer rows.Close()

	operators := make([]string, 0)
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
			return
		}
		operators = append(operators, username)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"operators": operators})
}

func (s *server) listOperatorDetails(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	rows, err := s.db.Query(`
		SELECT username, locked, totp_enabled, (totp_secret IS NOT NULL AND totp_secret != '')
		FROM accounts WHERE role = 'operator' ORDER BY username`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
		return
	}
	defer rows.Close()

	operators := make([]operatorSummary, 0)
	for rows.Next() {
		var operator operatorSummary
		var locked, mfaEnabled, mfaPending int
		if err := rows.Scan(&operator.Username, &locked, &mfaEnabled, &mfaPending); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
			return
		}
		operator.Locked = locked == 1
		operator.MFAEnabled = mfaEnabled == 1
		operator.MFAConfigured = operator.MFAEnabled || mfaPending == 1
		operators = append(operators, operator)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]operatorSummary{"operators": operators})
}

func (s *server) setOperatorLock(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request struct {
		Username string `json:"username"`
		Locked   *bool  `json:"locked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Locked == nil {
		s.recordAuditEvent(r, "update_operator_lock", "failure", s.auditRequestActor(r, "web"), "web", "", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and locked status are required"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		s.recordAuditEvent(r, "update_operator_lock", "failure", s.auditRequestActor(r, "web"), "web", "", "invalid_username")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid username is required"})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update operator"})
		return
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow("SELECT 1 FROM accounts WHERE username = ? AND role = 'operator'", request.Username).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			s.recordAuditEvent(r, "update_operator_lock", "failure", s.auditRequestActor(r, "web"), "web", "operator:"+request.Username, "operator_not_found")
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operator"})
		return
	}
	if _, err := tx.Exec("UPDATE accounts SET locked = ? WHERE username = ? AND role = 'operator'", *request.Locked, request.Username); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update operator"})
		return
	}
	if *request.Locked {
		if _, err := tx.Exec("DELETE FROM web_sessions WHERE username = ?", request.Username); err != nil {
			log.Printf("ERROR: could not revoke locked operator sessions: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke operator sessions"})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update operator"})
		return
	}
	if *request.Locked {
		s.removeOperatorSessionsFromCache(request.Username)
	}
	action := "unlock_operator"
	if *request.Locked {
		action = "lock_operator"
	}
	s.recordAuditEvent(r, action, "success", s.auditRequestActor(r, "web"), "web", "operator:"+request.Username, "")
	writeJSON(w, http.StatusOK, map[string]any{"username": request.Username, "locked": *request.Locked})
}

func (s *server) removeOperatorTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.recordAuditEvent(r, "remove_operator_mfa", "failure", s.auditRequestActor(r, "web"), "web", "", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		s.recordAuditEvent(r, "remove_operator_mfa", "failure", s.auditRequestActor(r, "web"), "web", "", "invalid_username")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid username is required"})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator two-factor authentication"})
		return
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow("SELECT 1 FROM accounts WHERE username = ? AND role = 'operator'", request.Username).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			s.recordAuditEvent(r, "remove_operator_mfa", "failure", s.auditRequestActor(r, "web"), "web", "operator:"+request.Username, "operator_not_found")
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operator"})
		return
	}
	if _, err := tx.Exec(
		"UPDATE accounts SET totp_secret = NULL, totp_enabled = 0, totp_recovery_codes = '[]' WHERE username = ? AND role = 'operator'",
		request.Username,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator two-factor authentication"})
		return
	}
	if _, err := tx.Exec("DELETE FROM web_sessions WHERE username = ?", request.Username); err != nil {
		log.Printf("ERROR: could not revoke operator sessions after MFA reset: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke operator sessions"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator two-factor authentication"})
		return
	}
	s.removeOperatorSessionsFromCache(request.Username)
	s.recordAuditEvent(r, "remove_operator_mfa", "success", s.auditRequestActor(r, "web"), "web", "operator:"+request.Username, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"username":       request.Username,
		"mfa_enabled":    false,
		"mfa_configured": false,
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

func (s *server) createOperator(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request operatorRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required and must be at most 128 characters"})
		return
	}
	generatedPassword := request.Password == "" && request.PasswordConfirmation == ""
	if (request.Password == "") != (request.PasswordConfirmation == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passwords must both be provided or omitted"})
		return
	}
	if generatedPassword {
		password, err := generateOperatorTemporaryPassword()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate operator password"})
			return
		}
		request.Password = password
		request.PasswordConfirmation = request.Password
	}
	if subtle.ConstantTimeCompare([]byte(request.Password), []byte(request.PasswordConfirmation)) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passwords do not match"})
		return
	}
	if len(request.Password) < 12 || len(request.Password) > 72 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 12 characters and no more than 72 bytes"})
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create operator"})
		return
	}
	result, err := s.db.Exec(
		"INSERT INTO accounts(username, password_hash, role, must_change_password) VALUES (?, ?, 'operator', 1) ON CONFLICT(username) DO NOTHING",
		request.Username,
		string(passwordHash),
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create operator"})
		return
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create operator"})
		return
	}
	if inserted == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an account with that username already exists"})
		return
	}
	s.recordAuditEvent(r, "create_operator", "success", s.auditRequestActor(r, "web"), "web", "operator:"+request.Username, "")
	response := map[string]any{
		"username":             request.Username,
		"role":                 "operator",
		"must_change_password": true,
	}
	if generatedPassword {
		response["initial_password"] = request.Password
	}
	writeJSON(w, http.StatusCreated, response)
}

func generateOperatorTemporaryPassword() (string, error) {
	length, err := rand.Int(rand.Reader, big.NewInt(9))
	if err != nil {
		return "", err
	}
	randomBytes := make([]byte, 15)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", err
	}
	password := base64.RawURLEncoding.EncodeToString(randomBytes)
	return password[:12+length.Int64()], nil
}

func (s *server) resetOperatorPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	actor := s.auditRequestActor(r, "web")
	if r.TLS == nil {
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", "", "https_required")
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", "", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", "", "invalid_username")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid username is required"})
		return
	}
	resource := "operator:" + request.Username
	temporaryPassword, err := generateOperatorTemporaryPassword()
	if err != nil {
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", resource, "password_generation_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(temporaryPassword), bcrypt.DefaultCost)
	if err != nil {
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", resource, "password_hash_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow(
		"SELECT 1 FROM accounts WHERE username = ? AND role = 'operator'",
		request.Username,
	).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", resource, "operator_not_found")
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
			return
		}
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operator"})
		return
	}
	result, err := tx.Exec(
		"UPDATE accounts SET password_hash = ?, must_change_password = 1 WHERE username = ? AND role = 'operator'",
		string(passwordHash),
		request.Username,
	)
	if err != nil {
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}
	if updated != 1 {
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", resource, "operator_not_found")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
		return
	}
	if _, err := tx.Exec("DELETE FROM web_sessions WHERE username = ?", request.Username); err != nil {
		log.Printf("ERROR: could not revoke sessions after operator password reset: %v", err)
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", resource, "session_revocation_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke operator sessions"})
		return
	}
	if err := tx.Commit(); err != nil {
		s.recordAuditEvent(r, "reset_operator_password", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}
	s.removeOperatorSessionsFromCache(request.Username)
	s.recordAuditEvent(r, "reset_operator_password", "success", actor, "web", resource, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"username":             request.Username,
		"temporary_password":   temporaryPassword,
		"must_change_password": true,
	})
}

func (s *server) deleteOperator(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid username is required"})
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator"})
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec("DELETE FROM accounts WHERE username = ? AND role = 'operator'", request.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator"})
		return
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator"})
		return
	}
	if deleted == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
		return
	}
	if _, err := tx.Exec("DELETE FROM web_sessions WHERE username = ?", request.Username); err != nil {
		log.Printf("ERROR: could not revoke deleted operator sessions: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke operator sessions"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator"})
		return
	}
	s.mu.Lock()
	for token, session := range s.sessions {
		if session.username == request.Username {
			delete(s.sessions, token)
		}
	}
	s.mu.Unlock()
	s.recordAuditEvent(r, "delete_operator", "success", s.auditRequestActor(r, "web"), "web", "operator:"+request.Username, "")
	writeJSON(w, http.StatusOK, map[string]string{"username": request.Username, "status": "deleted"})
}
