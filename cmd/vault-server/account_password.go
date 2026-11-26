package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (s *server) changeAccountPassword(w http.ResponseWriter, r *http.Request) {
	session, ok := s.accountTOTPRequest(w, r)
	if !ok {
		s.recordAuditEvent(r, "change_password", "failure", s.auditRequestActor(r, "web"), "web", "account", "unauthorized_or_https_required")
		return
	}
	var request struct {
		CurrentPassword   string `json:"current_password"`
		NewPassword       string `json:"new_password"`
		RepeatNewPassword string `json:"repeat_new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.recordAuditEvent(r, "change_password", "failure", session.username, "web", "account:"+session.username, "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.NewPassword), []byte(request.RepeatNewPassword)) != 1 {
		s.recordAuditEvent(r, "change_password", "failure", session.username, "web", "account:"+session.username, "passwords_do_not_match")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new passwords do not match"})
		return
	}
	if len(request.NewPassword) < 12 || len(request.NewPassword) > 72 {
		s.recordAuditEvent(r, "change_password", "failure", session.username, "web", "account:"+session.username, "invalid_password_length")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new password must be at least 12 characters and no more than 72 bytes"})
		return
	}

	db := s.accountDatabase(session.role)
	if db == nil {
		s.recordAuditEvent(r, "change_password", "failure", session.username, "web", "account:"+session.username, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read account"})
		return
	}
	var currentHash string
	if err := db.QueryRow("SELECT password_hash FROM accounts WHERE username = ?", session.username).Scan(&currentHash); err != nil {
		s.recordAuditEvent(r, "change_password", "failure", session.username, "web", "account:"+session.username, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read account"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(request.CurrentPassword)) != nil {
		s.recordAuditEvent(r, "change_password", "failure", session.username, "web", "account:"+session.username, "invalid_current_password")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.recordAuditEvent(r, "change_password", "failure", session.username, "web", "account:"+session.username, "password_hash_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not change password"})
		return
	}
	result, err := db.Exec(
		"UPDATE accounts SET password_hash = ?, must_change_password = 0 WHERE username = ? AND password_hash = ?",
		string(newHash),
		session.username,
		currentHash,
	)
	if err != nil {
		s.recordAuditEvent(r, "change_password", "failure", session.username, "web", "account:"+session.username, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not change password"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		s.recordAuditEvent(r, "change_password", "failure", session.username, "web", "account:"+session.username, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not change password"})
		return
	}
	if updated != 1 {
		s.recordAuditEvent(r, "change_password", "failure", session.username, "web", "account:"+session.username, "account_changed")
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account security settings changed; reload and try again"})
		return
	}
	s.recordAuditEvent(r, "change_password", "success", session.username, "web", "account:"+session.username, "")
	writeJSON(w, http.StatusOK, map[string]bool{
		"changed":              true,
		"must_change_password": false,
	})
}
