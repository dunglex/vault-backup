package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type operatorRequest struct {
	Username             string `json:"username"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"password_confirmation"`
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
	if subtle.ConstantTimeCompare([]byte(request.Password), []byte(request.PasswordConfirmation)) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passwords do not match"})
		return
	}
	if len(request.Password) < 12 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 12 characters"})
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create operator"})
		return
	}
	result, err := s.db.Exec(
		"INSERT INTO accounts(username, password_hash, role) VALUES (?, ?, 'operator') ON CONFLICT(username) DO NOTHING",
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
	writeJSON(w, http.StatusCreated, map[string]string{"username": request.Username, "role": "operator"})
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
	result, err := s.db.Exec("DELETE FROM accounts WHERE username = ? AND role = 'operator'", request.Username)
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
