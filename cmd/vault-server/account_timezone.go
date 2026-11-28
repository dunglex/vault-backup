package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type accountTimezoneRequest struct {
	Timezone string `json:"timezone"`
}

func (s *server) getAccountTimezone(w http.ResponseWriter, r *http.Request) {
	session, ok := s.accountTimezoneRequest(w, r)
	if !ok {
		return
	}
	account, _, err := s.loadAccountForRequest(r, session.username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read account timezone"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"timezone": sessionTimezone(sessionInfo{timezone: account.timezone})})
}

func (s *server) updateAccountTimezone(w http.ResponseWriter, r *http.Request) {
	session, ok := s.accountTimezoneRequest(w, r)
	if !ok {
		return
	}
	var request accountTimezoneRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	timezone := strings.TrimSpace(request.Timezone)
	if timezone == "" || len(timezone) > 64 || timezone != request.Timezone {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid timezone"})
		return
	}
	if timezone == "Local" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid timezone"})
		return
	}
	timezone = canonicalTimezone(timezone)
	if _, err := time.LoadLocation(timezone); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid timezone"})
		return
	}
	db := s.accountDatabase(session.role)
	if db == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "account database is unavailable"})
		return
	}
	result, err := db.Exec("UPDATE accounts SET timezone = ? WHERE username = ?", timezone, session.username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update account timezone"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account settings changed; reload and try again"})
		return
	}
	s.mu.Lock()
	for token, cached := range s.sessions {
		if cached.username == session.username && cached.role == session.role {
			cached.timezone = timezone
			s.sessions[token] = cached
		}
	}
	s.mu.Unlock()
	s.recordAuditEvent(r, "update_account_timezone", "success", session.username, "web", "account:"+session.username, "")
	writeJSON(w, http.StatusOK, map[string]string{"timezone": timezone})
}

func canonicalTimezone(timezone string) string {
	aliases := map[string]string{
		"Asia/Saigon": "Asia/Ho_Chi_Minh",
	}
	if canonical, ok := aliases[timezone]; ok {
		return canonical
	}
	return timezone
}

func (s *server) accountTimezoneRequest(w http.ResponseWriter, r *http.Request) (sessionInfo, bool) {
	session, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return sessionInfo{}, false
	}
	if !s.requestIsHTTPS(r) {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required for account settings"})
		return sessionInfo{}, false
	}
	return session, true
}
