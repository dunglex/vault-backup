package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	autoBlockLoginIPSetting = "auto_block_login_bruteforce_ip"
	loginIPFailureWindow    = 10 * time.Minute
)

type blockedLoginIP struct {
	IP           string `json:"ip"`
	BlockedAt    string `json:"blocked_at"`
	FailureCount int    `json:"failure_count"`
}

func (s *server) autoBlockLoginIPEnabled() (bool, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM server_settings WHERE key = ?", autoBlockLoginIPSetting).Scan(&value)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid %s setting: %w", autoBlockLoginIPSetting, err)
	}
	return enabled, nil
}

func (s *server) loginIPBlocked(clientIP string) (bool, error) {
	enabled, err := s.autoBlockLoginIPEnabled()
	if err != nil || !enabled {
		return false, err
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, fmt.Errorf("invalid client IP address %q", clientIP)
	}
	var exists int
	err = s.db.QueryRow("SELECT 1 FROM blocked_login_ips WHERE client_ip = ?", ip.String()).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *server) recordFailedLoginIP(clientIP string, now time.Time) (bool, error) {
	enabled, err := s.autoBlockLoginIPEnabled()
	if err != nil || !enabled {
		return false, err
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, fmt.Errorf("invalid client IP address %q", clientIP)
	}
	clientIP = ip.String()

	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin failed-login transaction: %w", err)
	}
	defer tx.Rollback()

	cutoff := now.UTC().Add(-loginIPFailureWindow).Unix()
	if _, err := tx.Exec("DELETE FROM login_ip_failures WHERE failed_at <= ?", cutoff); err != nil {
		return false, fmt.Errorf("expire old failed-login records: %w", err)
	}
	if _, err := tx.Exec("INSERT INTO login_ip_failures(client_ip, failed_at) VALUES (?, ?)", clientIP, now.UTC().Unix()); err != nil {
		return false, fmt.Errorf("record failed login: %w", err)
	}
	var failures int
	if err := tx.QueryRow(
		"SELECT COUNT(*) FROM login_ip_failures WHERE client_ip = ? AND failed_at > ?",
		clientIP, cutoff,
	).Scan(&failures); err != nil {
		return false, fmt.Errorf("count failed logins: %w", err)
	}
	if failures < loginAttemptLimit {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit failed-login record: %w", err)
		}
		return false, nil
	}
	result, err := tx.Exec(
		"INSERT OR IGNORE INTO blocked_login_ips(client_ip, blocked_at, failure_count) VALUES (?, ?, ?)",
		clientIP, now.UTC().Unix(), failures,
	)
	if err != nil {
		return false, fmt.Errorf("block login IP: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM login_ip_failures WHERE client_ip = ?", clientIP); err != nil {
		return false, fmt.Errorf("clear blocked IP failure records: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check blocked IP result: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit blocked IP: %w", err)
	}
	return inserted != 0, nil
}

func (s *server) clearLoginIPFailures(clientIP string) error {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return fmt.Errorf("invalid client IP address %q", clientIP)
	}
	if _, err := s.db.Exec("DELETE FROM login_ip_failures WHERE client_ip = ?", ip.String()); err != nil {
		return fmt.Errorf("clear failed-login records: %w", err)
	}
	return nil
}

func (s *server) blockedLoginIPs() ([]blockedLoginIP, error) {
	rows, err := s.db.Query(`
		SELECT client_ip, blocked_at, failure_count
		FROM blocked_login_ips
		ORDER BY blocked_at DESC, client_ip`)
	if err != nil {
		return nil, fmt.Errorf("list blocked login IPs: %w", err)
	}
	defer rows.Close()

	blocked := make([]blockedLoginIP, 0)
	for rows.Next() {
		var ip string
		var blockedAt int64
		var failureCount int
		if err := rows.Scan(&ip, &blockedAt, &failureCount); err != nil {
			return nil, fmt.Errorf("read blocked login IP: %w", err)
		}
		blocked = append(blocked, blockedLoginIP{
			IP:           ip,
			BlockedAt:    time.Unix(blockedAt, 0).UTC().Format(time.RFC3339),
			FailureCount: failureCount,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate blocked login IPs: %w", err)
	}
	return blocked, nil
}

func (s *server) rejectBlockedLoginIP(w http.ResponseWriter, r *http.Request, source string) bool {
	clientIP := s.clientIP(r)
	blocked, err := s.loginIPBlocked(clientIP)
	if err != nil {
		logLoginBlockError("check blocked login IP", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not check login IP block"})
		return true
	}
	if !blocked {
		return false
	}
	s.recordAuditEvent(r, "login_blocked", "failure", "system", source, clientIP, "permanent_ip_block")
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "login is blocked for this IP address"})
	return true
}

func (s *server) recordLoginFailure(r *http.Request, source string) {
	clientIP := s.clientIP(r)
	blocked, err := s.recordFailedLoginIP(clientIP, time.Now().UTC())
	if err != nil {
		logLoginBlockError("record failed login", err)
		return
	}
	if blocked {
		s.recordAuditEvent(r, "block_login_ip", "success", "system", source, clientIP, "five failed logins within ten minutes")
	}
}

func (s *server) resetLoginFailuresAfterSuccess(r *http.Request) {
	if err := s.clearLoginIPFailures(s.clientIP(r)); err != nil {
		logLoginBlockError("reset failed logins after successful login", err)
	}
}

func logLoginBlockError(action string, err error) {
	log.Printf("WARNING: could not %s: %v", action, err)
}

func (s *server) listBlockedLoginIPs(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	blocked, err := s.blockedLoginIPs()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list blocked IPs"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"blocked_ips": blocked})
}

func (s *server) unblockLoginIP(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to unblock login IPs"})
		return
	}
	rawIP := strings.TrimSpace(r.PathValue("ip"))
	ip := net.ParseIP(rawIP)
	if ip == nil {
		s.recordAuditEvent(r, "unblock_login_ip", "failure", s.auditRequestActor(r, "web"), "web", rawIP, "invalid_ip")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IP address"})
		return
	}
	clientIP := ip.String()

	tx, err := s.db.Begin()
	if err != nil {
		s.recordAuditEvent(r, "unblock_login_ip", "failure", s.auditRequestActor(r, "web"), "web", clientIP, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not unblock login IP"})
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec("DELETE FROM blocked_login_ips WHERE client_ip = ?", clientIP)
	if err != nil {
		s.recordAuditEvent(r, "unblock_login_ip", "failure", s.auditRequestActor(r, "web"), "web", clientIP, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not unblock login IP"})
		return
	}
	removed, err := result.RowsAffected()
	if err != nil {
		s.recordAuditEvent(r, "unblock_login_ip", "failure", s.auditRequestActor(r, "web"), "web", clientIP, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not unblock login IP"})
		return
	}
	if removed == 0 {
		s.recordAuditEvent(r, "unblock_login_ip", "failure", s.auditRequestActor(r, "web"), "web", clientIP, "not_blocked")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "IP address is not blocked"})
		return
	}
	if _, err := tx.Exec("DELETE FROM login_ip_failures WHERE client_ip = ?", clientIP); err != nil {
		s.recordAuditEvent(r, "unblock_login_ip", "failure", s.auditRequestActor(r, "web"), "web", clientIP, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not unblock login IP"})
		return
	}
	if err := tx.Commit(); err != nil {
		s.recordAuditEvent(r, "unblock_login_ip", "failure", s.auditRequestActor(r, "web"), "web", clientIP, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not unblock login IP"})
		return
	}

	s.recordAuditEvent(r, "unblock_login_ip", "success", s.auditRequestActor(r, "web"), "web", clientIP, "admin_unblock")
	writeJSON(w, http.StatusOK, map[string]string{"ip": clientIP})
}
