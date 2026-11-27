package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func newLoginBlockTestServer(t *testing.T, enabled bool) *server {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	value := "false"
	if enabled {
		value = "true"
	}
	if _, err := db.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, ?)",
		autoBlockLoginIPSetting,
		value,
	); err != nil {
		t.Fatal(err)
	}
	return &server{
		db:         db,
		loginDelay: func(context.Context) error { return nil },
	}
}

func TestAutoBlockLoginIPDisabledExplicitly(t *testing.T) {
	s := newLoginBlockTestServer(t, false)
	enabled, err := s.autoBlockLoginIPEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("automatic login IP blocking should be disabled by default")
	}
	for i := 0; i < loginAttemptLimit+1; i++ {
		blocked, err := s.recordFailedLoginIP("192.0.2.10", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			t.Fatal("disabled feature blocked an IP")
		}
	}
	var failures, blockedIPs int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM login_ip_failures").Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM blocked_login_ips").Scan(&blockedIPs); err != nil {
		t.Fatal(err)
	}
	if failures != 0 || blockedIPs != 0 {
		t.Fatalf("disabled feature stored %d failures and %d blocks", failures, blockedIPs)
	}
}

func TestAutoBlockLoginIPAfterFiveFailuresWithinTenMinutes(t *testing.T) {
	s := newLoginBlockTestServer(t, true)
	now := time.Now().UTC()
	for i := 0; i < loginAttemptLimit; i++ {
		blocked, err := s.recordFailedLoginIP("192.0.2.10", now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if blocked != (i == loginAttemptLimit-1) {
			t.Fatalf("failure %d newly blocked = %t", i+1, blocked)
		}
	}
	blocked, err := s.loginIPBlocked("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Fatal("IP was not permanently blocked")
	}
	list, err := s.blockedLoginIPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].IP != "192.0.2.10" || list[0].FailureCount != loginAttemptLimit {
		t.Fatalf("blocked IP listing = %+v", list)
	}
}

func TestAutoBlockLoginIPFailureWindowAndSuccessfulReset(t *testing.T) {
	s := newLoginBlockTestServer(t, true)
	now := time.Now().UTC()
	for i := 0; i < loginAttemptLimit-1; i++ {
		if _, err := s.recordFailedLoginIP("198.51.100.20", now.Add(-loginIPFailureWindow-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.recordFailedLoginIP("198.51.100.20", now); err != nil {
		t.Fatal(err)
	}
	if err := s.clearLoginIPFailures("198.51.100.20"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < loginAttemptLimit-1; i++ {
		blocked, err := s.recordFailedLoginIP("198.51.100.20", now.Add(time.Duration(i+1)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			t.Fatal("IP was blocked before five consecutive failures")
		}
	}
	blocked, err := s.recordFailedLoginIP("198.51.100.20", now.Add(loginAttemptLimit*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Fatal("IP was not blocked after five failures following success reset")
	}
}

func TestBlockedLoginIPEnforcementFollowsSetting(t *testing.T) {
	s := newLoginBlockTestServer(t, true)
	if _, err := s.db.Exec(
		"INSERT INTO blocked_login_ips(client_ip, blocked_at, failure_count) VALUES (?, ?, ?)",
		"203.0.113.12", time.Now().Unix(), loginAttemptLimit,
	); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	request.RemoteAddr = "203.0.113.12:54321"
	response := httptest.NewRecorder()
	if !s.rejectBlockedLoginIP(response, request, "web") || response.Code != http.StatusForbidden {
		t.Fatalf("enabled blocked IP response = %d, body %s", response.Code, response.Body.String())
	}

	if _, err := s.db.Exec(
		"UPDATE server_settings SET value = 'false' WHERE key = ?",
		autoBlockLoginIPSetting,
	); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	if s.rejectBlockedLoginIP(response, request, "web") {
		t.Fatalf("disabled feature rejected blocked IP: %d %s", response.Code, response.Body.String())
	}
}

func TestLoginHandlerPermanentlyBlocksIPAfterFiveFailures(t *testing.T) {
	s := newLoginBlockTestServer(t, true)
	s.attempts = make(map[string][]time.Time)
	auditStore, err := openAnnualAuditStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	s.auditStore = auditStore
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		"INSERT INTO accounts(username, password_hash, role) VALUES ('admin', ?, 'admin')",
		string(passwordHash),
	); err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt <= loginAttemptLimit; attempt++ {
		request := httptest.NewRequest(
			http.MethodPost,
			"/v1/auth/login",
			strings.NewReader(`{"username":"admin","password":"wrong-password"}`),
		)
		request.RemoteAddr = "192.0.2.55:40000"
		response := httptest.NewRecorder()
		s.login(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("failed login %d status = %d, body %s", attempt, response.Code, response.Body.String())
		}
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"username":"admin","password":"correct-password"}`),
	)
	request.RemoteAddr = "192.0.2.55:40000"
	response := httptest.NewRecorder()
	s.login(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("login after permanent IP block status = %d, body %s", response.Code, response.Body.String())
	}
	var blockEvents, rejectedEvents int
	if err := auditStore.withYear(time.Now().UTC().Year(), func(db *sql.DB) error {
		if err := db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action = 'block_login_ip' AND resource = '192.0.2.55'").Scan(&blockEvents); err != nil {
			return err
		}
		return db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action = 'login_blocked' AND resource = '192.0.2.55'").Scan(&rejectedEvents)
	}); err != nil {
		t.Fatal(err)
	}
	if blockEvents != 1 || rejectedEvents != 1 {
		t.Fatalf("automatic block audit events: block=%d rejected=%d", blockEvents, rejectedEvents)
	}
}

func TestAdminUnblockWritesAuditEvent(t *testing.T) {
	s := newLoginBlockTestServer(t, false)
	if _, err := s.db.Exec("INSERT INTO accounts(username, password_hash, role) VALUES ('admin', 'hash', 'admin')"); err != nil {
		t.Fatal(err)
	}
	if err := s.storeSession("admin-session", sessionInfo{
		username:  "admin",
		role:      "admin",
		expiresAt: time.Now().Add(time.Hour),
		ttl:       time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		"INSERT INTO blocked_login_ips(client_ip, blocked_at, failure_count) VALUES (?, ?, ?)",
		"203.0.113.12", time.Now().Unix(), loginAttemptLimit,
	); err != nil {
		t.Fatal(err)
	}
	auditStore, err := openAnnualAuditStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	s.auditStore = auditStore

	request := operatorRequestWithSession(
		http.MethodDelete,
		"/v1/settings/blocked-login-ips/203.0.113.12",
		"",
		"admin-session",
		true,
	)
	request.SetPathValue("ip", "203.0.113.12")
	response := httptest.NewRecorder()
	s.unblockLoginIP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unblock response = %d, body %s", response.Code, response.Body.String())
	}
	var remaining int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM blocked_login_ips WHERE client_ip = '203.0.113.12'").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("unblocked IP remains in the block list")
	}
	var auditCount int
	if err := auditStore.withYear(time.Now().UTC().Year(), func(db *sql.DB) error {
		return db.QueryRow(`
			SELECT COUNT(*) FROM audit_events
			WHERE action = 'unblock_login_ip'
			  AND outcome = 'success'
			  AND actor = 'admin'
			  AND resource = '203.0.113.12'`).Scan(&auditCount)
	}); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("successful unblock audit event count = %d, want 1", auditCount)
	}
}
