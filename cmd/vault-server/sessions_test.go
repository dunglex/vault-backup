package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestWebSessionSurvivesRestartAndLogoutRevokesIt(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close original database: %v", err)
		}
	})
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	password := "restart-session-password"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		"INSERT INTO accounts(username, password_hash, role) VALUES ('admin', ?, 'admin')",
		string(passwordHash),
	); err != nil {
		t.Fatal(err)
	}

	firstServer := &server{
		db:       db,
		sessions: make(map[string]sessionInfo),
		attempts: make(map[string][]time.Time),
		loginDelay: func(context.Context) error {
			return nil
		},
	}
	loginRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"username":"admin","password":"`+password+`"}`),
	)
	loginRequest.TLS = &tls.ConnectionState{}
	loginResponse := httptest.NewRecorder()
	firstServer.login(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, body %s", loginResponse.Code, loginResponse.Body.String())
	}
	cookies := loginResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "vault_session" {
		t.Fatalf("login cookies = %#v", cookies)
	}
	token := cookies[0].Value

	var storedHash string
	if err := db.QueryRow("SELECT token_hash FROM web_sessions WHERE username = 'admin'").Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != sessionTokenHash(token) || storedHash == token {
		t.Fatal("session token was not stored only as a hash")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	restartedDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	restartedDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := restartedDB.Close(); err != nil {
			t.Errorf("close restarted database: %v", err)
		}
	})
	if err := initializeDatabase(restartedDB); err != nil {
		t.Fatal(err)
	}
	restartedServer := &server{db: restartedDB, sessions: make(map[string]sessionInfo)}
	session, ok := restartedServer.sessionForToken(token)
	if !ok || session.username != "admin" || session.role != "admin" {
		t.Fatalf("session after restart = %#v, authenticated = %t", session, ok)
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	logoutRequest.AddCookie(cookies[0])
	logoutResponse := httptest.NewRecorder()
	restartedServer.logout(logoutResponse, logoutRequest)
	if logoutResponse.Code != http.StatusOK {
		t.Fatalf("logout status = %d, body %s", logoutResponse.Code, logoutResponse.Body.String())
	}
	if _, ok := restartedServer.sessionForToken(token); ok {
		t.Fatal("session remained valid after logout")
	}

	var remaining int
	if err := restartedDB.QueryRow("SELECT COUNT(*) FROM web_sessions WHERE token_hash = ?", storedHash).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("persistent session rows after logout = %d, want 0", remaining)
	}
}
