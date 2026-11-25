package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newOperatorTestServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	db.SetMaxOpenConns(1)
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	secretsDB, err := sql.Open("sqlite", filepath.Join(dir, "vault-secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := secretsDB.Close(); err != nil {
			t.Errorf("close secrets database: %v", err)
		}
	})
	secretsDB.SetMaxOpenConns(1)
	if err := initializeSecretsDatabase(secretsDB); err != nil {
		t.Fatalf("initialize secrets database: %v", err)
	}
	if _, err := db.Exec("INSERT INTO accounts(username, password_hash, role) VALUES ('admin', 'hash', 'admin')"); err != nil {
		t.Fatal(err)
	}
	return &server{
		db:        db,
		secretsDB: secretsDB,
		adminName: "admin",
		loginDelay: func(context.Context) error {
			return nil
		},
		sessions: map[string]sessionInfo{
			"admin-session": {username: "admin", role: "admin", expiresAt: time.Now().Add(time.Hour)},
		},
	}
}

func operatorRequestWithSession(method, path, body, session string, https bool) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: "vault_session", Value: session})
	if https {
		request.TLS = &tls.ConnectionState{}
	}
	return request
}

func TestLegacySettingsRedirectsToSecurity(t *testing.T) {
	response := httptest.NewRecorder()
	redirectSecurityPage(response, httptest.NewRequest(http.MethodGet, "/settings.html", nil))
	if response.Code != http.StatusMovedPermanently {
		t.Fatalf("legacy settings status = %d, want %d", response.Code, http.StatusMovedPermanently)
	}
	if location := response.Header().Get("Location"); location != "/security.html" {
		t.Fatalf("legacy settings redirect location = %q, want /security.html", location)
	}
}

func TestOperatorManagementIsAdminOnlyAndRevokesDeletedSessions(t *testing.T) {
	s := newOperatorTestServer(t)

	created := httptest.NewRecorder()
	s.createOperator(created, operatorRequestWithSession(
		http.MethodPost,
		"/v1/operators",
		`{"username":"night-shift","password":"correct horse battery","password_confirmation":"correct horse battery"}`,
		"admin-session",
		true,
	))
	if created.Code != http.StatusCreated {
		t.Fatalf("create operator status = %d, body %s", created.Code, created.Body.String())
	}

	var role string
	if err := s.db.QueryRow("SELECT role FROM accounts WHERE username = ?", "night-shift").Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "operator" {
		t.Fatalf("new account role = %q, want operator", role)
	}
	s.mu.Lock()
	s.sessions["operator-session"] = sessionInfo{
		username:  "night-shift",
		role:      "operator",
		expiresAt: time.Now().Add(time.Hour),
	}
	s.mu.Unlock()

	operatorRequest := func(method, path string) *http.Request {
		return operatorRequestWithSession(method, path, "", "operator-session", true)
	}
	for _, test := range []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
	}{
		{"security settings API", s.getSettings},
		{"blocked login IP list API", s.listBlockedLoginIPs},
		{"unblock login IP API", s.unblockLoginIP},
		{"operator list API", s.listOperators},
		{"security page", s.serveSecurity},
		{"operators page", s.serveOperators},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			test.call(response, operatorRequest(http.MethodGet, "/"))
			if response.Code != http.StatusForbidden {
				t.Fatalf("operator access status = %d, body %s", response.Code, response.Body.String())
			}
		})
	}

	operatorPage := httptest.NewRecorder()
	s.serveSecrets(operatorPage, operatorRequest(http.MethodGet, "/secret.html"))
	if operatorPage.Code != http.StatusOK {
		t.Fatalf("operator secrets page status = %d", operatorPage.Code)
	}
	for _, path := range []string{"/security.html", "/operators.html"} {
		if strings.Contains(operatorPage.Body.String(), `href="`+path+`"`) {
			t.Fatalf("operator navigation includes the %s link", path)
		}
	}

	adminSecurity := httptest.NewRecorder()
	s.serveSecurity(adminSecurity, operatorRequestWithSession(http.MethodGet, "/security.html", "", "admin-session", true))
	if adminSecurity.Code != http.StatusOK ||
		!strings.Contains(adminSecurity.Body.String(), `id="enforceMTLS"`) ||
		!strings.Contains(adminSecurity.Body.String(), `id="autoBlockLoginBruteforceIP"`) {
		t.Fatalf("admin Security page status = %d, missing mTLS form", adminSecurity.Code)
	}
	if strings.Contains(adminSecurity.Body.String(), `id="operatorForm"`) {
		t.Fatal("Security page contains operator management")
	}

	adminOperators := httptest.NewRecorder()
	s.serveOperators(adminOperators, operatorRequestWithSession(http.MethodGet, "/operators.html", "", "admin-session", true))
	if adminOperators.Code != http.StatusOK ||
		!strings.Contains(adminOperators.Body.String(), `<dialog id="createOperatorDialog"`) ||
		!strings.Contains(adminOperators.Body.String(), `id="openCreateOperator"`) {
		t.Fatalf("admin Operators page status = %d, missing operator manager", adminOperators.Code)
	}

	adminList := httptest.NewRecorder()
	s.listOperators(adminList, operatorRequestWithSession(http.MethodGet, "/v1/operators", "", "admin-session", true))
	if adminList.Code != http.StatusOK || !strings.Contains(adminList.Body.String(), `"night-shift"`) {
		t.Fatalf("admin operator list status = %d, body %s", adminList.Code, adminList.Body.String())
	}

	adminDelete := httptest.NewRecorder()
	s.deleteOperator(adminDelete, operatorRequestWithSession(
		http.MethodDelete,
		"/v1/operators",
		`{"username":"night-shift"}`,
		"admin-session",
		true,
	))
	if adminDelete.Code != http.StatusOK {
		t.Fatalf("delete operator status = %d, body %s", adminDelete.Code, adminDelete.Body.String())
	}
	if s.authorizedToken("operator-session") {
		t.Fatal("deleted operator session remains authorized")
	}

	adminDeleteSelf := httptest.NewRecorder()
	s.deleteOperator(adminDeleteSelf, operatorRequestWithSession(
		http.MethodDelete,
		"/v1/operators",
		`{"username":"admin"}`,
		"admin-session",
		true,
	))
	if adminDeleteSelf.Code != http.StatusNotFound {
		t.Fatalf("delete admin status = %d, want %d", adminDeleteSelf.Code, http.StatusNotFound)
	}
}

func TestOperatorCreationRequiresHTTPSAndRejectsDuplicateNames(t *testing.T) {
	s := newOperatorTestServer(t)
	body := `{"username":"operator-one","password":"correct horse battery","password_confirmation":"correct horse battery"}`

	insecure := httptest.NewRecorder()
	s.createOperator(insecure, operatorRequestWithSession(http.MethodPost, "/v1/operators", body, "admin-session", false))
	if insecure.Code != http.StatusUpgradeRequired {
		t.Fatalf("HTTP create status = %d, want %d", insecure.Code, http.StatusUpgradeRequired)
	}

	for attempt := 0; attempt < 2; attempt++ {
		response := httptest.NewRecorder()
		s.createOperator(response, operatorRequestWithSession(http.MethodPost, "/v1/operators", body, "admin-session", true))
		want := http.StatusCreated
		if attempt == 1 {
			want = http.StatusConflict
		}
		if response.Code != want {
			t.Fatalf("create attempt %d status = %d, want %d, body %s", attempt+1, response.Code, want, response.Body.String())
		}
	}
}

func TestOperatorCreateRejectsPasswordMismatch(t *testing.T) {
	s := newOperatorTestServer(t)
	request := operatorRequestWithSession(
		http.MethodPost,
		"/v1/operators",
		`{"username":"operator-one","password":"correct horse battery","password_confirmation":"different password"}`,
		"admin-session",
		true,
	)
	response := httptest.NewRecorder()
	s.createOperator(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("password mismatch status = %d, want %d", response.Code, http.StatusBadRequest)
	}

	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "passwords do not match" {
		t.Fatalf("password mismatch error = %q", body["error"])
	}
}
