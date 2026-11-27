package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"vault-backup/internal/operator"
)

func TestEnableOperatorsExtensionInitializesEncryptedDatabase(t *testing.T) {
	dir := t.TempDir()
	operatorDBPath := filepath.Join(dir, "vault-operators.db")
	s := &server{
		dbPassword:     "test-database-password",
		operatorDBPath: operatorDBPath,
	}

	if err := s.enableOperatorsExtension(); err != nil {
		t.Fatalf("enable operators extension: %v", err)
	}
	t.Cleanup(func() {
		if s.operatorDB != nil {
			_ = s.operatorDB.Close()
		}
	})
	if s.operatorDB == nil || s.operatorHandler == nil {
		t.Fatal("operators extension was not initialized")
	}
	if _, err := os.Stat(operatorDBPath); err != nil {
		t.Fatalf("operator database not created: %v", err)
	}
	if _, err := os.Stat(operatorDBPath + ".key"); err != nil {
		t.Fatalf("operator key not created: %v", err)
	}
}

func TestResolveOperatorDatabasePath(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	config := serverConfig{
		DBPath:        filepath.Join(dir, "vault.db"),
		SecretsDBPath: filepath.Join(dir, "vault-secrets.db"),
		AuditDBPath:   filepath.Join(dir, "audit.db"),
	}
	path := defaultOperatorDatabasePath(config.DBPath)
	resolve := func() (string, bool, error) {
		t.Helper()
		return resolveOperatorDatabasePath(db, config)
	}
	if got, _, err := resolve(); err != nil || got != "" {
		t.Fatalf("fresh installation: path %q, error %v", got, err)
	}
	if _, err := db.Exec("INSERT INTO accounts(username, password_hash, role) VALUES ('admin', 'hash', 'admin')"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolve(); err == nil {
		t.Fatal("existing database without key was accepted")
	}
	if err := os.WriteFile(path+".key", []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, migrate, err := resolve(); err != nil || got != path || !migrate {
		t.Fatalf("legacy installation: path %q, migrate %t, error %v", got, migrate, err)
	}
	if _, err := db.Exec("INSERT INTO server_settings(key, value) VALUES (?, 'true')", operatorExtensionEnabledSetting); err != nil {
		t.Fatal(err)
	}
	if got, migrate, err := resolve(); err != nil || got != path || migrate {
		t.Fatalf("enabled installation: path %q, migrate %t, error %v", got, migrate, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolve(); err == nil {
		t.Fatal("enabled extension with missing database was accepted")
	}
	if _, err := db.Exec("UPDATE server_settings SET value = 'false' WHERE key = ?", operatorExtensionEnabledSetting); err != nil {
		t.Fatal(err)
	}
	if got, _, err := resolve(); err != nil || got != "" {
		t.Fatalf("disabled extension: path %q, error %v", got, err)
	}
}

func TestSetupPersistsOperatorsWithoutBackup(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	s := &server{
		db:             db,
		dbPassword:     "test-database-password",
		operatorDBPath: filepath.Join(dir, "app-operators.db"),
		setupKey:       "setup-key",
		setupKeyPath:   filepath.Join(dir, "setup-key"),
		setupDeadline:  time.Now().Add(time.Hour),
	}
	defer func() {
		if s.operatorDB != nil {
			_ = s.operatorDB.Close()
		}
	}()
	response := httptest.NewRecorder()
	s.setup(response, httptest.NewRequest(http.MethodPost, "/v1/setup", strings.NewReader(
		`{"setup_key":"setup-key","username":"admin","password":"correct-horse-battery","password_confirmation":"correct-horse-battery","enable_operators":true}`,
	)))
	if response.Code != http.StatusCreated {
		t.Fatalf("setup status = %d, body = %s", response.Code, response.Body.String())
	}
	var value string
	if err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", operatorExtensionEnabledSetting).Scan(&value); err != nil || value != "true" {
		t.Fatalf("operator extension setting = %q, error %v", value, err)
	}
}

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
	operatorDB, err := sql.Open("sqlite", filepath.Join(dir, "operator.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := operatorDB.Close(); err != nil {
			t.Errorf("close operator database: %v", err)
		}
	})
	operatorDB.SetMaxOpenConns(1)
	if err := operator.Initialize(operatorDB); err != nil {
		t.Fatalf("initialize operator database: %v", err)
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
	s := &server{
		db:            db,
		secretsDB:     secretsDB,
		operatorDB:    operatorDB,
		adminName:     "admin",
		backupEnabled: true,
		loginDelay: func(context.Context) error {
			return nil
		},
		sessions: map[string]sessionInfo{
			"admin-session": {username: "admin", role: "admin", expiresAt: time.Now().Add(time.Hour), ttl: time.Hour},
		},
		attempts: make(map[string][]time.Time),
	}
	s.operatorHandler = s.newOperatorHandler()
	if err := s.storeSession("admin-session", s.sessions["admin-session"]); err != nil {
		t.Fatalf("store admin test session: %v", err)
	}
	return s
}

func operatorRequestWithSession(method, path, body, session string, https bool) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: "vault_session", Value: session})
	if https {
		request.TLS = &tls.ConnectionState{}
	}
	return request
}

func TestOperatorCreationGeneratesOneTimeTemporaryPassword(t *testing.T) {
	s := newOperatorTestServer(t)
	response := httptest.NewRecorder()
	s.createOperator(response, operatorRequestWithSession(
		http.MethodPost,
		"/v1/operators",
		`{"username":"generated-operator","prefixes":["team-a"]}`,
		"admin-session",
		true,
	))
	if response.Code != http.StatusCreated {
		t.Fatalf("create operator status = %d, body %s", response.Code, response.Body.String())
	}
	var body struct {
		InitialPassword    string `json:"initial_password"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if len(body.InitialPassword) < 12 || len(body.InitialPassword) > 20 || !body.MustChangePassword {
		t.Fatalf("generated password response has invalid state: length=%d must_change=%v", len(body.InitialPassword), body.MustChangePassword)
	}
	var passwordHash string
	var mustChangePassword int
	if err := s.operatorDB.QueryRow(
		"SELECT password_hash, must_change_password FROM accounts WHERE username = ?",
		"generated-operator",
	).Scan(&passwordHash, &mustChangePassword); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(body.InitialPassword)); err != nil {
		t.Fatal("generated password does not match stored password hash")
	}
	if mustChangePassword != 1 {
		t.Fatalf("new operator must_change_password = %d, want 1", mustChangePassword)
	}
}

func TestAdminResetsOperatorPasswordAndRevokesSessions(t *testing.T) {
	s := newOperatorTestServer(t)
	oldPassword := "old-operator-password"
	oldHash, err := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.operatorDB.Exec(
		"INSERT INTO accounts(username, password_hash, role) VALUES ('reset-target', ?, 'operator')",
		string(oldHash),
	); err != nil {
		t.Fatal(err)
	}
	if err := s.storeSession("reset-target-session", sessionInfo{
		username:  "reset-target",
		role:      "operator",
		expiresAt: time.Now().Add(time.Hour),
		ttl:       time.Hour,
	}); err != nil {
		t.Fatalf("store operator test session: %v", err)
	}

	response := httptest.NewRecorder()
	s.resetOperatorPassword(response, operatorRequestWithSession(
		http.MethodPost,
		"/v1/operators/password",
		`{"username":"reset-target"}`,
		"admin-session",
		true,
	))
	if response.Code != http.StatusOK {
		t.Fatalf("reset operator password status = %d, body %s", response.Code, response.Body.String())
	}
	var body struct {
		TemporaryPassword  string `json:"temporary_password"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode reset response: %v", err)
	}
	if len(body.TemporaryPassword) < 12 || len(body.TemporaryPassword) > 20 || !body.MustChangePassword {
		t.Fatalf("reset response has invalid state: length=%d must_change=%v", len(body.TemporaryPassword), body.MustChangePassword)
	}
	if _, ok := s.sessionForToken("reset-target-session"); ok {
		t.Fatal("operator session remains authorized after password reset")
	}

	var passwordHash string
	var mustChangePassword int
	if err := s.operatorDB.QueryRow(
		"SELECT password_hash, must_change_password FROM accounts WHERE username = 'reset-target'",
	).Scan(&passwordHash, &mustChangePassword); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(body.TemporaryPassword)); err != nil {
		t.Fatal("temporary password does not match stored password hash")
	}
	if mustChangePassword != 1 {
		t.Fatalf("must_change_password = %d, want 1", mustChangePassword)
	}

	login := httptest.NewRecorder()
	s.login(login, httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"username":"reset-target","password":"`+body.TemporaryPassword+`"}`),
	))
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), `"must_change_password":true`) {
		t.Fatalf("login with temporary password = %d, body %s", login.Code, login.Body.String())
	}
}

func TestTemporaryPasswordSessionRestrictsAccess(t *testing.T) {
	s := newOperatorTestServer(t)
	if _, err := s.db.Exec("UPDATE accounts SET must_change_password = 1 WHERE username = 'admin'"); err != nil {
		t.Fatal(err)
	}
	guard := s.mustChangePasswordGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := func(method, path string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		guard.ServeHTTP(response, operatorRequestWithSession(method, path, "", "admin-session", true))
		return response
	}
	if response := request(http.MethodGet, "/account.html"); response.Code != http.StatusNoContent {
		t.Fatalf("account page status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if response := request(http.MethodPost, "/v1/account/password"); response.Code != http.StatusNoContent {
		t.Fatalf("password change status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if response := request(http.MethodGet, "/secrets.html"); response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/account.html?password=required" {
		t.Fatalf("secrets redirect = %d to %q", response.Code, response.Header().Get("Location"))
	}
	if response := request(http.MethodGet, "/v1/tokens"); response.Code != http.StatusForbidden {
		t.Fatalf("tokens API status = %d, want %d", response.Code, http.StatusForbidden)
	}
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
		`{"username":"night-shift","password":"correct horse battery","password_confirmation":"correct horse battery","prefixes":["team-a"]}`,
		"admin-session",
		true,
	))
	if created.Code != http.StatusCreated {
		t.Fatalf("create operator status = %d, body %s", created.Code, created.Body.String())
	}

	var role string
	if err := s.operatorDB.QueryRow("SELECT role FROM accounts WHERE username = ?", "night-shift").Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "operator" {
		t.Fatalf("new account role = %q, want operator", role)
	}
	var mustChangePassword int
	if err := s.operatorDB.QueryRow("SELECT must_change_password FROM accounts WHERE username = ?", "night-shift").Scan(&mustChangePassword); err != nil {
		t.Fatal(err)
	}
	if mustChangePassword != 1 {
		t.Fatalf("new operator must_change_password = %d, want 1", mustChangePassword)
	}
	if err := s.storeSession("operator-session", sessionInfo{
		username:  "night-shift",
		role:      "operator",
		expiresAt: time.Now().Add(time.Hour),
		ttl:       time.Hour,
	}); err != nil {
		t.Fatalf("store operator test session: %v", err)
	}

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
		{"operator details API", s.listOperatorDetails},
		{"operator lock API", s.setOperatorLock},
		{"operator TOTP reset API", s.removeOperatorTOTP},
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
	if !strings.Contains(adminSecurity.Body.String(), `id="fileLogging"`) {
		t.Fatal("admin Security page is missing file logging setting")
	}
	if strings.Contains(adminSecurity.Body.String(), `id="operatorForm"`) {
		t.Fatal("Security page contains operator management")
	}

	adminOperators := httptest.NewRecorder()
	s.serveOperators(adminOperators, operatorRequestWithSession(http.MethodGet, "/operators.html", "", "admin-session", true))
	if adminOperators.Code != http.StatusOK ||
		!strings.Contains(adminOperators.Body.String(), `<dialog id="createOperatorDialog"`) ||
		!strings.Contains(adminOperators.Body.String(), `id="openCreateOperator"`) ||
		!strings.Contains(adminOperators.Body.String(), "/v1/operators/lock") ||
		!strings.Contains(adminOperators.Body.String(), "/v1/operators/totp") ||
		!strings.Contains(adminOperators.Body.String(), "Reset password") ||
		!strings.Contains(adminOperators.Body.String(), "/v1/operators/password") ||
		strings.Contains(adminOperators.Body.String(), "Remove operator") {
		t.Fatalf("admin Operators page status = %d, missing expected controls or includes operator removal", adminOperators.Code)
	}

	adminList := httptest.NewRecorder()
	s.listOperators(adminList, operatorRequestWithSession(http.MethodGet, "/v1/operators", "", "admin-session", true))
	if adminList.Code != http.StatusOK || !strings.Contains(adminList.Body.String(), `"night-shift"`) {
		t.Fatalf("admin operator list status = %d, body %s", adminList.Code, adminList.Body.String())
	}
	adminDetails := httptest.NewRecorder()
	s.listOperatorDetails(adminDetails, operatorRequestWithSession(http.MethodGet, "/v1/operators/details", "", "admin-session", true))
	if adminDetails.Code != http.StatusOK ||
		!strings.Contains(adminDetails.Body.String(), `"locked":false`) ||
		!strings.Contains(adminDetails.Body.String(), `"mfa_enabled":false`) {
		t.Fatalf("admin operator details status = %d, body %s", adminDetails.Code, adminDetails.Body.String())
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

func TestAdminCanLockUnlockOperatorAndLockedLoginIsRejected(t *testing.T) {
	s := newOperatorTestServer(t)
	created := httptest.NewRecorder()
	s.createOperator(created, operatorRequestWithSession(
		http.MethodPost,
		"/v1/operators",
		`{"username":"night-shift","password":"operator-test-password","password_confirmation":"operator-test-password","prefixes":["team-a"]}`,
		"admin-session",
		true,
	))
	if created.Code != http.StatusCreated {
		t.Fatalf("create operator status = %d, body %s", created.Code, created.Body.String())
	}
	if err := s.storeSession("operator-session", sessionInfo{
		username:  "night-shift",
		role:      "operator",
		expiresAt: time.Now().Add(time.Hour),
		ttl:       time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	lock := httptest.NewRecorder()
	s.setOperatorLock(lock, operatorRequestWithSession(
		http.MethodPatch,
		"/v1/operators/lock",
		`{"username":"night-shift","locked":true}`,
		"admin-session",
		true,
	))
	if lock.Code != http.StatusOK || !strings.Contains(lock.Body.String(), `"locked":true`) {
		t.Fatalf("lock operator = %d, body %s", lock.Code, lock.Body.String())
	}
	if _, ok := s.sessionForToken("operator-session"); ok {
		t.Fatal("locked operator session remained valid")
	}
	var locked int
	if err := s.operatorDB.QueryRow("SELECT locked FROM accounts WHERE username = 'night-shift'").Scan(&locked); err != nil {
		t.Fatal(err)
	}
	if locked != 1 {
		t.Fatalf("stored locked state = %d, want 1", locked)
	}

	login := httptest.NewRecorder()
	s.login(login, httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"username":"night-shift","password":"operator-test-password"}`),
	))
	if login.Code != http.StatusForbidden || !strings.Contains(login.Body.String(), "account is locked") {
		t.Fatalf("locked operator login = %d, body %s", login.Code, login.Body.String())
	}

	unlock := httptest.NewRecorder()
	s.setOperatorLock(unlock, operatorRequestWithSession(
		http.MethodPatch,
		"/v1/operators/lock",
		`{"username":"night-shift","locked":false}`,
		"admin-session",
		true,
	))
	if unlock.Code != http.StatusOK || !strings.Contains(unlock.Body.String(), `"locked":false`) {
		t.Fatalf("unlock operator = %d, body %s", unlock.Code, unlock.Body.String())
	}
	login = httptest.NewRecorder()
	s.login(login, httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"username":"night-shift","password":"operator-test-password"}`),
	))
	if login.Code != http.StatusOK {
		t.Fatalf("unlocked operator login = %d, body %s", login.Code, login.Body.String())
	}
}

func TestAdminCanRemoveOperatorTOTPAndRevokeSessions(t *testing.T) {
	s := newOperatorTestServer(t)
	created := httptest.NewRecorder()
	s.createOperator(created, operatorRequestWithSession(
		http.MethodPost,
		"/v1/operators",
		`{"username":"night-shift","password":"operator-test-password","password_confirmation":"operator-test-password","prefixes":["team-a"]}`,
		"admin-session",
		true,
	))
	if created.Code != http.StatusCreated {
		t.Fatalf("create operator status = %d, body %s", created.Code, created.Body.String())
	}
	if _, err := s.operatorDB.Exec(
		"UPDATE accounts SET totp_secret = 'test-secret', totp_enabled = 1, totp_recovery_codes = '[\"test-hash\"]' WHERE username = 'night-shift'",
	); err != nil {
		t.Fatal(err)
	}
	if err := s.storeSession("operator-session", sessionInfo{
		username:  "night-shift",
		role:      "operator",
		expiresAt: time.Now().Add(time.Hour),
		ttl:       time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	s.removeOperatorTOTP(response, operatorRequestWithSession(
		http.MethodDelete,
		"/v1/operators/totp",
		`{"username":"night-shift"}`,
		"admin-session",
		true,
	))
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"mfa_configured":false`) {
		t.Fatalf("remove operator TOTP = %d, body %s", response.Code, response.Body.String())
	}
	var secret sql.NullString
	var enabled int
	var recoveryCodes string
	if err := s.operatorDB.QueryRow(
		"SELECT totp_secret, totp_enabled, totp_recovery_codes FROM accounts WHERE username = 'night-shift'",
	).Scan(&secret, &enabled, &recoveryCodes); err != nil {
		t.Fatal(err)
	}
	if secret.Valid || enabled != 0 || recoveryCodes != "[]" {
		t.Fatalf("operator TOTP state = secret:%v enabled:%d recovery:%q", secret, enabled, recoveryCodes)
	}
	if _, ok := s.sessionForToken("operator-session"); ok {
		t.Fatal("operator session remained valid after TOTP removal")
	}
}

func TestOperatorCreationRequiresHTTPSAndRejectsDuplicateNames(t *testing.T) {
	s := newOperatorTestServer(t)
	body := `{"username":"operator-one","password":"correct horse battery","password_confirmation":"correct horse battery","prefixes":["team-a"]}`

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
		`{"username":"operator-one","password":"correct horse battery","password_confirmation":"different password","prefixes":["team-a"]}`,
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
