package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWithRequestTimeout(t *testing.T) {
	handler := withRequestTimeout(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}), 10*time.Millisecond)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("timeout status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if response.Body.String() != `{"error":"request timed out"}` {
		t.Fatalf("timeout response = %q", response.Body.String())
	}
}

func TestHTTPErrorLogWriterFiltersUnknownCertificateHandshakeErrors(t *testing.T) {
	var output bytes.Buffer
	writer := httpErrorLogWriter{output: &output}

	ignored := []byte("http: TLS handshake error from 127.0.0.1:1234: remote error: tls: unknown certificate\n")
	if n, err := writer.Write(ignored); err != nil || n != len(ignored) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(ignored))
	}
	if output.Len() != 0 {
		t.Fatalf("unknown certificate handshake log was not filtered: %q", output.String())
	}

	retained := []byte("http: TLS handshake error from 127.0.0.1:1234: tls: bad certificate\n")
	if n, err := writer.Write(retained); err != nil || n != len(retained) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(retained))
	}
	if output.String() != string(retained) {
		t.Fatalf("other HTTP server errors should be retained: got %q", output.String())
	}
}

func TestInitializeDatabaseRemovesLegacyUniqueTokenNameConstraint(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`
		CREATE TABLE api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			revoked_at INTEGER,
			secret_prefixes TEXT NOT NULL DEFAULT '[]'
		);
		CREATE TABLE server_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO server_settings(key, value) VALUES ('auto_rotate_certificates', 'true');
		INSERT INTO api_tokens(name, token_hash, created_at, expires_at)
			VALUES ('backup-agent', 'first-hash', 1, 2);
	`); err != nil {
		t.Fatal(err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO api_tokens(name, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
		"backup-agent", "second-hash", 1, 2,
	); err != nil {
		t.Fatalf("insert API token with duplicate name: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM api_tokens WHERE name = ?", "backup-agent").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("API tokens with duplicate name = %d, want 2", count)
	}
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM server_settings WHERE key = 'auto_rotate_certificates'",
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("legacy automatic certificate rotation setting was not removed")
	}
	var mounts string
	if err := db.QueryRow("SELECT secret_mounts FROM api_tokens WHERE token_hash = 'first-hash'").Scan(&mounts); err != nil {
		t.Fatal(err)
	}
	if mounts != "[]" {
		t.Fatalf("migrated token mounts = %q, want empty scope", mounts)
	}
}

func TestInitializeDatabaseMigratesExistingAccountsToAdmin(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`
		CREATE TABLE accounts (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			secret_prefixes TEXT NOT NULL DEFAULT '[]',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO accounts(username, password_hash) VALUES ('existing-admin', 'hash');
	`); err != nil {
		t.Fatal(err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	var role string
	if err := db.QueryRow("SELECT role FROM accounts WHERE username = 'existing-admin'").Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "admin" {
		t.Fatalf("migrated account role = %q, want admin", role)
	}
	var mounts string
	if err := db.QueryRow("SELECT secret_mounts FROM accounts WHERE username = 'existing-admin'").Scan(&mounts); err != nil {
		t.Fatal(err)
	}
	if mounts != "[]" {
		t.Fatalf("migrated account mounts = %q, want empty scope", mounts)
	}
	var locked int
	if err := db.QueryRow("SELECT locked FROM accounts WHERE username = 'existing-admin'").Scan(&locked); err != nil {
		t.Fatal(err)
	}
	if locked != 0 {
		t.Fatalf("migrated account locked state = %d, want unlocked", locked)
	}
	var totpEnabled int
	var totpSecret sql.NullString
	var recoveryCodes string
	if err := db.QueryRow(
		"SELECT totp_enabled, totp_secret, totp_recovery_codes FROM accounts WHERE username = 'existing-admin'",
	).Scan(&totpEnabled, &totpSecret, &recoveryCodes); err != nil {
		t.Fatal(err)
	}
	if totpEnabled != 0 || totpSecret.Valid || recoveryCodes != "[]" {
		t.Fatalf("migrated account TOTP state = enabled:%d secret:%v codes:%q, want disabled and empty", totpEnabled, totpSecret, recoveryCodes)
	}
}

func TestInitializeDatabaseRejectsLegacySecretsTable(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE secrets (path TEXT PRIMARY KEY, data TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if err := initializeDatabase(db); err == nil || !strings.Contains(err.Error(), "does not migrate") {
		t.Fatalf("initializeDatabase() error = %v, want explicit legacy-secrets error", err)
	}
}

func TestInitializeDatabaseKeepsSecretsSchemaSeparate(t *testing.T) {
	dir := t.TempDir()
	appDB, err := sql.Open("sqlite", filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer appDB.Close()
	secretsDB, err := sql.Open("sqlite", filepath.Join(dir, "vault-secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer secretsDB.Close()

	if err := initializeDatabase(appDB); err != nil {
		t.Fatal(err)
	}
	if err := initializeSecretsDatabase(secretsDB); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		db   *sql.DB
		want int
	}{
		{appDB, 0},
		{secretsDB, 1},
	} {
		var count int
		if err := check.db.QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'secrets'",
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != check.want {
			t.Fatalf("secrets table count = %d, want %d", count, check.want)
		}
	}
}

func TestAppAndSecretsAEADKeysAreIndependent(t *testing.T) {
	appKey := bytes.Repeat([]byte{1}, databaseKeyLength)
	secretsKey := bytes.Repeat([]byte{2}, databaseKeyLength)
	appAEAD, err := newDatabaseAEAD(appKey)
	if err != nil {
		t.Fatal(err)
	}
	secretsAEAD, err := newDatabaseAEAD(secretsKey)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := encryptWithAEAD(secretsAEAD, []byte("secret data"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := decryptWithAEAD(secretsAEAD, encoded)
	if err != nil || string(plaintext) != "secret data" {
		t.Fatalf("secrets AEAD round trip = %q, %v", plaintext, err)
	}
	if _, err := decryptWithAEAD(appAEAD, encoded); err == nil {
		t.Fatal("app database key decrypted secrets data")
	}
}

func TestAuthenticatedPagesShareAccountSecurityNavigation(t *testing.T) {
	pages := []string{
		"secret.gohtml",
		"secrets.gohtml",
		"token.gohtml",
		"audit.gohtml",
		"security.gohtml",
		"account.gohtml",
	}
	for _, name := range pages {
		t.Run(name, func(t *testing.T) {
			content, err := embeddedFiles.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			html := string(content)
			if !strings.Contains(html, `href="/account.html"`) {
				t.Errorf("%s is missing the Account link", name)
			}
			if !strings.Contains(html, `href="/account.html">Account</a>`) {
				t.Errorf("%s Account button text is not Account", name)
			}
			if !strings.Contains(html, `href="/security.html"`) {
				t.Errorf("%s is missing the Security link", name)
			}
			hasLogout := strings.Contains(html, `id="logout"`)
			if wantLogout := name == "account.gohtml"; hasLogout != wantLogout {
				t.Errorf("%s Logout presence = %t, want %t", name, hasLogout, wantLogout)
			}
			if name == "account.gohtml" {
				if strings.Contains(html, "Provisioning URI") || strings.Contains(html, `id="totpProvisioningURI"`) {
					t.Error("provisioning URI is still displayed in the setup dialog")
				}
				if !strings.Contains(html, "window.confirm('Are you sure you want to log out?')") {
					t.Error("Logout does not confirm before signing out")
				}
				navStart := strings.Index(html, "<nav")
				if navStart < 0 {
					t.Fatal("account navigation is missing")
				}
				navEnd := strings.Index(html[navStart:], "</nav>")
				if navEnd < 0 {
					t.Fatal("account navigation is missing")
				}
				if strings.Contains(html[navStart:navStart+navEnd], `id="logout"`) {
					t.Error("Logout button is still in the top navigation")
				}
			}
		})
	}
}

func TestNotyfAssetsAreWiredIntoInteractivePages(t *testing.T) {
	pages := []string{
		"account.gohtml",
		"audit.gohtml",
		"login.gohtml",
		"secret.gohtml",
		"secrets.gohtml",
		"security.gohtml",
		"setup.gohtml",
		"token.gohtml",
	}
	for _, name := range pages {
		content, err := embeddedFiles.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		html := string(content)
		for _, marker := range []string{
			`href="/notyf.css"`,
			`src="/notyf.js"`,
			`src="/notifications.js"`,
		} {
			if !strings.Contains(html, marker) {
				t.Errorf("%s is missing %s", name, marker)
			}
		}
	}

	for _, asset := range []struct {
		name        string
		contentType string
		marker      string
	}{
		{"notyf.css", "text/css; charset=utf-8", ".notyf {"},
		{"notyf.js", "text/javascript; charset=utf-8", "window.Notyf = exports.Notyf"},
		{"notifications.js", "text/javascript; charset=utf-8", "window.vaultNotify"},
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/"+asset.name, nil)
		serveEmbeddedAsset(asset.name, asset.contentType).ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("%s status = %d, want %d", asset.name, response.Code, http.StatusOK)
		}
		if got := response.Header().Get("Content-Type"); got != asset.contentType {
			t.Errorf("%s content type = %q, want %q", asset.name, got, asset.contentType)
		}
		if !strings.Contains(response.Body.String(), asset.marker) {
			t.Errorf("%s does not contain expected marker %q", asset.name, asset.marker)
		}
	}
}

func TestPageTemplatesRenderStandalonePages(t *testing.T) {
	tests := []struct {
		name    string
		markers []string
	}{
		{"index.gohtml", []string{"http-equiv=\"refresh\"", "/secrets.html"}},
		{"setup.gohtml", []string{"<title>Initial setup - Vault Server</title>", `id="phase1"`, `id="phase2"`, `id="phase3"`, `id="phase4"`, `id="phase5"`, `id="setupKeyForm"`, `id="skipDomains"`, `id="extensionsForm"`, `id="enableOperators"`, `id="enableBackup"`, `id="skipExtensions"`, `id="loginLink"`, `name="password_confirmation"`, `name="main_domain"`, `name="alias_domains"`, `name="certificate_mode"`, `value="acme"`, "/v1/setup/validate-key", "/v1/setup/domains", "/v1/setup", "location.assign(result.redirect_url)"}},
		{"login.gohtml", []string{`id="loginForm"`, `id="totpChallenge"`, `id="loginSpinner"`, `id="loginButtonLabel"`, "Signing in...", "Failed sign-in attempts are recorded with your IP address.", "Repeated failed attempts may result in this IP being blocked from signing in.", "/v1/auth/login"}},
		{"secret.gohtml", []string{`id="paths"`, `id="secretPath"`, "secret-editor-layout", `class="secret-editor-heading"`, `id="secretBreadcrumb"`, `id="secretBreadcrumbItems"`, `id="versionControls"`, `id="versionSelect"`, `id="secretAccessDetails"`, `id="secretCLIPath"`, `id="secretAPIPath"`, `id="secretCLICommand"`, `id="secretAPICurlCommand"`, "renderSecretAccessDetails", "(current)", "loadSecretVersion", "window.vaultNotify.error", "window.vaultNotify.info", "window.vaultNotify.success", "renderBreadcrumb", `id="convert-format"`, `id="convert-case"`, "parseDotenv", "validateEditorData", "Duplicate dotenv key", ".slice(0, 20)", "location.assign('/secrets.html?mount='"}},
		{"secrets.gohtml", []string{`id="secret-summary"`, `id="secret-list"`, "/v1/secrets-browser", "all:'true'"}},
		{"token.gohtml", []string{`id="tokens"`, `id="openCreateToken"`, `id="createTokenDialog"`, `id="createToken"`, `id="closeCreateToken"`, `id="finishCreateToken"`, `id="tokenMounts"`, `<select id="tokenLifetimeDays" name="expires_in_days" required>`, `<option value="30" selected>30 days</option>`, `<option value="60">60 days</option>`, `<option value="90">90 days</option>`, `<option value="180">180 days</option>`, `<option value="365">365 days</option>`, `id="editTokenMounts"`, `id="tokenCopyPanel"`, `id="copyToken"`, "downloadClientCert", "downloadClientKey", "token-actions", "Sample vault-backup command", `id="sampleCommand"`, "window.confirm", "addEventListener('beforeunload'", "async function refreshTokens()"}},
		{"security.gohtml", []string{`id="settingsForm"`, `id="enforceMTLS"`, `id="autoBlockLoginBruteforceIP"`, `id="fileLogging"`, `id="viewBlockedIPs"`, `id="blockedIPsDialog"`}},
		{"account.gohtml", []string{`id="totpSetupPanel"`, `id="openTOTPSetup"`, `>Setup 2FA</button>`, `<dialog id="totpSetupDialog"`, `id="closeTOTPSetup"`, `id="setupTOTP"`, `id="totpQRCode"`, `id="enableForm"`, `id="totpEnabledPanel"`, `id="openRecoveryCodesDialog"`, `<dialog id="recoveryCodesDialog"`, `id="regenerateRecoveryCodesForm"`, `<dialog id="disableTOTPDialog"`, `id="openDisableTOTPDialog"`, `<dialog id="passwordDialog"`, `id="passwordForm"`, `id="currentPassword"`, `id="newPassword"`, `id="repeatNewPassword"`, "/v1/account/totp/recovery-codes", "/v1/account/password", "/qrcode.js", "/v1/account/totp"}},
		{"audit.gohtml", []string{`id="events"`, `href="/audits.html"`, "/v1/audit", "create_token", "update_token_mounts", "update_operator_mounts", "revoke_token", "issue_certificate", "rotate_certificate", "update_settings", "block_login_ip", "unblock_login_ip", "server_backup", ">started</option>", "async function refresh()"}},
		{"401.gohtml", []string{"401", "Go to login"}},
		{"404.gohtml", []string{"404", "Page not found"}},
		{"lock.gohtml", []string{"423", "Setup locked", "<style>", ".status-page", ".status-card", "var(--danger)"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := any(nil)
			switch test.name {
			case "index.gohtml":
				data = map[string]string{"Destination": "/secrets.html"}
			case "setup.gohtml":
				data = map[string]bool{"ACMEAvailable": true}
			case "login.gohtml":
				data = map[string]bool{"AutoBlockLoginIPEnabled": true}
			case "secret.gohtml", "secrets.gohtml", "token.gohtml", "audit.gohtml", "account.gohtml":
				data = map[string]bool{"IsAdmin": true, "HasOperators": true}
			}
			var output bytes.Buffer
			if err := pageTemplate.ExecuteTemplate(&output, test.name, data); err != nil {
				t.Fatal(err)
			}
			for _, marker := range test.markers {
				if !strings.Contains(output.String(), marker) {
					t.Errorf("rendered %s does not contain %q", test.name, marker)
				}
			}
			if test.name == "lock.gohtml" && strings.Contains(output.String(), `href="/admin.css"`) {
				t.Error("lock page should use its page-local styles instead of admin.css")
			}
			if test.name == "secret.gohtml" {
				if strings.Contains(output.String(), `id="error"`) {
					t.Error("secret editor should display messages through Notyf, not an inline error box")
				}
				for _, title := range []string{
					`id="editorTitle"`,
					`id="currentVersion"`,
					`<label for="secretPath">`,
					`<label for="versionSelect">`,
				} {
					if strings.Contains(output.String(), title) {
						t.Errorf("secret editor still renders title %q", title)
					}
				}
			}
			if test.name == "setup.gohtml" &&
				(strings.Contains(output.String(), " of 4:") || strings.Contains(output.String(), `id="setupProgress"`)) {
				t.Error("setup page exposes a public setup-step list")
			}
			switch test.name {
			case "login.gohtml", "secret.gohtml", "secrets.gohtml", "token.gohtml",
				"security.gohtml", "account.gohtml", "audit.gohtml":
				if !strings.Contains(output.String(), `<h1 class="brand"><a href="/">Vault Server</a></h1>`) {
					t.Errorf("%s brand heading does not link to the root page", test.name)
				}
			}
			if test.name == "index.gohtml" && strings.Contains(output.String(), `location.replace("\"`) {
				t.Error("navigator includes quotes in the redirect URL")
			}
		})
	}
}

func TestIndexNavigatesByServerState(t *testing.T) {
	tests := []struct {
		name          string
		adminName     string
		authenticated bool
		locked        bool
		destination   string
	}{
		{"setup", "", false, false, "/setup.html"},
		{"locked", "", false, true, "/lock.html"},
		{"login", "admin", false, false, "/login.html"},
		{"secrets", "admin", true, false, "/secrets.html"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := &server{adminName: test.adminName, sessions: map[string]sessionInfo{}}
			if test.locked {
				s.setupDeadline = time.Now().Add(-time.Second)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.authenticated {
				const token = "session-token"
				s.sessions[token] = sessionInfo{username: "admin", role: "admin", expiresAt: time.Now().Add(time.Minute)}
				request.AddCookie(&http.Cookie{Name: "vault_session", Value: token})
			}
			response := httptest.NewRecorder()
			s.serveHome(response, request)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.destination) {
				t.Fatalf("navigator response = status %d, destination marker %q", response.Code, test.destination)
			}
		})
	}
}

func TestWebPagesUseExpectedStatusAndContent(t *testing.T) {
	s := newOperatorTestServer(t)

	login := httptest.NewRecorder()
	s.serveLogin(login, httptest.NewRequest(http.MethodGet, "/login", nil))
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), `id="loginForm"`) {
		t.Fatalf("login page returned status %d or did not contain its form", login.Code)
	}
	warning := "Failed sign-in attempts are recorded with your IP address."
	if !strings.Contains(login.Body.String(), warning) {
		t.Fatal("login warning is missing while automatic IP blocking is enabled by default")
	}
	if _, err := s.db.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		autoBlockLoginIPSetting,
		"true",
	); err != nil {
		t.Fatalf("enable automatic IP blocking: %v", err)
	}
	login = httptest.NewRecorder()
	s.serveLogin(login, httptest.NewRequest(http.MethodGet, "/login", nil))
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), warning) {
		t.Fatal("login warning is missing while automatic IP blocking is enabled")
	}

	unauthorized := httptest.NewRecorder()
	s.serveUnauthorized(unauthorized, httptest.NewRequest(http.MethodGet, "/401", nil))
	if unauthorized.Code != http.StatusUnauthorized || !strings.Contains(unauthorized.Body.String(), "401") {
		t.Fatalf("unauthorized page returned status %d or invalid content", unauthorized.Code)
	}

	notFound := httptest.NewRecorder()
	s.serveNotFound(notFound, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if notFound.Code != http.StatusNotFound || !strings.Contains(notFound.Body.String(), "404") {
		t.Fatalf("not-found page returned status %d or invalid content", notFound.Code)
	}

	apiNotFound := httptest.NewRecorder()
	s.serveNotFound(apiNotFound, httptest.NewRequest(http.MethodPost, "/api/v1/missing", nil))
	if apiNotFound.Code != http.StatusNotFound || apiNotFound.Body.Len() != 0 {
		t.Fatalf("API not-found response = status %d, body %q", apiNotFound.Code, apiNotFound.Body.String())
	}

	home := httptest.NewRecorder()
	s.serveHome(home, httptest.NewRequest(http.MethodGet, "/", nil))
	if home.Code != http.StatusOK || !strings.Contains(home.Body.String(), "/login.html") {
		t.Fatalf("unauthenticated home navigator = %d %q", home.Code, home.Body.String())
	}

	secret := httptest.NewRecorder()
	s.serveSecrets(secret, httptest.NewRequest(http.MethodGet, "/secret.html", nil))
	if secret.Code != http.StatusUnauthorized || !strings.Contains(secret.Body.String(), "401") {
		t.Fatalf("unauthenticated secret page = %d", secret.Code)
	}
}

func TestHealthChecksConfiguredDatabases(t *testing.T) {
	for _, unavailable := range []string{"app", "secrets", "operator", "audit"} {
		t.Run(unavailable, func(t *testing.T) {
			dir := t.TempDir()
			db, err := sql.Open("sqlite", filepath.Join(dir, "vault.db"))
			if err != nil {
				t.Fatal(err)
			}
			secretsDB, err := sql.Open("sqlite", filepath.Join(dir, "secrets.db"))
			if err != nil {
				t.Fatal(err)
			}
			operatorDB, err := sql.Open("sqlite", filepath.Join(dir, "operator.db"))
			if err != nil {
				t.Fatal(err)
			}
			auditStore, err := openAnnualAuditStore(filepath.Join(dir, "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if db != nil {
					if err := db.Close(); err != nil {
						t.Errorf("close app database: %v", err)
					}
				}
				if secretsDB != nil {
					if err := secretsDB.Close(); err != nil {
						t.Errorf("close secrets database: %v", err)
					}
					if operatorDB != nil {
						if err := operatorDB.Close(); err != nil {
							t.Errorf("close operator database: %v", err)
						}
					}
				}
				if auditStore != nil {
					if err := auditStore.Close(); err != nil {
						t.Errorf("close audit database: %v", err)
					}
				}
			})

			s := &server{db: db, secretsDB: secretsDB, operatorDB: operatorDB, auditStore: auditStore}
			healthy := httptest.NewRecorder()
			s.health(healthy, httptest.NewRequest(http.MethodGet, "/health", nil))
			if healthy.Code != http.StatusOK || healthy.Body.String() != "{\"ok\":true}\n" {
				t.Fatalf("healthy response = %d %q", healthy.Code, healthy.Body.String())
			}

			switch unavailable {
			case "app":
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				db = nil
			case "secrets":
				if err := secretsDB.Close(); err != nil {
					t.Fatal(err)
				}
				secretsDB = nil
			case "operator":
				if err := operatorDB.Close(); err != nil {
					t.Fatal(err)
				}
				operatorDB = nil
			case "audit":
				if err := auditStore.Close(); err != nil {
					t.Fatal(err)
				}
				auditStore = nil
			}

			unhealthy := httptest.NewRecorder()
			s.health(unhealthy, httptest.NewRequest(http.MethodGet, "/health", nil))
			if unhealthy.Code != http.StatusServiceUnavailable || unhealthy.Body.String() != "{\"ok\":false}\n" {
				t.Fatalf("unhealthy response = %d %q", unhealthy.Code, unhealthy.Body.String())
			}
		})
	}
}

func TestOpenAuditDatabaseIsSeparateAndQueryable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := openAuditDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`
		INSERT INTO audit_events(created_at, action, outcome, actor, client_ip, source, resource, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().Unix(), "read", "success", "admin", "127.0.0.1", "web", "app/database", "",
	); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit event count = %d, want 1", count)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(contents), "SQLite format 3\x00") {
		t.Fatal("audit database is not plaintext SQLite")
	}
}

func TestBrowseSecretsGroupsAndPaginates(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeSecretsDatabase(db); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"kv/dummy/app/secret1",
		"kv/dummy/app/secret2",
		"kv/dummy/app/z-nested/secret3",
		"kv/production/database",
		"kv/other",
	}
	for _, path := range paths {
		insertTestSecretRecord(t, db, path, "unused")
	}

	s := &server{
		secretsDB: db,
		sessions:  map[string]sessionInfo{"session": {role: "admin", expiresAt: time.Now().Add(time.Minute)}},
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/secrets-browser?group=dummy%2Fapp&limit=10&offset=1", nil)
	request.AddCookie(&http.Cookie{Name: "vault_session", Value: "session"})
	response := httptest.NewRecorder()
	s.browseSecrets(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("browse secrets status = %d, body %q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"group":"dummy/app"`,
		`"paths":["dummy/app/secret2","dummy/app/z-nested/secret3"]`,
		`"total":3`,
		`"count":3`,
		`"name":"production/database"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("browse response %q does not contain %q", body, want)
		}
	}
	nestedRequest := httptest.NewRequest(http.MethodGet, "/v1/secrets-browser?group=dummy%2Fapp%2Fz-nested", nil)
	nestedRequest.AddCookie(&http.Cookie{Name: "vault_session", Value: "session"})
	nestedResponse := httptest.NewRecorder()
	s.browseSecrets(nestedResponse, nestedRequest)
	if nestedResponse.Code != http.StatusOK ||
		!strings.Contains(nestedResponse.Body.String(), `"group":"dummy/app/z-nested"`) ||
		!strings.Contains(nestedResponse.Body.String(), `"paths":["dummy/app/z-nested/secret3"]`) {
		t.Fatalf("nested browse response = status %d, body %s", nestedResponse.Code, nestedResponse.Body.String())
	}
	allRequest := httptest.NewRequest(http.MethodGet, "/v1/secrets-browser?all=true&limit=10&offset=1", nil)
	allRequest.AddCookie(&http.Cookie{Name: "vault_session", Value: "session"})
	allResponse := httptest.NewRecorder()
	s.browseSecrets(allResponse, allRequest)
	if allResponse.Code != http.StatusOK ||
		!strings.Contains(allResponse.Body.String(), `"group":""`) ||
		!strings.Contains(allResponse.Body.String(), `"paths":["dummy/app/secret2","dummy/app/z-nested/secret3","other","production/database"]`) ||
		!strings.Contains(allResponse.Body.String(), `"total":5`) {
		t.Fatalf("all-path browse response = status %d, body %s", allResponse.Code, allResponse.Body.String())
	}
}

func TestBrowseSecretsUsesAllowedPageSizes(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeSecretsDatabase(db); err != nil {
		t.Fatal(err)
	}
	s := &server{
		secretsDB: db,
		sessions:  map[string]sessionInfo{"session": {role: "admin", expiresAt: time.Now().Add(time.Minute)}},
	}

	for _, test := range []struct {
		query string
		want  []string
	}{
		{"", []string{`"limit":20`, `"groups":[]`, `"paths":[]`}},
		{"?limit=999", []string{`"limit":20`}},
		{"?limit=50", []string{`"limit":50`}},
	} {
		request := httptest.NewRequest(http.MethodGet, "/v1/secrets-browser"+test.query, nil)
		request.AddCookie(&http.Cookie{Name: "vault_session", Value: "session"})
		response := httptest.NewRecorder()
		s.browseSecrets(response, request)
		for _, want := range test.want {
			if !strings.Contains(response.Body.String(), want) {
				t.Fatalf("query %q response = %q, want %q", test.query, response.Body.String(), want)
			}
		}
	}

}

func TestValidSecretPath(t *testing.T) {
	for _, path := range []string{"kv", "kv/dummy/load-test-10", "A-Z/secret123"} {
		if !validSecretPath(path) {
			t.Errorf("valid path %q was rejected", path)
		}
	}
	for _, path := range []string{"", "/kv", "kv/", "kv//secret", "kv/dummy_test", "kv/dummy.test", strings.Repeat("a", 128)} {
		if validSecretPath(path) {
			t.Errorf("invalid path %q was accepted", path)
		}
	}
}

func TestSetupWindowLockResponses(t *testing.T) {
	s := &server{setupDeadline: time.Now().Add(-time.Second)}

	page := httptest.NewRecorder()
	s.serveSetup(page, httptest.NewRequest(http.MethodGet, "/setup.html", nil))
	if page.Code != http.StatusLocked || !strings.Contains(page.Body.String(), "Setup locked") {
		t.Fatalf("locked setup page = status %d", page.Code)
	}

	api := httptest.NewRecorder()
	s.setup(api, httptest.NewRequest(http.MethodPost, "/v1/setup", strings.NewReader("invalid json")))
	if api.Code != http.StatusLocked || !strings.Contains(api.Body.String(), "setup window expired") {
		t.Fatalf("locked setup API = status %d, body %q", api.Code, api.Body.String())
	}

	middlewareAPI := httptest.NewRecorder()
	handler := s.setupLockAPIs(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("locked API request reached the next handler")
	}))
	handler.ServeHTTP(middlewareAPI, httptest.NewRequest(http.MethodGet, "/api/v1/kv/data/app/test", nil))
	if middlewareAPI.Code != http.StatusLocked {
		t.Fatalf("locked Vault API status = %d", middlewareAPI.Code)
	}
	if got := middlewareAPI.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("locked Vault API content type = %q", got)
	}
	if middlewareAPI.Body.String() != "{\"error\":\"setup window expired\"}\n" {
		t.Fatalf("locked Vault API body = %q", middlewareAPI.Body.String())
	}

	html := httptest.NewRecorder()
	htmlHandler := s.setupLockAPIs(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	htmlHandler.ServeHTTP(html, httptest.NewRequest(http.MethodGet, "/setup.html", nil))
	if html.Code != http.StatusNoContent {
		t.Fatalf("HTML route passed through lock middleware with status %d", html.Code)
	}
}

func TestSetupDeadlinePersists(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE server_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}

	const startedAt int64 = 1700000000
	if _, err := db.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, ?)",
		"setup_started_at",
		strconv.FormatInt(startedAt, 10),
	); err != nil {
		t.Fatal(err)
	}
	deadline, err := loadOrCreateSetupDeadline(db)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Unix(startedAt, 0).Add(setupLifetime); !deadline.Equal(want) {
		t.Fatalf("setup deadline = %v, want %v", deadline, want)
	}
}

func TestDatabaseKeyIsEncryptedAnd128Bytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db.key")
	password := "a-secure-test-password"

	key, err := loadOrCreateKey(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != databaseKeyLength {
		t.Fatalf("database key length: got %d, want %d", len(key), databaseKeyLength)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) == databaseKeyLength {
		t.Fatal("database key file contains a raw key")
	}

	loaded, err := loadOrCreateKey(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != databaseKeyLength {
		t.Fatalf("loaded database key length: got %d, want %d", len(loaded), databaseKeyLength)
	}
	for i := range key {
		if key[i] != loaded[i] {
			t.Fatal("database key changed after reopening")
		}
	}

	if _, err := loadOrCreateKey(path, "wrong-password"); err == nil {
		t.Fatal("wrong database password was accepted")
	}
}

func TestLegacy32ByteKeyIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db.key")
	if err := os.WriteFile(path, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKey(path, "password"); err == nil {
		t.Fatal("legacy 32-byte key was accepted")
	}
}

func TestLoadDotEnvPreservesExistingEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.env")
	contents := "VAULT_SERVER_DB_PASSWORD=from-file\nVAULT_SERVER_HTTPS_ADDR=127.0.0.1:8200\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_SERVER_DB_PASSWORD", "from-process")

	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("VAULT_SERVER_DB_PASSWORD"); got != "from-process" {
		t.Fatalf("existing environment was overwritten: got %q", got)
	}
	if got := os.Getenv("VAULT_SERVER_HTTPS_ADDR"); got != "127.0.0.1:8200" {
		t.Fatalf("env file value was not loaded: got %q", got)
	}
}

func TestLoadClientCAPoolRejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClientCAPool(path); err == nil {
		t.Fatal("invalid client CA PEM was accepted")
	}
}

func TestOpenDatabaseEncryptsNewDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	key := []byte("0123456789abcdef0123456789abcdef")

	db, legacy, err := openDatabase(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if legacy {
		t.Fatal("new database selected the legacy driver")
	}
	if _, err := db.Exec("CREATE TABLE test (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	plaintext, err := isPlaintextSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext {
		t.Fatal("new database has a plaintext SQLite header")
	}
}

func TestOpenDatabasePreservesPlaintextDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	legacyDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec("CREATE TABLE test (value TEXT); INSERT INTO test VALUES ('preserved')"); err != nil {
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	db, legacy, err := openDatabaseWithOptions(path, []byte("0123456789abcdef0123456789abcdef"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if !legacy {
		t.Fatal("plaintext database did not select the legacy driver")
	}

	var value string
	if err := db.QueryRow("SELECT value FROM test").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "preserved" {
		t.Fatalf("got %q, want %q", value, "preserved")
	}
}

func TestOpenDatabaseRejectsPlaintextDatabaseByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	legacyDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec("CREATE TABLE test (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	_, legacy, err := openDatabase(path, []byte("0123456789abcdef0123456789abcdef"))
	if err == nil {
		t.Fatal("plaintext database was accepted without an explicit insecure opt-in")
	}
	if !legacy {
		t.Fatal("plaintext database was not detected")
	}
}

func TestLoginAttemptsIgnoreEphemeralPorts(t *testing.T) {
	s := &server{attempts: map[string][]time.Time{}}
	for i := 0; i < loginAttemptLimit; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
		request.RemoteAddr = "192.0.2.10:" + strconv.Itoa(40000+i)
		if !s.allowLoginAttempt(request, "admin") {
			t.Fatalf("attempt %d was unexpectedly blocked", i+1)
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	request.RemoteAddr = "192.0.2.10:59999"
	if s.allowLoginAttempt(request, "other-user") {
		t.Fatal("new ephemeral port bypassed the IP limit")
	}
}

func TestLoginAttemptsAreLimitedPerAccount(t *testing.T) {
	s := &server{attempts: map[string][]time.Time{}}
	for i := 0; i < loginAttemptLimit; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
		request.RemoteAddr = fmt.Sprintf("198.51.100.%d:40000", i+1)
		if !s.allowLoginAttempt(request, "Admin") {
			t.Fatalf("attempt %d was unexpectedly blocked", i+1)
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	request.RemoteAddr = "203.0.113.20:40000"
	if s.allowLoginAttempt(request, "admin") {
		t.Fatal("new source IP bypassed the account limit")
	}
}

func TestClientIPTrustsForwardedAddressOnlyFromTrustedProxy(t *testing.T) {
	ranges, err := parseTrustedProxies("10.0.0.0/8, 192.0.2.5")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{trustedProxies: ranges}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	request.RemoteAddr = "10.1.2.3:40000"
	request.Header.Set("X-Forwarded-For", "203.0.113.8")
	if got := s.clientIP(request); got != "203.0.113.8" {
		t.Fatalf("trusted proxy client IP = %q", got)
	}

	request.RemoteAddr = "198.51.100.10:40000"
	if got := s.clientIP(request); got != "198.51.100.10" {
		t.Fatalf("untrusted proxy client IP = %q", got)
	}
}

func TestLoginAttemptWindowExpires(t *testing.T) {
	s := &server{
		attempts: map[string][]time.Time{
			"ip:192.0.2.10": {time.Now().Add(-loginAttemptWindow - time.Second)},
			"account:admin": {time.Now().Add(-loginAttemptWindow - time.Second)},
		},
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	request.RemoteAddr = "192.0.2.10:40000"
	if !s.allowLoginAttempt(request, "admin") {
		t.Fatal("expired attempts were not discarded")
	}
}

func TestShutdownServersWaitsForActiveRequests(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-releaseRequest
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() {
		_ = server.Serve(listener)
	}()

	requestDone := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	<-requestStarted

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutdownDone <- shutdownServers(ctx, []*http.Server{server})
	}()

	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown completed before active request drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseRequest)
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	if err := <-shutdownDone; err != nil {
		t.Fatal(err)
	}
}
