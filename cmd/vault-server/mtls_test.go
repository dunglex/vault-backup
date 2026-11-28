package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"database/sql"
)

func TestManagedCertificateUsesTokenExpiry(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	cipherBlock, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		t.Fatal(err)
	}
	server := &server{db: db, aead: aead}
	if err := server.loadOrCreateManagedClientCA(); err != nil {
		t.Fatal(err)
	}

	tokenExpiry := time.Now().UTC().Truncate(time.Second).Add(90 * 24 * time.Hour)
	issued, err := server.issueClientCertificate(42, tokenExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if !issued.ExpiresAt.Equal(tokenExpiry) {
		t.Fatalf("reported certificate expiry = %s, want %s", issued.ExpiresAt, tokenExpiry)
	}
	certBlock, _ := pem.Decode([]byte(issued.Certificate))
	if certBlock == nil {
		t.Fatal("issued certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.NotAfter.Equal(tokenExpiry) {
		t.Fatalf("certificate NotAfter = %s, want %s", certificate.NotAfter, tokenExpiry)
	}
	if _, err := tls.X509KeyPair([]byte(issued.Certificate), []byte(issued.PrivateKey)); err != nil {
		t.Fatalf("issued certificate and key do not match: %v", err)
	}
}

func TestAPIClientCertificateGuardReturnsUnauthorizedForInvalidCredentials(t *testing.T) {
	s := newOperatorTestServer(t)
	if _, err := s.db.Exec("INSERT INTO server_settings(key, value) VALUES ('enforce_mtls', 'true')"); err != nil {
		t.Fatal(err)
	}
	insertScopedAPIToken(t, s, "cert-token", []string{"kv"}, "")
	insertScopedAPIToken(t, s, "other-token", []string{"kv"}, "")

	var tokenID int64
	if err := s.db.QueryRow("SELECT id FROM api_tokens WHERE name = 'cert-token'").Scan(&tokenID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := s.db.Exec(`
		INSERT INTO managed_client_certificates(serial_number, token_id, certificate_pem, created_at, not_after)
		VALUES (?, ?, 'test-certificate', ?, ?)`,
		"cafe", tokenID, now, now+3600,
	); err != nil {
		t.Fatal(err)
	}

	cert := func(serial int64) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial)}
	}
	matchingCert := cert(0xcafe)
	unregisteredCert := cert(0xbeef)
	request := func(token string, clientCert *x509.Certificate) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/kv/data/example", nil)
		r.Header.Set("X-Vault-Backup-Protocol", "client-cert-v1")
		if token != "" {
			r.Header.Set("X-Vault-Token", token)
		}
		if clientCert != nil {
			r.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{clientCert},
				VerifiedChains:   [][]*x509.Certificate{{clientCert}},
			}
		}
		return r
	}
	handler := s.apiClientCertificateGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, test := range []struct {
		name       string
		token      string
		cert       *x509.Certificate
		wantStatus int
	}{
		{name: "invalid token", token: "wrong-token", cert: matchingCert, wantStatus: http.StatusUnauthorized},
		{name: "missing certificate", token: "cert-token", wantStatus: http.StatusUnauthorized},
		{name: "unregistered certificate", token: "cert-token", cert: unregisteredCert, wantStatus: http.StatusUnauthorized},
		{name: "certificate for another token", token: "other-token", cert: matchingCert, wantStatus: http.StatusUnauthorized},
		{name: "matching credentials", token: "cert-token", cert: matchingCert, wantStatus: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request(test.token, test.cert))
			if response.Code != test.wantStatus {
				t.Fatalf("response status = %d, want %d; body %s", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestMFAEnforcementSettingPersistsAndSupportsPartialUpdates(t *testing.T) {
	s := newOperatorTestServer(t)
	readSettings := func() bool {
		t.Helper()
		response := httptest.NewRecorder()
		s.getSettings(response, operatorRequestWithSession(
			http.MethodGet,
			"/v1/settings",
			"",
			"admin-session",
			true,
		))
		if response.Code != http.StatusOK {
			t.Fatalf("read settings status = %d, body %s", response.Code, response.Body.String())
		}
		var settings struct {
			EnforceMFA bool `json:"enforce_mfa"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &settings); err != nil {
			t.Fatal(err)
		}
		return settings.EnforceMFA
	}

	if settings := readSettings(); settings {
		t.Fatal("MFA enforcement should be disabled by default")
	}
	enable := httptest.NewRecorder()
	s.updateSettings(enable, operatorRequestWithSession(
		http.MethodPut,
		"/v1/settings",
		`{"enforce_mfa":true}`,
		"admin-session",
		true,
	))
	if enable.Code != http.StatusOK || !strings.Contains(enable.Body.String(), `"enforce_mfa":true`) {
		t.Fatalf("enable MFA enforcement = %d, body %s", enable.Code, enable.Body.String())
	}

	partialUpdate := httptest.NewRecorder()
	s.updateSettings(partialUpdate, operatorRequestWithSession(
		http.MethodPut,
		"/v1/settings",
		`{"enforce_mtls":false}`,
		"admin-session",
		true,
	))
	if partialUpdate.Code != http.StatusOK || !strings.Contains(partialUpdate.Body.String(), `"enforce_mfa":true`) {
		t.Fatalf("partial settings update = %d, body %s", partialUpdate.Code, partialUpdate.Body.String())
	}
	if settings := readSettings(); !settings {
		t.Fatal("partial settings update did not preserve MFA enforcement")
	}
}

func TestAutomaticBackupSettingsAndCronValidation(t *testing.T) {
	s := newOperatorTestServer(t)
	s.backupEnabled = true
	if err := s.startBackupScheduler(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.stopBackupScheduler(); err != nil {
			t.Errorf("stop backup scheduler: %v", err)
		}
	})

	response := httptest.NewRecorder()
	s.getBackupSettings(response, operatorRequestWithSession(http.MethodGet, "/v1/backup/settings", "", "admin-session", true))
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"automatic_server_backup":false`) ||
		!strings.Contains(response.Body.String(), `"server_backup_cron":"0 0 2 * * *"`) {
		t.Fatalf("read default backup settings = %d, body %s", response.Code, response.Body.String())
	}

	invalid := httptest.NewRecorder()
	s.updateBackupSettings(invalid, operatorRequestWithSession(
		http.MethodPut,
		"/v1/backup/settings",
		`{"automatic_server_backup":true,"server_backup_cron":"0 2 * * *"}`,
		"admin-session",
		true,
	))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid backup cron status = %d, body %s", invalid.Code, invalid.Body.String())
	}

	enable := httptest.NewRecorder()
	s.updateBackupSettings(enable, operatorRequestWithSession(
		http.MethodPut,
		"/v1/backup/settings",
		`{"automatic_server_backup":true,"server_backup_cron":"0 0 0 1 1 *"}`,
		"admin-session",
		true,
	))
	if enable.Code != http.StatusOK || !strings.Contains(enable.Body.String(), `"automatic_server_backup":true`) {
		t.Fatalf("enable scheduled backup = %d, body %s", enable.Code, enable.Body.String())
	}
	if jobs := s.backupCron.Jobs(); len(jobs) != 1 {
		t.Fatalf("scheduled backup jobs = %d, want 1", len(jobs))
	}

	disable := httptest.NewRecorder()
	s.updateBackupSettings(disable, operatorRequestWithSession(
		http.MethodPut,
		"/v1/backup/settings",
		`{"automatic_server_backup":false}`,
		"admin-session",
		true,
	))
	if disable.Code != http.StatusOK || !strings.Contains(disable.Body.String(), `"automatic_server_backup":false`) {
		t.Fatalf("disable scheduled backup = %d, body %s", disable.Code, disable.Body.String())
	}
	if jobs := s.backupCron.Jobs(); len(jobs) != 0 {
		t.Fatalf("scheduled backup jobs after disable = %d, want 0", len(jobs))
	}
}

func TestFileLoggingSecuritySettingPersistsAndControlsLogger(t *testing.T) {
	s := newOperatorTestServer(t)
	writer := newServerLogWriter(io.Discard, filepath.Join(t.TempDir(), "vault-server"))
	s.logWriter = writer
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Errorf("close log writer: %v", err)
		}
	})

	enabled, err := s.fileLoggingEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("file logging should be disabled by default")
	}
	settingsResponse := httptest.NewRecorder()
	s.getSettings(settingsResponse, operatorRequestWithSession(
		http.MethodGet,
		"/v1/settings",
		"",
		"admin-session",
		true,
	))
	if settingsResponse.Code != http.StatusOK ||
		!strings.Contains(settingsResponse.Body.String(), `"file_logging":false`) {
		t.Fatalf("read default file logging setting = %d, body %s", settingsResponse.Code, settingsResponse.Body.String())
	}

	enable := httptest.NewRecorder()
	s.updateSettings(enable, operatorRequestWithSession(
		http.MethodPut,
		"/v1/settings",
		`{"file_logging":true}`,
		"admin-session",
		true,
	))
	if enable.Code != http.StatusOK || !strings.Contains(enable.Body.String(), `"file_logging":true`) {
		t.Fatalf("enable file logging = %d, body %s", enable.Code, enable.Body.String())
	}
	enabled, err = s.fileLoggingEnabled()
	if err != nil || !enabled {
		t.Fatalf("file logging setting = %t, error %v", enabled, err)
	}
	if writer.file == nil {
		t.Fatal("file logging was not enabled")
	}

	disable := httptest.NewRecorder()
	s.updateSettings(disable, operatorRequestWithSession(
		http.MethodPut,
		"/v1/settings",
		`{"file_logging":false}`,
		"admin-session",
		true,
	))
	if disable.Code != http.StatusOK || !strings.Contains(disable.Body.String(), `"file_logging":false`) {
		t.Fatalf("disable file logging = %d, body %s", disable.Code, disable.Body.String())
	}
	if writer.file != nil {
		t.Fatal("file logging remained enabled")
	}
}

func TestAccessLogDisableSecuritySettingPersistsAndControlsLogger(t *testing.T) {
	s := newOperatorTestServer(t)
	writer := newServerLogWriter(io.Discard, filepath.Join(t.TempDir(), "vault-server"))
	s.logWriter = writer
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Errorf("close log writer: %v", err)
		}
	})

	disabled, err := readAccessLogDisabledSetting(s.db)
	if err != nil || disabled {
		t.Fatalf("access log disabled setting = %t, error %v; want false by default", disabled, err)
	}
	settingsResponse := httptest.NewRecorder()
	s.getSettings(settingsResponse, operatorRequestWithSession(
		http.MethodGet,
		"/v1/settings",
		"",
		"admin-session",
		true,
	))
	if settingsResponse.Code != http.StatusOK ||
		!strings.Contains(settingsResponse.Body.String(), `"disable_access_log":false`) {
		t.Fatalf("read default access log setting = %d, body %s", settingsResponse.Code, settingsResponse.Body.String())
	}

	disable := httptest.NewRecorder()
	s.updateSettings(disable, operatorRequestWithSession(
		http.MethodPut,
		"/v1/settings",
		`{"disable_access_log":true}`,
		"admin-session",
		true,
	))
	if disable.Code != http.StatusOK || !strings.Contains(disable.Body.String(), `"disable_access_log":true`) {
		t.Fatalf("disable access logging = %d, body %s", disable.Code, disable.Body.String())
	}
	disabled, err = readAccessLogDisabledSetting(s.db)
	if err != nil || !disabled || writer.accessLoggingEnabled() {
		t.Fatalf("disabled access log setting = %t, enabled logger = %t, error %v", disabled, writer.accessLoggingEnabled(), err)
	}

	enable := httptest.NewRecorder()
	s.updateSettings(enable, operatorRequestWithSession(
		http.MethodPut,
		"/v1/settings",
		`{"disable_access_log":false}`,
		"admin-session",
		true,
	))
	if enable.Code != http.StatusOK || !strings.Contains(enable.Body.String(), `"disable_access_log":false`) {
		t.Fatalf("enable access logging = %d, body %s", enable.Code, enable.Body.String())
	}
	disabled, err = readAccessLogDisabledSetting(s.db)
	if err != nil || disabled || !writer.accessLoggingEnabled() {
		t.Fatalf("enabled access log setting = %t, enabled logger = %t, error %v", disabled, writer.accessLoggingEnabled(), err)
	}
}
