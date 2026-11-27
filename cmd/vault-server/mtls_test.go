package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
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
		if err := writer.DisableFileLogging(); err != nil {
			t.Errorf("disable file logging: %v", err)
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
