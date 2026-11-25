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
	readSettings := func() map[string]bool {
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
		var settings map[string]bool
		if err := json.Unmarshal(response.Body.Bytes(), &settings); err != nil {
			t.Fatal(err)
		}
		return settings
	}

	if settings := readSettings(); settings["enforce_mfa"] {
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
	if settings := readSettings(); !settings["enforce_mfa"] {
		t.Fatal("partial settings update did not preserve MFA enforcement")
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
