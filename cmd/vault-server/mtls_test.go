package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
