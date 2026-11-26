package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizeServerDomains(t *testing.T) {
	main, aliases, all, err := normalizeServerDomains(
		" BÜCHER.example. ",
		[]string{"ALIAS.example", "alias.example.", "127.0.0.1", ""},
	)
	if err != nil {
		t.Fatal(err)
	}
	if main != "xn--bcher-kva.example" {
		t.Fatalf("main domain = %q", main)
	}
	if !reflect.DeepEqual(aliases, []string{"alias.example", "127.0.0.1"}) {
		t.Fatalf("alias domains = %#v", aliases)
	}
	if !reflect.DeepEqual(all, []string{"xn--bcher-kva.example", "alias.example", "127.0.0.1"}) {
		t.Fatalf("all domains = %#v", all)
	}
	if _, _, _, err := normalizeServerDomains("not a domain", nil); err == nil {
		t.Fatal("invalid main domain was accepted")
	}
}

func TestServerCertificateManagerGeneratesAndRefreshesCertificate(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	manager, err := newServerCertificateManager(
		db, certPath, keyPath, filepath.Join(dir, "acme"), "127.0.0.1:8200", false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !manager.generated || manager.certificate == nil {
		t.Fatal("manager did not create its bootstrap certificate")
	}
	if info, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("private key mode = %o", info.Mode().Perm())
	}

	_, _, domains, err := normalizeServerDomains("vault.example.com", []string{"alias.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.prepareSelfSigned(domains); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("vault.example.com"); err != nil {
		t.Fatalf("main domain missing from generated certificate: %v", err)
	}
	if err := leaf.VerifyHostname("alias.example.com"); err != nil {
		t.Fatalf("alias domain missing from generated certificate: %v", err)
	}

	reloaded, err := newServerCertificateManager(
		db, certPath, keyPath, filepath.Join(dir, "acme"), "127.0.0.1:8200", false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.generated {
		t.Fatal("generated certificate ownership was not persisted")
	}
}

func TestServerCertificateManagerDoesNotReplaceProvidedPair(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	certPEM, keyPEM, _, err := generateServerCertificate([]string{"existing.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeServerCertificatePair(certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	manager, err := newServerCertificateManager(
		db, certPath, keyPath, filepath.Join(dir, "acme"), ":8200", false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if manager.generated {
		t.Fatal("provided certificate pair was marked as app-generated")
	}
	if err := manager.prepareSelfSigned([]string{"new.example.com"}); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("existing.example.com"); err != nil {
		t.Fatalf("provided certificate was replaced: %v", err)
	}
	if err := leaf.VerifyHostname("new.example.com"); err == nil {
		t.Fatal("provided certificate unexpectedly includes the new domain")
	}
}

func TestServerCertificateManagerRejectsPartialPair(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	if err := os.WriteFile(certPath, []byte("certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newServerCertificateManager(
		db, certPath, filepath.Join(dir, "server.key"), filepath.Join(dir, "acme"), ":8200", false,
	); err == nil {
		t.Fatal("partial TLS certificate pair was accepted")
	}
}

func TestSetupStoresNormalizedDomainsAndCertificateMode(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	s := &server{
		db:            db,
		setupKey:      "setup-key",
		setupDeadline: time.Now().Add(time.Hour),
		setupKeyPath:  filepath.Join(t.TempDir(), "setup-key"),
	}
	domainsBody, err := json.Marshal(setupDomainsRequest{
		SetupKey:        s.setupKey,
		MainDomain:      "Vault.Example.com.",
		AliasDomains:    []string{"alias.example.com", "ALIAS.example.com"},
		CertificateMode: serverCertificateModeSelfSigned,
	})
	if err != nil {
		t.Fatal(err)
	}
	domainsResponse := httptest.NewRecorder()
	s.saveSetupDomains(
		domainsResponse,
		httptest.NewRequest(http.MethodPost, "/v1/setup/domains", strings.NewReader(string(domainsBody))),
	)
	if domainsResponse.Code != http.StatusOK {
		t.Fatalf("save domains status = %d, body = %s", domainsResponse.Code, domainsResponse.Body.String())
	}

	body, err := json.Marshal(setupAdminRequest{
		SetupKey:             s.setupKey,
		Username:             "admin",
		Password:             "correct-horse-battery",
		PasswordConfirmation: "correct-horse-battery",
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.setup(response, httptest.NewRequest(http.MethodPost, "/v1/setup", strings.NewReader(string(body))))
	if response.Code != http.StatusCreated {
		t.Fatalf("setup status = %d, body = %s", response.Code, response.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["redirect_url"] != "https://vault.example.com/login.html" {
		t.Fatalf("setup redirect URL = %q", result["redirect_url"])
	}

	var mainDomain, aliasesJSON, mode string
	if err := db.QueryRow(
		"SELECT value FROM server_settings WHERE key = ?", serverSettingMainDomain,
	).Scan(&mainDomain); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(
		"SELECT value FROM server_settings WHERE key = ?", serverSettingAliasDomains,
	).Scan(&aliasesJSON); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(
		"SELECT value FROM server_settings WHERE key = ?", serverSettingCertificateMode,
	).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mainDomain != "vault.example.com" || aliasesJSON != `["alias.example.com"]` || mode != serverCertificateModeSelfSigned {
		t.Fatalf("saved setup settings = main %q, aliases %q, mode %q", mainDomain, aliasesJSON, mode)
	}
}

func TestSetupCanSkipDomainConfiguration(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	s := &server{
		db:            db,
		setupKey:      "setup-key",
		setupDeadline: time.Now().Add(time.Hour),
		setupKeyPath:  filepath.Join(t.TempDir(), "setup-key"),
	}
	body, err := json.Marshal(setupAdminRequest{
		SetupKey:             s.setupKey,
		Username:             "admin",
		Password:             "correct-horse-battery",
		PasswordConfirmation: "correct-horse-battery",
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.setup(response, httptest.NewRequest(http.MethodPost, "/v1/setup", strings.NewReader(string(body))))
	if response.Code != http.StatusCreated {
		t.Fatalf("setup status = %d, body = %s", response.Code, response.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["redirect_url"] != "/login.html" {
		t.Fatalf("setup redirect URL when domains are skipped = %q", result["redirect_url"])
	}

	var settingCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM server_settings").Scan(&settingCount); err != nil {
		t.Fatal(err)
	}
	if settingCount != 0 {
		t.Fatalf("server settings were saved despite skipping domain configuration: %d", settingCount)
	}
}

func TestLoadConfiguredServerDomains(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	aliases, err := json.Marshal([]string{"alias.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		serverSettingMainDomain:   "vault.example.com",
		serverSettingAliasDomains: string(aliases),
	} {
		if _, err := db.Exec("INSERT INTO server_settings(key, value) VALUES (?, ?)", key, value); err != nil {
			t.Fatal(err)
		}
	}
	domains, err := loadConfiguredServerDomains(db)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(domains, []string{"vault.example.com", "alias.example.com"}) {
		t.Fatalf("loaded domains = %#v", domains)
	}
}

func TestSetupLoginURLUsesStoredDomainAndRequestScheme(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, ?)",
		serverSettingMainDomain, "vault.example.com",
	); err != nil {
		t.Fatal(err)
	}

	s := &server{db: db}
	request := httptest.NewRequest(http.MethodPost, "/v1/setup", nil)
	loginURL, err := s.setupLoginURL(request)
	if err != nil {
		t.Fatal(err)
	}
	if loginURL != "http://vault.example.com/login.html" {
		t.Fatalf("HTTP setup redirect = %q", loginURL)
	}

	request.TLS = &tls.ConnectionState{}
	loginURL, err = s.setupLoginURL(request)
	if err != nil {
		t.Fatal(err)
	}
	if loginURL != "https://vault.example.com/login.html" {
		t.Fatalf("HTTPS setup redirect = %q", loginURL)
	}

	request.TLS = nil
	request.RemoteAddr = "10.1.2.3:8201"
	request.Header.Set("X-Forwarded-Proto", "http, https")
	ranges, err := parseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	s.trustedProxies = ranges
	loginURL, err = s.setupLoginURL(request)
	if err != nil {
		t.Fatal(err)
	}
	if loginURL != "https://vault.example.com/login.html" {
		t.Fatalf("trusted proxy HTTPS redirect = %q", loginURL)
	}

	request.RemoteAddr = "192.0.2.10:8201"
	loginURL, err = s.setupLoginURL(request)
	if err != nil {
		t.Fatal(err)
	}
	if loginURL != "http://vault.example.com/login.html" {
		t.Fatalf("untrusted proxy redirect = %q", loginURL)
	}
}

func TestHostOriginGuardChecksConfiguredDomains(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	aliasesJSON, err := json.Marshal([]string{"alias.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		serverSettingMainDomain:   "vault.example.com",
		serverSettingAliasDomains: string(aliasesJSON),
	} {
		if _, err := db.Exec("INSERT INTO server_settings(key, value) VALUES (?, ?)", key, value); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name      string
		adminName string
		path      string
		host      string
		origin    string
		wantCode  int
	}{
		{name: "main host and alias origin", adminName: "admin", path: "/v1/settings", host: "vault.example.com:8443", origin: "https://alias.example.com:9443", wantCode: http.StatusNoContent},
		{name: "missing origin for non-browser client", adminName: "admin", path: "/v1/settings", host: "vault.example.com", wantCode: http.StatusNoContent},
		{name: "unconfigured host", adminName: "admin", path: "/v1/settings", host: "attacker.example", origin: "https://vault.example.com", wantCode: http.StatusForbidden},
		{name: "unconfigured origin", adminName: "admin", path: "/v1/settings", host: "vault.example.com", origin: "https://attacker.example", wantCode: http.StatusForbidden},
		{name: "health probe remains available", adminName: "admin", path: "/health", host: "attacker.example", wantCode: http.StatusNoContent},
		{name: "liveness probe remains available", adminName: "admin", path: "/live", host: "attacker.example", wantCode: http.StatusNoContent},
		{name: "setup remains accessible until admin creation", path: "/v1/setup", host: "attacker.example", origin: "https://attacker.example", wantCode: http.StatusNoContent},
		{name: "other routes remain restricted during setup", path: "/v1/settings", host: "attacker.example", origin: "https://attacker.example", wantCode: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := &server{db: db, adminName: test.adminName}
			handler := s.hostOriginGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(http.MethodGet, "https://vault.example.com"+test.path, nil)
			request.Host = test.host
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantCode {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.wantCode, response.Body.String())
			}
		})
	}
}
