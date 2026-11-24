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

func TestPageTemplatesRenderStandalonePages(t *testing.T) {
	tests := []struct {
		name    string
		markers []string
	}{
		{"index.gohtml", []string{"http-equiv=\"refresh\"", "/secret.html"}},
		{"setup.gohtml", []string{`id="setupForm"`, `name="password_confirmation"`, "/v1/setup"}},
		{"login.gohtml", []string{`id="loginForm"`, "/v1/auth/login"}},
		{"secret.gohtml", []string{`id="paths"`, `id="secretPath"`, "async function refresh()"}},
		{"token.gohtml", []string{`id="tokens"`, `id="createToken"`, "async function refreshTokens()"}},
		{"401.gohtml", []string{"401", "Go to login"}},
		{"404.gohtml", []string{"404", "Page not found"}},
		{"lock.gohtml", []string{"423", "Setup locked"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := any(nil)
			if test.name == "index.gohtml" {
				data = map[string]string{"Destination": "/secret.html"}
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
		{"secrets", "admin", true, false, "/secret.html"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := &server{adminName: test.adminName, sessions: map[string]time.Time{}}
			if test.locked {
				s.setupDeadline = time.Now().Add(-time.Second)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.authenticated {
				const token = "session-token"
				s.sessions[token] = time.Now().Add(time.Minute)
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
	s := &server{adminName: "admin", sessions: map[string]time.Time{}}

	login := httptest.NewRecorder()
	s.serveLogin(login, httptest.NewRequest(http.MethodGet, "/login", nil))
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), `id="loginForm"`) {
		t.Fatalf("login page returned status %d or did not contain its form", login.Code)
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
	contents := "VAULT_SERVER_DB_PASSWORD=from-file\nVAULT_SERVER_ADDR=127.0.0.1:8200\n"
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
	if got := os.Getenv("VAULT_SERVER_ADDR"); got != "127.0.0.1:8200" {
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
