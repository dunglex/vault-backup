package main

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	apiTokenLifetime    = 30 * 24 * time.Hour
	maxAPITokenLifetime = 365 * 24 * time.Hour
	setupLifetime       = 20 * time.Minute
	defaultSessionTTL   = 30 * time.Minute
	totpSessionTTL      = 8 * time.Hour
	loginAttemptLimit   = 5
	loginAttemptWindow  = 10 * time.Minute
	shutdownTimeout     = 15 * time.Second
)

type server struct {
	db            *sql.DB
	secretsDB     *sql.DB
	auditStore    *auditStore
	setupKey      string
	setupKeyPath  string
	setupDeadline time.Time
	adminName     string
	aead          cipher.AEAD
	secretsAEAD   cipher.AEAD
	clientCA      *managedClientCA
	serverCerts   *serverCertificateManager
	acmeAvailable bool
	logWriter     *serverLogWriter

	mu             sync.Mutex
	sessions       map[string]sessionInfo
	attempts       map[string][]time.Time
	trustedProxies []*net.IPNet
	loginDelay     func(context.Context) error
}

type sessionInfo struct {
	username           string
	role               string
	expiresAt          time.Time
	ttl                time.Duration
	mustChangePassword bool
}

type accountRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type setupKeyRequest struct {
	SetupKey string `json:"setup_key"`
}

type setupDomainsRequest struct {
	SetupKey        string   `json:"setup_key"`
	MainDomain      string   `json:"main_domain"`
	AliasDomains    []string `json:"alias_domains"`
	CertificateMode string   `json:"certificate_mode"`
}

type setupAdminRequest struct {
	SetupKey             string `json:"setup_key"`
	Username             string `json:"username"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"password_confirmation"`
}

type secretRequest struct {
	Data map[string]any `json:"data"`
}

type httpErrorLogWriter struct {
	output io.Writer
}

func (w httpErrorLogWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("http: TLS handshake error")) &&
		bytes.Contains(p, []byte("tls: unknown certificate")) {
		return len(p), nil
	}
	return w.output.Write(p)
}

//go:embed *.gohtml *.css *.js
var embeddedFiles embed.FS

var pageTemplate = template.Must(template.ParseFS(embeddedFiles, "*.gohtml"))

func main() {
	log.SetOutput(os.Stdout)
	config, err := loadServerConfigFromProcess()
	if errors.Is(err, errHelpRequested) {
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	logWriter := newServerLogWriter(os.Stdout, filepath.Join(filepath.Dir(config.DBPath), "vault-server"))
	log.SetOutput(logWriter)
	defer func() {
		if err := logWriter.DisableFileLogging(); err != nil {
			log.Printf("ERROR: could not close file logging cleanly: %v", err)
		}
	}()
	if config.HTTPAddr != "" {
		log.Printf("WARNING: insecure HTTP listener enabled on %s; traffic is not encrypted", config.HTTPAddr)
	}

	databaseDirs := []string{
		filepath.Dir(config.DBPath),
		filepath.Dir(config.SecretsDBPath),
		filepath.Dir(config.AuditDBPath),
	}
	for _, dir := range databaseDirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatal(err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			log.Fatal(err)
		}
	}

	masterKey, err := loadOrCreateKey(config.DBPath+".key", config.DBPassword)
	if err != nil {
		log.Fatal(err)
	}
	secretsMasterKey, err := loadOrCreateKey(config.SecretsDBPath+".key", config.DBPassword)
	if err != nil {
		log.Fatal(err)
	}

	db, _, err := openDatabaseWithOptions(config.DBPath, masterKey, config.AllowPlaintextDB)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Could not close database cleanly: %v", err)
		}
	}()
	secretsDB, _, err := openDatabaseWithOptions(config.SecretsDBPath, secretsMasterKey, false)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := secretsDB.Close(); err != nil {
			log.Printf("Could not close secrets database cleanly: %v", err)
		}
	}()
	auditStore, err := openAnnualAuditStore(config.AuditDBPath)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := auditStore.Close(); err != nil {
			log.Printf("Could not close audit store cleanly: %v", err)
		}
	}()

	if err := os.Chmod(config.DBPath, 0600); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	if err := initializeDatabase(db); err != nil {
		log.Fatal(err)
	}
	fileLogging, err := readFileLoggingSetting(db)
	if err != nil {
		log.Fatal(err)
	}
	if fileLogging {
		if err := logWriter.EnableFileLogging(); err != nil {
			log.Fatal(err)
		}
	}
	if err := initializeSecretsDatabase(secretsDB); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(config.DBPath, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(config.SecretsDBPath, 0600); err != nil {
		log.Fatal(err)
	}
	serverCerts, err := newServerCertificateManager(
		db,
		config.TLSCertPath,
		config.TLSKeyPath,
		filepath.Join(filepath.Dir(config.DBPath), "acme-cache"),
		config.Addr,
		config.HTTPAddr != "",
	)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(config.DBPath, 0600); err != nil {
		log.Fatal(err)
	}

	var adminName string
	if err := db.QueryRow("SELECT username FROM accounts WHERE role = 'admin' ORDER BY rowid LIMIT 1").Scan(&adminName); err != nil && err != sql.ErrNoRows {
		log.Fatal(err)
	}

	setupKeyPath := config.DBPath + ".setup-key"
	setupKey := ""
	if adminName == "" {
		setupKey = config.SetupKey
		if setupKey == "" {
			var err error
			setupKey, err = loadOrCreateSetupKey(setupKeyPath)
			if err != nil {
				log.Fatal(err)
			}
		}
	} else if err := os.Remove(setupKeyPath); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}
	var setupDeadline time.Time
	if adminName == "" {
		setupDeadline, err = loadOrCreateSetupDeadline(db)
		if err != nil {
			log.Fatal(err)
		}
	}

	aead, err := newDatabaseAEAD(masterKey)
	if err != nil {
		log.Fatal(err)
	}
	secretsAEAD, err := newDatabaseAEAD(secretsMasterKey)
	if err != nil {
		log.Fatal(err)
	}

	// Web server initialization.
	s := &server{
		db:             db,
		secretsDB:      secretsDB,
		auditStore:     auditStore,
		setupKey:       setupKey,
		setupKeyPath:   setupKeyPath,
		setupDeadline:  setupDeadline,
		adminName:      adminName,
		aead:           aead,
		secretsAEAD:    secretsAEAD,
		serverCerts:    serverCerts,
		acmeAvailable:  config.HTTPAddr != "",
		logWriter:      logWriter,
		sessions:       map[string]sessionInfo{},
		attempts:       map[string][]time.Time{},
		trustedProxies: config.TrustedProxyRanges,
	}
	// Load or create the managed client CA for mTLS.
	if err := s.loadOrCreateManagedClientCA(); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)

	// Serve static assets from embedded files.
	mux.HandleFunc("GET /normalize.css", serveEmbeddedAsset("normalize.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /miligram.css", serveEmbeddedAsset("miligram.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /admin.css", serveEmbeddedAsset("admin.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /qrcode.js", serveEmbeddedAsset("qrcode.js", "text/javascript; charset=utf-8"))

	// Serve HTML pages.
	for _, path := range []string{"/setup", "/setup.html"} {
		mux.HandleFunc("GET "+path, s.serveSetup)
	}
	for _, path := range []string{"/lock", "/lock.html"} {
		mux.HandleFunc("GET "+path, s.serveLocked)
	}
	for _, path := range []string{"/login", "/login.html"} {
		mux.HandleFunc("GET "+path, s.serveLogin)
	}
	for _, path := range []string{"/secret", "/secret.html"} {
		mux.HandleFunc("GET "+path, s.serveSecrets)
	}
	for _, path := range []string{"/secrets", "/secrets.html"} {
		mux.HandleFunc("GET "+path, s.serveSecretBrowser)
	}
	for _, path := range []string{"/tokens", "/tokens.html"} {
		mux.HandleFunc("GET "+path, s.serveTokens)
	}
	for _, path := range []string{"/security", "/security.html"} {
		mux.HandleFunc("GET "+path, s.serveSecurity)
	}
	mux.HandleFunc("GET /settings", redirectSecurityPage)
	mux.HandleFunc("GET /settings.html", redirectSecurityPage)
	for _, path := range []string{"/operators", "/operators.html"} {
		mux.HandleFunc("GET "+path, s.serveOperators)
	}
	for _, path := range []string{"/token", "/token.html"} {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/tokens.html", http.StatusMovedPermanently)
		})
	}
	for _, path := range []string{"/audits", "/audits.html"} {
		mux.HandleFunc("GET "+path, s.serveAudit)
	}
	for _, path := range []string{"/account", "/account.html"} {
		mux.HandleFunc("GET "+path, s.serveAccount)
	}
	for _, path := range []string{"/audit", "/audit.html"} {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/audits.html", http.StatusMovedPermanently)
		})
	}
	for _, path := range []string{"/401", "/401.html"} {
		mux.HandleFunc("GET "+path, s.serveUnauthorized)
	}
	for _, path := range []string{"/404", "/404.html"} {
		mux.HandleFunc("GET "+path, s.serveNotFound)
	}

	// Web endpoints: use same-origin cookie sessions.
	mux.HandleFunc("POST /v1/setup/validate-key", s.validateSetupKey)
	mux.HandleFunc("POST /v1/setup/domains", s.saveSetupDomains)
	mux.HandleFunc("POST /v1/setup", s.setup)
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("POST /v1/auth/logout", s.logout)
	mux.HandleFunc("GET /v1/secrets/{path...}", s.getSecret)
	mux.HandleFunc("PUT /v1/secrets/{path...}", s.putSecret)
	mux.HandleFunc("DELETE /v1/secrets/{path...}", s.deleteSecret)
	mux.HandleFunc("GET /v1/secrets", s.listSecrets)
	mux.HandleFunc("GET /v1/secrets-browser", s.browseSecrets)
	mux.HandleFunc("GET /v1/session", s.webSession)
	mux.HandleFunc("POST /v1/tokens", s.createAPIToken)
	mux.HandleFunc("GET /v1/tokens", s.listAPITokens)
	mux.HandleFunc("DELETE /v1/tokens/{id}", s.revokeAPIToken)
	mux.HandleFunc("POST /v1/tokens/{id}/certificate", s.issueAPITokenCertificate)
	mux.HandleFunc("GET /v1/settings", s.getSettings)
	mux.HandleFunc("PUT /v1/settings", s.updateSettings)
	mux.HandleFunc("GET /v1/settings/blocked-login-ips", s.listBlockedLoginIPs)
	mux.HandleFunc("DELETE /v1/settings/blocked-login-ips/{ip}", s.unblockLoginIP)
	mux.HandleFunc("GET /v1/operators", s.listOperators)
	mux.HandleFunc("GET /v1/operators/details", s.listOperatorDetails)
	mux.HandleFunc("POST /v1/operators", s.createOperator)
	mux.HandleFunc("DELETE /v1/operators", s.deleteOperator)
	mux.HandleFunc("PATCH /v1/operators/lock", s.setOperatorLock)
	mux.HandleFunc("DELETE /v1/operators/totp", s.removeOperatorTOTP)
	mux.HandleFunc("GET /v1/account/totp", s.getAccountTOTP)
	mux.HandleFunc("POST /v1/account/totp/setup", s.setupAccountTOTP)
	mux.HandleFunc("POST /v1/account/totp/enable", s.enableAccountTOTP)
	mux.HandleFunc("POST /v1/account/totp/recovery-codes", s.regenerateAccountRecoveryCodes)
	mux.HandleFunc("DELETE /v1/account/totp", s.disableAccountTOTP)
	mux.HandleFunc("POST /v1/account/password", s.changeAccountPassword)
	mux.HandleFunc("GET /v1/audit/years", s.listAuditYears)
	mux.HandleFunc("GET /v1/audit", s.listAuditEvents)

	// API endpoints: require bearer/X-Vault-Token authentication.
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("POST /api/v1/auth/ldap/login/{username}", s.loginLDAP)
	mux.HandleFunc("PUT /api/v1/auth/ldap/login/{username}", s.loginLDAP)
	mux.HandleFunc("GET /api/v1/{mount}/data/{path...}", s.getKVSecret)
	mux.HandleFunc("PUT /api/v1/{mount}/data/{path...}", s.putKVSecret)
	mux.HandleFunc("DELETE /api/v1/{mount}/data/{path...}", s.deleteKVSecret)
	mux.HandleFunc("LIST /api/v1/{mount}/metadata/{path...}", s.listKVMetadata)

	mux.HandleFunc("/", s.serveHome)

	handler := withAccessLogging(s.middleware(mux), logWriter)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.VerifyClientCertIfGiven,
	}
	serverCerts.configureTLS(tlsConfig)
	clientCAs := x509.NewCertPool()
	if strings.TrimSpace(config.MTLSCACertPath) != "" {
		clientCAs = config.MTLSCAPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		log.Printf("Vault server HTTPS mutual TLS enabled using client CA %s", config.MTLSCACertPath)
	}
	clientCAs.AddCert(s.clientCA.certificate)
	tlsConfig.ClientCAs = clientCAs
	httpErrorLog := log.New(httpErrorLogWriter{output: logWriter}, "", log.LstdFlags)
	httpsServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         tlsConfig,
		ErrorLog:          httpErrorLog,
	}
	httpServer := &http.Server{
		Handler:           serverCerts.HTTPHandler(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          httpErrorLog,
	}
	httpsListener, err := net.Listen("tcp", config.Addr)
	if err != nil {
		log.Fatal(err)
	}
	var httpListener net.Listener
	if config.HTTPAddr != "" {
		httpListener, err = net.Listen("tcp", config.HTTPAddr)
		if err != nil {
			_ = httpsListener.Close()
			log.Fatal(err)
		}
	}

	if setupKey != "" {
		fmt.Printf("Vault setup key: %s\n", setupKey)
	}
	log.Printf("Vault server listening on %s (app DB: %s; secrets DB: %s; audit: %s)", config.Addr, config.DBPath, config.SecretsDBPath, config.AuditDBPath)
	log.Printf("Vault server serving HTTPS on %s", config.Addr)
	if httpListener != nil {
		log.Printf("Vault server serving HTTP on %s", config.HTTPAddr)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	errs := make(chan error, 2)
	go func() { errs <- httpsServer.ServeTLS(httpsListener, "", "") }()
	if httpListener != nil {
		go func() { errs <- httpServer.Serve(httpListener) }()
	}

	select {
	case sig := <-signals:
		log.Printf("Shutdown signal %s received", sig)
		servers := []*http.Server{httpsServer}
		if httpListener != nil {
			servers = append(servers, httpServer)
		}
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := shutdownServers(ctx, servers); err != nil {
			log.Printf("Graceful shutdown incomplete: %v", err)
		}
		<-errs
		if httpListener != nil {
			<-errs
		}
		log.Printf("Vault server shut down")
	case err := <-errs:
		servers := []*http.Server{httpsServer}
		if httpListener != nil {
			servers = append(servers, httpServer)
		}
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		shutdownErr := shutdownServers(ctx, servers)
		cancel()
		if shutdownErr != nil {
			log.Printf("Server cleanup failed: %v", shutdownErr)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("Vault server stopped unexpectedly: %v", err)
		}
	}
}

func shutdownServers(ctx context.Context, servers []*http.Server) error {
	results := make(chan error, len(servers))
	for _, server := range servers {
		go func(server *http.Server) {
			if err := server.Shutdown(ctx); err != nil {
				if closeErr := server.Close(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
					results <- errors.Join(err, closeErr)
					return
				}
				results <- err
				return
			}
			results <- nil
		}(server)
	}
	var failures []error
	for range servers {
		if err := <-results; err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *server) encrypt(plaintext []byte) (string, error) {
	return encryptWithAEAD(s.aead, plaintext)
}

func (s *server) decrypt(encoded string) ([]byte, error) {
	return decryptWithAEAD(s.aead, encoded)
}

func (s *server) encryptSecret(plaintext []byte) (string, error) {
	return encryptWithAEAD(s.secretsAEAD, plaintext)
}

func (s *server) decryptSecret(encoded string) ([]byte, error) {
	return decryptWithAEAD(s.secretsAEAD, encoded)
}

func encryptWithAEAD(aead cipher.AEAD, plaintext []byte) (string, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func decryptWithAEAD(aead cipher.AEAD, encoded string) ([]byte, error) {
	sealed, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func serveEmbeddedAsset(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := embeddedFiles.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	}
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	checks := []func(context.Context) error{
		func(ctx context.Context) error {
			return checkDatabaseHealth(ctx, s.db)
		},
		func(ctx context.Context) error {
			return checkDatabaseHealth(ctx, s.secretsDB)
		},
		func(ctx context.Context) error {
			if s.auditStore == nil {
				return errors.New("audit database unavailable")
			}
			return s.auditStore.withYear(time.Now().UTC().Year(), func(db *sql.DB) error {
				return checkDatabaseHealth(ctx, db)
			})
		},
	}
	results := make(chan error, len(checks))
	for _, check := range checks {
		go func(check func(context.Context) error) {
			results <- check(ctx)
		}(check)
	}
	healthy := true
	for range checks {
		if err := <-results; err != nil {
			healthy = false
		}
	}
	if !healthy {
		writeJSON(w, http.StatusServiceUnavailable, map[string]bool{"ok": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func checkDatabaseHealth(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("database unavailable")
	}
	var result int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&result); err != nil {
		return err
	}
	if result != 1 {
		return errors.New("database health query returned an unexpected result")
	}
	return nil
}

func (s *server) setupAvailable(w http.ResponseWriter) bool {
	if s.adminName != "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account already configured"})
		return false
	}
	if s.setupLocked() {
		writeJSON(w, http.StatusLocked, map[string]string{"error": "setup window expired"})
		return false
	}
	return true
}

func (s *server) setupKeyValid(w http.ResponseWriter, key string) bool {
	if subtle.ConstantTimeCompare([]byte(key), []byte(s.setupKey)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid setup key"})
		return false
	}
	return true
}

func (s *server) validateSetupKey(w http.ResponseWriter, r *http.Request) {
	if !s.setupAvailable(w) {
		return
	}
	var req setupKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if !s.setupKeyValid(w, req.SetupKey) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}

func (s *server) saveSetupDomains(w http.ResponseWriter, r *http.Request) {
	if !s.setupAvailable(w) {
		return
	}
	var req setupDomainsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if !s.setupKeyValid(w, req.SetupKey) {
		return
	}
	mainDomain, aliasDomains, domains, err := normalizeServerDomains(req.MainDomain, req.AliasDomains)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	certificateMode := strings.TrimSpace(req.CertificateMode)
	if certificateMode == "" {
		certificateMode = serverCertificateModeSelfSigned
	}
	if certificateMode != serverCertificateModeSelfSigned && certificateMode != serverCertificateModeACME {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported server certificate mode"})
		return
	}
	if certificateMode == serverCertificateModeACME {
		if !s.acmeAvailable || s.serverCerts == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ACME certificates require the HTTP listener"})
			return
		}
		if err := s.serverCerts.prepareACME(domains); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
	} else if s.serverCerts != nil {
		if err := s.serverCerts.prepareSelfSigned(domains); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate server certificate"})
			return
		}
	}
	aliasesJSON, err := json.Marshal(aliasDomains)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save server domains"})
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save server domains"})
		return
	}
	defer tx.Rollback()
	settings := map[string]string{
		serverSettingMainDomain:      mainDomain,
		serverSettingAliasDomains:    string(aliasesJSON),
		serverSettingCertificateMode: certificateMode,
	}
	for key, value := range settings {
		if _, err := tx.Exec(
			"INSERT INTO server_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			key, value,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save server domains"})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save server domains"})
		return
	}
	if s.serverCerts != nil {
		s.serverCerts.configure(certificateMode, domains)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"saved": true})
}

func (s *server) setup(w http.ResponseWriter, r *http.Request) {
	if !s.setupAvailable(w) {
		return
	}
	var req setupAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if !s.setupKeyValid(w, req.SetupKey) {
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(req.PasswordConfirmation)) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passwords do not match"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Username) > 128 || len(req.Password) < 12 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username required and password must be at least 12 characters"})
		return
	}
	loginURL, err := s.setupLoginURL(r)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not prepare login redirect"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create account"})
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create account"})
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO accounts(username, password_hash, role) VALUES (?, ?, 'admin')", req.Username, string(hash)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create account"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create account"})
		return
	}
	s.adminName = req.Username
	s.setupKey = ""
	if err := os.Remove(s.setupKeyPath); err != nil && !os.IsNotExist(err) {
		log.Printf("WARNING: could not remove setup key file %s: %v", s.setupKeyPath, err)
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"username":     req.Username,
		"redirect_url": loginURL,
	})
}

func (s *server) setupLoginURL(r *http.Request) (string, error) {
	mainDomain, err := readServerSetting(s.db, serverSettingMainDomain)
	if err != nil {
		return "", err
	}
	if mainDomain == "" {
		return "/login.html", nil
	}

	mode, err := readServerSetting(s.db, serverSettingCertificateMode)
	if err != nil {
		return "", err
	}
	scheme := "http"
	switch mode {
	case serverCertificateModeSelfSigned, serverCertificateModeACME:
		scheme = "https"
	case "":
		if s.requestIsHTTPS(r) {
			scheme = "https"
		}
	default:
		return "", fmt.Errorf("unsupported server certificate mode %q", mode)
	}

	mainDomain, _, _, err = normalizeServerDomains(mainDomain, nil)
	if err != nil {
		return "", fmt.Errorf("invalid configured main domain: %w", err)
	}

	host := mainDomain
	if ip := net.ParseIP(mainDomain); ip != nil && strings.Contains(mainDomain, ":") {
		host = "[" + mainDomain + "]"
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: "/login.html"}).String(), nil
}

func (s *server) requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peerIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peerIP = net.ParseIP(host)
	}
	if peerIP == nil || !ipInRanges(peerIP, s.trustedProxies) {
		return false
	}
	forwardedProto := strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")
	if len(forwardedProto) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(forwardedProto[len(forwardedProto)-1]), "https")
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if s.rejectBlockedLoginIP(w, r, "web") {
		return
	}
	var req accountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.recordLoginFailure(r, "web")
		s.recordAuditEvent(r, "login", "failure", "unknown", "web", "", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	if !s.allowLoginAttempt(r, req.Username) {
		s.recordAuditEvent(r, "login", "failure", req.Username, "web", "", "rate_limited")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts"})
		return
	}
	if s.delayLoginAction(w, r) {
		return
	}

	var hash, role string
	var totpSecret sql.NullString
	var totpEnabled, locked, mustChangePassword int
	if err := s.db.QueryRow(
		"SELECT password_hash, role, totp_secret, totp_enabled, locked, must_change_password FROM accounts WHERE username = ?",
		req.Username,
	).Scan(&hash, &role, &totpSecret, &totpEnabled, &locked, &mustChangePassword); err != nil {
		s.recordLoginFailure(r, "web")
		s.recordAuditEvent(r, "login", "failure", req.Username, "web", "", "invalid_credentials")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		s.recordLoginFailure(r, "web")
		s.recordAuditEvent(r, "login", "failure", req.Username, "web", "", "invalid_credentials")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	if locked == 1 {
		s.recordAuditEvent(r, "login", "failure", req.Username, "web", "", "account_locked")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account is locked"})
		return
	}
	enforceMFA, err := s.mfaEnforcementEnabled()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read MFA settings"})
		return
	}
	mfaSetupRequired := enforceMFA && totpEnabled != 1
	if totpEnabled == 1 {
		if r.TLS == nil {
			writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required for two-factor login"})
			return
		}
		if req.TOTPCode == "" {
			s.recordAuditEvent(r, "login", "challenge", req.Username, "web", "", "totp_required")
			writeJSON(w, http.StatusOK, map[string]bool{"requires_totp": true})
			return
		}
		valid, err := s.verifyAccountSecondFactor(req.Username, totpSecret.String, req.TOTPCode)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify authentication code"})
			return
		}
		if !valid {
			s.recordLoginFailure(r, "web")
			s.recordAuditEvent(r, "login", "failure", req.Username, "web", "", "invalid_second_factor")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username, password, or authentication code"})
			return
		}
	}

	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create session"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	sessionTTL := defaultSessionTTL
	if totpEnabled == 1 {
		sessionTTL = totpSessionTTL
	}
	session := sessionInfo{
		username:           req.Username,
		role:               role,
		expiresAt:          time.Now().Add(sessionTTL),
		ttl:                sessionTTL,
		mustChangePassword: mustChangePassword == 1,
	}
	if err := s.storeSession(token, session); err != nil {
		s.recordAuditEvent(r, "login", "failure", req.Username, "web", "", "session_storage_error")
		log.Printf("ERROR: could not store web session: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create session"})
		return
	}
	if !mfaSetupRequired {
		s.resetLoginFailuresAfterSuccess(r)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "vault_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	if mfaSetupRequired {
		s.recordAuditEvent(r, "login", "challenge", req.Username, "web", "", "mfa_setup_required")
		writeJSON(w, http.StatusOK, map[string]any{
			"token":                token,
			"requires_mfa_setup":   true,
			"must_change_password": mustChangePassword == 1,
		})
		return
	}
	if mustChangePassword == 1 {
		s.recordAuditEvent(r, "login", "challenge", req.Username, "web", "", "password_change_required")
		writeJSON(w, http.StatusOK, map[string]any{
			"token":                token,
			"must_change_password": true,
		})
		return
	}
	s.recordAuditEvent(r, "login", "success", req.Username, "web", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *server) loginLDAP(w http.ResponseWriter, r *http.Request) {
	if s.rejectBlockedLoginIP(w, r, "api") {
		return
	}
	username := r.PathValue("username")
	var req accountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.recordLoginFailure(r, "api")
		s.recordAuditEvent(r, "login", "failure", username, "api", "", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if !s.allowLoginAttempt(r, username) {
		s.recordAuditEvent(r, "login", "failure", username, "api", "", "rate_limited")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts"})
		return
	}
	if s.delayLoginAction(w, r) {
		return
	}
	var hash, role string
	var totpSecret sql.NullString
	var totpEnabled, locked, mustChangePassword int
	if err := s.db.QueryRow(
		"SELECT password_hash, role, totp_secret, totp_enabled, locked, must_change_password FROM accounts WHERE username = ?",
		username,
	).Scan(&hash, &role, &totpSecret, &totpEnabled, &locked, &mustChangePassword); err != nil {
		s.recordLoginFailure(r, "api")
		s.recordAuditEvent(r, "login", "failure", username, "api", "", "invalid_credentials")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		s.recordLoginFailure(r, "api")
		s.recordAuditEvent(r, "login", "failure", username, "api", "", "invalid_credentials")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	if locked == 1 {
		s.recordAuditEvent(r, "login", "failure", username, "api", "", "account_locked")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account is locked"})
		return
	}
	if mustChangePassword == 1 {
		s.recordAuditEvent(r, "login", "challenge", username, "api", "", "password_change_required")
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":                "password change is required through web login",
			"must_change_password": true,
		})
		return
	}
	enforceMFA, err := s.mfaEnforcementEnabled()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read MFA settings"})
		return
	}
	if enforceMFA && totpEnabled != 1 {
		s.recordAuditEvent(r, "login", "challenge", username, "api", "", "mfa_setup_required")
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":              "MFA setup is required through web login",
			"requires_mfa_setup": true,
		})
		return
	}
	if totpEnabled == 1 {
		if r.TLS == nil {
			writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required for two-factor login"})
			return
		}
		if req.TOTPCode == "" {
			s.recordLoginFailure(r, "api")
			s.recordAuditEvent(r, "login", "failure", username, "api", "", "totp_required")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication code required"})
			return
		}
		valid, err := s.verifyAccountSecondFactor(username, totpSecret.String, req.TOTPCode)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify authentication code"})
			return
		}
		if !valid {
			s.recordLoginFailure(r, "api")
			s.recordAuditEvent(r, "login", "failure", username, "api", "", "invalid_second_factor")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username, password, or authentication code"})
			return
		}
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create session"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	session := sessionInfo{
		username:  username,
		role:      role,
		expiresAt: time.Now().Add(defaultSessionTTL),
		ttl:       defaultSessionTTL,
	}
	if err := s.storeSession(token, session); err != nil {
		s.recordAuditEvent(r, "login", "failure", username, "api", "", "session_storage_error")
		log.Printf("ERROR: could not store LDAP login session: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create session"})
		return
	}
	s.resetLoginFailuresAfterSuccess(r)
	s.recordAuditEvent(r, "login", "success", username, "api", "", "")
	writeJSON(w, http.StatusOK, map[string]any{"auth": map[string]any{"client_token": token}})
}

func (s *server) recordAuditEvent(r *http.Request, action, outcome, actor, source, resource, detail string) {
	if s.auditStore == nil {
		return
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "unknown"
	}
	if len(actor) > 128 {
		actor = actor[:128]
	}
	if len(resource) > 1024 {
		resource = resource[:1024]
	}
	if len(detail) > 1024 {
		detail = detail[:1024]
	}
	err := s.auditStore.Record(time.Now().UTC().Unix(), action, outcome, actor, s.clientIP(r), source, resource, detail)
	if err != nil {
		log.Printf("WARNING: could not write audit event %s/%s: %v", action, outcome, err)
	}
}

func (s *server) auditRequestActor(r *http.Request, source string) string {
	if source == "web" {
		if cookie, err := r.Cookie("vault_session"); err == nil {
			s.mu.Lock()
			session, ok := s.sessions[cookie.Value]
			s.mu.Unlock()
			if ok {
				return session.username
			}
		}
		if session, ok := s.sessionFromRequest(r); ok {
			return session.username
		}
		return "anonymous"
	}
	token := r.Header.Get("X-Vault-Token")
	if token == "" {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if token == "" {
		return "anonymous"
	}
	sum := sha256.Sum256([]byte(token))
	return "api-token:" + hex.EncodeToString(sum[:6])
}

func (s *server) allowLoginAttempt(r *http.Request, username string) bool {
	now := time.Now()
	username = strings.ToLower(strings.TrimSpace(username))
	keys := []string{"ip:" + s.clientIP(r)}
	if username != "" {
		keys = append(keys, "account:"+username)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-loginAttemptWindow)
	for key, attempts := range s.attempts {
		recent := attempts[:0]
		for _, attempt := range attempts {
			if attempt.After(cutoff) {
				recent = append(recent, attempt)
			}
		}
		if len(recent) == 0 {
			delete(s.attempts, key)
		} else {
			s.attempts[key] = recent
		}
	}
	for _, key := range keys {
		if len(s.attempts[key]) >= loginAttemptLimit {
			return false
		}
	}
	for _, key := range keys {
		s.attempts[key] = append(s.attempts[key], now)
	}
	return true
}

func (s *server) clientIP(r *http.Request) string {
	peerIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peerIP = net.ParseIP(host)
	}
	if peerIP == nil {
		return r.RemoteAddr
	}
	if !ipInRanges(peerIP, s.trustedProxies) {
		return peerIP.String()
	}

	chain := make([]net.IP, 0)
	for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		if ip := net.ParseIP(strings.TrimSpace(part)); ip != nil {
			chain = append(chain, ip)
		}
	}
	chain = append(chain, peerIP)
	for i := len(chain) - 1; i >= 0; i-- {
		if !ipInRanges(chain[i], s.trustedProxies) {
			return chain[i].String()
		}
	}
	return peerIP.String()
}

func ipInRanges(ip net.IP, ranges []*net.IPNet) bool {
	for _, network := range ranges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *server) authorizedWeb(r *http.Request) bool {
	_, ok := s.sessionFromRequest(r)
	return ok
}

func (s *server) sessionFromRequest(r *http.Request) (sessionInfo, bool) {
	cookie, err := r.Cookie("vault_session")
	if err != nil {
		return sessionInfo{}, false
	}
	return s.sessionForToken(cookie.Value)
}

func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	session, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return false
	}
	if session.role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrator access required"})
		return false
	}
	return true
}

func (s *server) authorizedAPI(r *http.Request) bool {
	token := apiTokenFromRequest(r)
	var tokenID int64
	if err := s.lookupActiveAPIToken(token, &tokenID); err != nil {
		return false
	}
	enforced, err := s.mtlsSettings()
	if err != nil {
		return false
	}
	if !enforced {
		return true
	}
	certTokenID, ok := s.certificateTokenID(r)
	return ok && certTokenID == tokenID
}

func (s *server) authorizedToken(token string) bool {
	_, ok := s.sessionForToken(token)
	return ok
}

func (s *server) authorizedAPIToken(token string) bool {
	var tokenID int64
	return s.lookupActiveAPIToken(token, &tokenID) == nil
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	token := ""
	if cookie, err := r.Cookie("vault_session"); err == nil {
		token = cookie.Value
	}
	http.SetCookie(w, &http.Cookie{Name: "vault_session", Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	if err := s.deleteSession(token); err != nil {
		log.Printf("ERROR: could not complete logout: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not complete logout"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		s.recordAuditEvent(r, "create_token", "failure", "anonymous", "web", "api-token", "unauthorized")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to create tokens and client credentials"})
		return
	}
	var req struct {
		Name          string `json:"name"`
		ExpiresInDays *int   `json:"expires_in_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 128 {
		s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "invalid_name")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required and must be at most 128 characters"})
		return
	}
	lifetime := apiTokenLifetime
	if req.ExpiresInDays != nil {
		maxDays := int(maxAPITokenLifetime / (24 * time.Hour))
		if *req.ExpiresInDays < 1 || *req.ExpiresInDays > maxDays {
			s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "invalid_expiration")
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "expires_in_days must be between 1 and 365",
			})
			return
		}
		lifetime = time.Duration(*req.ExpiresInDays) * 24 * time.Hour
	}

	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "random_generation_failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create API token"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256([]byte(token))
	createdAt := time.Now().UTC().Truncate(time.Second)
	expiresAt := createdAt.Add(lifetime)
	tx, err := s.db.Begin()
	if err != nil {
		s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create API token"})
		return
	}
	defer tx.Rollback()

	// Check if mTLS enforcement is enabled in the server settings
	var mtlsSetting string
	if err := tx.QueryRow("SELECT value FROM server_settings WHERE key = 'enforce_mtls'").Scan(&mtlsSetting); err != nil && err != sql.ErrNoRows {
		s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "settings_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read mTLS settings"})
		return
	}
	enforceMTLS := mtlsSetting == "true"
	var nameExists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM api_tokens WHERE name = ?)", req.Name).Scan(&nameExists); err != nil {
		s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not check API token name"})
		return
	}
	if nameExists {
		s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "duplicate_name")
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an API token with this name already exists"})
		return
	}
	result, err := tx.Exec(
		"INSERT INTO api_tokens(name, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
		req.Name,
		hex.EncodeToString(tokenHash[:]),
		createdAt.Unix(),
		expiresAt.Unix(),
	)
	if err != nil {
		s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create API token"})
		return
	}
	id, err := result.LastInsertId()
	if err != nil {
		s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create API token"})
		return
	}
	var issued issuedClientCertificate
	if enforceMTLS {
		issued, err = s.issueClientCertificate(id, expiresAt)
		if err != nil {
			s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "certificate_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not issue client certificate"})
			return
		}
		if err := s.saveClientCertificate(tx, id, issued); err != nil {
			s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "certificate_storage_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save client certificate"})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		s.recordAuditEvent(r, "create_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create API token"})
		return
	}
	s.recordAuditEvent(r, "create_token", "success", s.auditRequestActor(r, "web"), "web", "api-token:"+strconv.FormatInt(id, 10), "")
	response := map[string]any{
		"id":         id,
		"name":       req.Name,
		"token":      token,
		"created_at": createdAt.UTC().Format(time.RFC3339),
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	}
	if enforceMTLS {
		response["client_certificate"] = issued.Certificate
		response["client_private_key"] = issued.PrivateKey
		response["client_certificate_expires_at"] = issued.ExpiresAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusCreated, response)
}

func (s *server) listAPITokens(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	rows, err := s.db.Query(`
		SELECT tokens.id, tokens.name, tokens.created_at, tokens.expires_at, tokens.revoked_at,
		       MAX(certificates.not_after)
		FROM api_tokens AS tokens
		LEFT JOIN managed_client_certificates AS certificates
		  ON certificates.token_id = tokens.id AND certificates.revoked_at IS NULL
		GROUP BY tokens.id, tokens.name, tokens.created_at, tokens.expires_at, tokens.revoked_at
		ORDER BY tokens.created_at DESC, tokens.id DESC`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list API tokens"})
		return
	}
	defer rows.Close()

	tokens := make([]map[string]any, 0)
	for rows.Next() {
		var id, createdAt, expiresAt int64
		var revokedAt, certificateExpiresAt sql.NullInt64
		var name string
		if err := rows.Scan(&id, &name, &createdAt, &expiresAt, &revokedAt, &certificateExpiresAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read API tokens"})
			return
		}
		item := map[string]any{
			"id":              id,
			"name":            name,
			"created_at":      time.Unix(createdAt, 0).UTC().Format(time.RFC3339),
			"expires_at":      time.Unix(expiresAt, 0).UTC().Format(time.RFC3339),
			"expired":         expiresAt < time.Now().Unix(),
			"revoked":         revokedAt.Valid,
			"has_certificate": certificateExpiresAt.Valid && certificateExpiresAt.Int64 > time.Now().Unix(),
		}
		if certificateExpiresAt.Valid {
			item["certificate_expires_at"] = time.Unix(certificateExpiresAt.Int64, 0).UTC().Format(time.RFC3339)
		}
		tokens = append(tokens, item)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list API tokens"})
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *server) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		s.recordAuditEvent(r, "revoke_token", "failure", "anonymous", "web", "api-token", "unauthorized")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		s.recordAuditEvent(r, "revoke_token", "failure", s.auditRequestActor(r, "web"), "web", "api-token", "invalid_token_id")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token id"})
		return
	}
	resource := "api-token:" + strconv.FormatInt(id, 10)
	tx, err := s.db.Begin()
	if err != nil {
		s.recordAuditEvent(r, "revoke_token", "failure", s.auditRequestActor(r, "web"), "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke API token"})
		return
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	result, err := tx.Exec("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", now, id)
	if err != nil {
		s.recordAuditEvent(r, "revoke_token", "failure", s.auditRequestActor(r, "web"), "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke API token"})
		return
	}
	if _, err := tx.Exec(
		"UPDATE managed_client_certificates SET revoked_at = ? WHERE token_id = ? AND revoked_at IS NULL",
		now, id,
	); err != nil {
		s.recordAuditEvent(r, "revoke_token", "failure", s.auditRequestActor(r, "web"), "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke API token"})
		return
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		s.recordAuditEvent(r, "revoke_token", "failure", s.auditRequestActor(r, "web"), "web", resource, "active_token_not_found")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "active API token not found"})
		return
	}
	if err := tx.Commit(); err != nil {
		s.recordAuditEvent(r, "revoke_token", "failure", s.auditRequestActor(r, "web"), "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke API token"})
		return
	}
	s.recordAuditEvent(r, "revoke_token", "success", s.auditRequestActor(r, "web"), "web", resource, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *server) getKVSecret(w http.ResponseWriter, r *http.Request) {
	source, path := "api", r.PathValue("mount")+"/"+r.PathValue("path")
	if !validSecretPath(path) {
		s.recordAuditEvent(r, "read", "failure", s.auditRequestActor(r, source), source, path, "invalid_secret_path")
		writeInvalidSecretPath(w)
		return
	}
	if !s.kvAuthorized(r) {
		s.recordAuditEvent(r, "read", "failure", s.auditRequestActor(r, source), source, path, "unauthorized")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var encrypted string
	if err := s.secretsDB.QueryRow("SELECT data FROM secrets WHERE path = ?", path).Scan(&encrypted); err != nil {
		s.recordAuditEvent(r, "read", "failure", s.auditRequestActor(r, source), source, path, "not_found")
		writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{"secret not found"}})
		return
	}
	plaintext, err := s.decryptSecret(encrypted)
	if err != nil {
		s.recordAuditEvent(r, "read", "failure", s.auditRequestActor(r, source), source, path, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid stored secret"})
		return
	}
	var data map[string]any
	if err := json.Unmarshal(plaintext, &data); err != nil {
		s.recordAuditEvent(r, "read", "failure", s.auditRequestActor(r, source), source, path, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid stored secret"})
		return
	}
	s.recordAuditEvent(r, "read", "success", s.auditRequestActor(r, source), source, path, "")
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"data": data}})
}

func (s *server) putKVSecret(w http.ResponseWriter, r *http.Request) {
	source, path := "api", r.PathValue("mount")+"/"+r.PathValue("path")
	if !validSecretPath(path) {
		s.recordAuditEvent(r, "update", "failure", s.auditRequestActor(r, source), source, path, "invalid_secret_path")
		writeInvalidSecretPath(w)
		return
	}
	if !s.kvAuthorized(r) {
		s.recordAuditEvent(r, "update", "failure", s.auditRequestActor(r, source), source, path, "unauthorized")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	action := "create"
	var exists int
	if err := s.secretsDB.QueryRow("SELECT 1 FROM secrets WHERE path = ?", path).Scan(&exists); err == nil {
		action = "update"
	} else if err != sql.ErrNoRows {
		s.recordAuditEvent(r, action, "failure", s.auditRequestActor(r, source), source, path, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store secret"})
		return
	}
	var req struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Data == nil {
		s.recordAuditEvent(r, action, "failure", s.auditRequestActor(r, source), source, path, "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid secret data"})
		return
	}
	plaintext, err := json.Marshal(req.Data)
	if err != nil {
		s.recordAuditEvent(r, action, "failure", s.auditRequestActor(r, source), source, path, "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid secret data"})
		return
	}
	encrypted, err := s.encryptSecret(plaintext)
	if err != nil {
		s.recordAuditEvent(r, action, "failure", s.auditRequestActor(r, source), source, path, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store secret"})
		return
	}
	if _, err := s.secretsDB.Exec(`INSERT INTO secrets(path, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(path) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`, path, encrypted); err != nil {
		s.recordAuditEvent(r, action, "failure", s.auditRequestActor(r, source), source, path, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store secret"})
		return
	}
	s.recordAuditEvent(r, action, "success", s.auditRequestActor(r, source), source, path, "")
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"version": 1}})
}

func (s *server) deleteKVSecret(w http.ResponseWriter, r *http.Request) {
	source, path := "api", r.PathValue("mount")+"/"+r.PathValue("path")
	if !validSecretPath(path) {
		s.recordAuditEvent(r, "delete", "failure", s.auditRequestActor(r, source), source, path, "invalid_secret_path")
		writeInvalidSecretPath(w)
		return
	}
	if !s.kvAuthorized(r) {
		s.recordAuditEvent(r, "delete", "failure", s.auditRequestActor(r, source), source, path, "unauthorized")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if _, err := s.secretsDB.Exec("DELETE FROM secrets WHERE path = ?", path); err != nil {
		s.recordAuditEvent(r, "delete", "failure", s.auditRequestActor(r, source), source, path, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not delete secret"})
		return
	}
	s.recordAuditEvent(r, "delete", "success", s.auditRequestActor(r, source), source, path, "")
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *server) listKVMetadata(w http.ResponseWriter, r *http.Request) {
	source := "api"
	path := r.PathValue("mount") + "/" + r.PathValue("path")
	if !validSecretPath(path) {
		s.recordAuditEvent(r, "list", "failure", s.auditRequestActor(r, source), source, path, "invalid_secret_path")
		writeInvalidSecretPath(w)
		return
	}
	if !s.kvAuthorized(r) {
		s.recordAuditEvent(r, "list", "failure", s.auditRequestActor(r, source), source, r.PathValue("mount")+"/"+r.PathValue("path"), "unauthorized")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	prefix := r.PathValue("mount") + "/"
	secretPrefix := r.PathValue("path")
	if secretPrefix != "" {
		prefix += strings.Trim(secretPrefix, "/") + "/"
	}
	rows, err := s.secretsDB.Query("SELECT path FROM secrets WHERE path LIKE ? ORDER BY path", prefix+"%")
	if err != nil {
		s.recordAuditEvent(r, "list", "failure", s.auditRequestActor(r, source), source, r.PathValue("mount")+"/"+r.PathValue("path"), "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secrets"})
		return
	}
	defer rows.Close()
	keys := []string{}
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			s.recordAuditEvent(r, "list", "failure", s.auditRequestActor(r, source), source, r.PathValue("mount")+"/"+r.PathValue("path"), "storage_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read secrets"})
			return
		}
		path = strings.TrimPrefix(path, prefix)
		if path != "" && !strings.Contains(path, "/") {
			keys = append(keys, path)
		}
	}
	if err := rows.Err(); err != nil {
		s.recordAuditEvent(r, "list", "failure", s.auditRequestActor(r, source), source, r.PathValue("mount")+"/"+r.PathValue("path"), "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secrets"})
		return
	}
	s.recordAuditEvent(r, "list", "success", s.auditRequestActor(r, source), source, r.PathValue("mount")+"/"+r.PathValue("path"), "")
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"keys": keys}})
}

func (s *server) getSecret(w http.ResponseWriter, r *http.Request) {
	source, path := "web", r.PathValue("path")
	if !validSecretPath(path) {
		writeInvalidSecretPath(w)
		return
	}
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var encrypted string
	if err := s.secretsDB.QueryRow("SELECT data FROM secrets WHERE path = ?", path).Scan(&encrypted); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "secret not found"})
		return
	}
	plaintext, err := s.decryptSecret(encrypted)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid stored secret"})
		return
	}
	var data map[string]any
	if err := json.Unmarshal(plaintext, &data); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid stored secret"})
		return
	}
	s.recordAuditEvent(r, "read", "success", s.auditRequestActor(r, source), source, path, "")
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

func (s *server) putSecret(w http.ResponseWriter, r *http.Request) {
	source, path := "web", r.PathValue("path")
	if !validSecretPath(path) {
		writeInvalidSecretPath(w)
		return
	}
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	action := "create"
	var exists int
	if err := s.secretsDB.QueryRow("SELECT 1 FROM secrets WHERE path = ?", path).Scan(&exists); err == nil {
		action = "update"
	} else if err != sql.ErrNoRows {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store secret"})
		return
	}
	var req secretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Data == nil {
		s.recordAuditEvent(r, action, "failure", s.auditRequestActor(r, source), source, path, "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid secret data"})
		return
	}
	plaintext, err := json.Marshal(req.Data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid secret data"})
		return
	}
	encrypted, err := s.encryptSecret(plaintext)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store secret"})
		return
	}
	if _, err := s.secretsDB.Exec(`INSERT INTO secrets(path, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(path) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`, path, encrypted); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store secret"})
		return
	}
	s.recordAuditEvent(r, action, "success", s.auditRequestActor(r, source), source, path, "")
	writeJSON(w, http.StatusOK, map[string]string{"path": path})
}

func (s *server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	source, path := "web", r.PathValue("path")
	if !validSecretPath(path) {
		writeInvalidSecretPath(w)
		return
	}
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if _, err := s.secretsDB.Exec("DELETE FROM secrets WHERE path = ?", path); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not delete secret"})
		return
	}
	s.recordAuditEvent(r, "delete", "success", s.auditRequestActor(r, source), source, path, "")
	writeJSON(w, http.StatusOK, map[string]string{"path": path})
}

func (s *server) listSecrets(w http.ResponseWriter, r *http.Request) {
	source := "web"
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	rows, err := s.secretsDB.Query("SELECT path FROM secrets ORDER BY path")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secrets"})
		return
	}
	defer rows.Close()
	paths := []string{}
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read secrets"})
			return
		}
		paths = append(paths, path)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secrets"})
		return
	}
	s.recordAuditEvent(r, "list", "success", s.auditRequestActor(r, source), source, "*", "")
	writeJSON(w, http.StatusOK, paths)
}

func validSecretPath(path string) bool {
	segments := strings.Split(path, "/")
	if len(segments) == 0 {
		return false
	}
	for _, segment := range segments {
		if len(segment) < 1 || len(segment) > 127 {
			return false
		}
		for _, char := range segment {
			if (char < 'a' || char > 'z') &&
				(char < 'A' || char > 'Z') &&
				(char < '0' || char > '9') &&
				char != '-' {
				return false
			}
		}
	}
	return true
}

func writeInvalidSecretPath(w http.ResponseWriter) {
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"error": "invalid secret path: each segment must be 1-127 characters and contain only letters, numbers, or hyphens",
	})
}

func (s *server) browseSecrets(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	rows, err := s.secretsDB.Query("SELECT path FROM secrets ORDER BY path")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secrets"})
		return
	}
	defer rows.Close()

	groupCounts := make(map[string]int)
	groupPaths := make(map[string][]string)
	allPaths := make([]string, 0)
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read secrets"})
			return
		}
		group := secretGroup(path)
		groupCounts[group]++
		groupPaths[group] = append(groupPaths[group], path)
		allPaths = append(allPaths, path)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secrets"})
		return
	}

	groups := make([]map[string]any, 0, len(groupCounts))
	groupNames := make([]string, 0, len(groupCounts))
	for group := range groupCounts {
		groupNames = append(groupNames, group)
	}
	sort.Strings(groupNames)
	for _, group := range groupNames {
		groups = append(groups, map[string]any{"name": group, "count": groupCounts[group]})
	}

	selected := strings.TrimSpace(r.URL.Query().Get("group"))
	if selected == "" && len(groupNames) > 0 {
		selected = groupNames[0]
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || (limit != 10 && limit != 20 && limit != 50 && limit != 100) {
		limit = 20
	}
	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}
	paths, groupExists := groupPaths[selected]
	if selected != "" && (!groupExists || !strings.Contains(selected, "/")) {
		if !validSecretPath(selected) {
			writeInvalidSecretPath(w)
			return
		}
		paths = make([]string, 0)
		for _, path := range allPaths {
			if path == selected || strings.HasPrefix(path, selected+"/") {
				paths = append(paths, path)
			}
		}
	}
	total := len(paths)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	pagedPaths := append([]string{}, paths[offset:end]...)

	writeJSON(w, http.StatusOK, map[string]any{
		"groups": groups,
		"group":  selected,
		"paths":  pagedPaths,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func secretGroup(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return parts[0]
	}
	return strings.Join(parts[:2], "/")
}

func (s *server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	year := time.Now().UTC().Year()
	if rawYear := strings.TrimSpace(r.URL.Query().Get("year")); rawYear != "" {
		parsedYear, err := strconv.Atoi(rawYear)
		if err != nil || parsedYear < 1970 || parsedYear > 9999 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid year"})
			return
		}
		year = parsedYear
	}
	years, err := s.auditStore.AvailableYears()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list audit years"})
		return
	}
	yearExists := false
	for _, availableYear := range years {
		if availableYear == year {
			yearExists = true
			break
		}
	}
	if !yearExists {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no audit database for selected year"})
		return
	}

	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}

	conditions := []string{"1 = 1"}
	args := make([]any, 0)
	addFilter := func(column, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		conditions = append(conditions, column+" = ?")
		args = append(args, value)
	}
	addFilter("action", r.URL.Query().Get("action"))
	addFilter("outcome", r.URL.Query().Get("outcome"))
	addFilter("actor", r.URL.Query().Get("actor"))
	addFilter("source", r.URL.Query().Get("source"))

	if search := strings.TrimSpace(r.URL.Query().Get("q")); search != "" {
		conditions = append(conditions, "(actor LIKE ? OR resource LIKE ? OR detail LIKE ?)")
		pattern := "%" + search + "%"
		args = append(args, pattern, pattern, pattern)
	}
	if from, ok := parseAuditDate(r.URL.Query().Get("from")); ok {
		if from.UTC().Year() != year {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from date must be in selected year"})
			return
		}
		conditions = append(conditions, "created_at >= ?")
		args = append(args, from.Unix())
	} else if strings.TrimSpace(r.URL.Query().Get("from")) != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid from date"})
		return
	}
	if to, ok := parseAuditDate(r.URL.Query().Get("to")); ok {
		if to.UTC().Year() != year {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to date must be in selected year"})
			return
		}
		conditions = append(conditions, "created_at < ?")
		args = append(args, to.Add(24*time.Hour).Unix())
	} else if strings.TrimSpace(r.URL.Query().Get("to")) != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid to date"})
		return
	}

	where := strings.Join(conditions, " AND ")
	var result map[string]any
	err = s.auditStore.withYear(year, func(db *sql.DB) error {
		var queryErr error
		result, queryErr = queryAuditEvents(db, year, where, args, limit, offset)
		return queryErr
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not query selected audit year"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func queryAuditEvents(db *sql.DB, year int, where string, args []any, limit, offset int) (map[string]any, error) {
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE "+where, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count audit events: %w", err)
	}
	queryArgs := append(append([]any{}, args...), limit, offset)
	rows, err := db.Query(`
		SELECT id, created_at, action, outcome, actor, client_ip, source, resource, detail
		FROM audit_events
		WHERE `+where+`
		ORDER BY created_at DESC, id DESC
		LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	events := make([]map[string]any, 0)
	for rows.Next() {
		var id, createdAt int64
		var action, outcome, actor, clientIP, source, resource, detail string
		if err := rows.Scan(&id, &createdAt, &action, &outcome, &actor, &clientIP, &source, &resource, &detail); err != nil {
			return nil, fmt.Errorf("read audit event: %w", err)
		}
		events = append(events, map[string]any{
			"id":         id,
			"created_at": time.Unix(createdAt, 0).UTC().Format(time.RFC3339),
			"action":     action,
			"outcome":    outcome,
			"actor":      actor,
			"client_ip":  clientIP,
			"source":     source,
			"resource":   resource,
			"detail":     detail,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit events: %w", err)
	}
	return map[string]any{
		"year":   year,
		"events": events,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	}, nil
}

func (s *server) listAuditYears(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	years, err := s.auditStore.AvailableYears()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list audit years"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"years": years})
}

func parseAuditDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse("2006-01-02", value)
	return parsed, err == nil
}

func (s *server) kvAuthorized(r *http.Request) bool {
	return s.authorizedAPI(r)
}

func (s *server) serveHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.serveNotFound(w, r)
		return
	}
	destination := "/secrets.html"
	if s.adminName == "" {
		destination = "/setup.html"
		if s.setupLocked() {
			destination = "/lock.html"
		}
	} else if !s.authorizedWeb(r) {
		destination = "/login.html"
	}
	s.renderPage(w, "index.gohtml", http.StatusOK, map[string]string{"Destination": destination})
}

func (s *server) serveSetup(w http.ResponseWriter, r *http.Request) {
	if s.adminName != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if s.setupLocked() {
		s.serveLocked(w, r)
		return
	}
	s.renderPage(w, "setup.gohtml", http.StatusOK, map[string]bool{"ACMEAvailable": s.acmeAvailable})
}

func (s *server) serveLogin(w http.ResponseWriter, r *http.Request) {
	if s.adminName == "" {
		destination := "/setup.html"
		if s.setupLocked() {
			destination = "/lock.html"
		}
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	if s.authorizedWeb(r) {
		http.Redirect(w, r, "/secrets.html", http.StatusSeeOther)
		return
	}
	autoBlockLoginIPEnabled, err := s.autoBlockLoginIPEnabled()
	if err != nil {
		log.Printf("ERROR: could not read automatic login IP blocking setting: %v", err)
		http.Error(w, "could not load login page", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, "login.gohtml", http.StatusOK, map[string]bool{
		"AutoBlockLoginIPEnabled": autoBlockLoginIPEnabled,
	})
}

func (s *server) serveSecrets(w http.ResponseWriter, r *http.Request) {
	s.serveProtectedPage(w, r, "secret.gohtml")
}

func (s *server) serveSecretBrowser(w http.ResponseWriter, r *http.Request) {
	s.serveProtectedPage(w, r, "secrets.gohtml")
}

func (s *server) serveTokens(w http.ResponseWriter, r *http.Request) {
	s.serveProtectedPage(w, r, "token.gohtml")
}

func (s *server) serveAudit(w http.ResponseWriter, r *http.Request) {
	s.serveProtectedPage(w, r, "audit.gohtml")
}

func (s *server) serveAccount(w http.ResponseWriter, r *http.Request) {
	s.serveProtectedPage(w, r, "account.gohtml")
}

func redirectSecurityPage(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/security.html", http.StatusMovedPermanently)
}

func (s *server) serveSecurity(w http.ResponseWriter, r *http.Request) {
	s.serveAdminProtectedPage(w, r, "security.gohtml")
}

func (s *server) serveOperators(w http.ResponseWriter, r *http.Request) {
	s.serveAdminProtectedPage(w, r, "operators.gohtml")
}

func (s *server) serveAdminProtectedPage(w http.ResponseWriter, r *http.Request, name string) {
	if s.adminName == "" {
		destination := "/setup.html"
		if s.setupLocked() {
			destination = "/lock.html"
		}
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	session, ok := s.sessionFromRequest(r)
	if !ok {
		s.renderPage(w, "401.gohtml", http.StatusUnauthorized, nil)
		return
	}
	if session.role != "admin" {
		http.Error(w, "administrator access required", http.StatusForbidden)
		return
	}
	s.renderPage(w, name, http.StatusOK, map[string]bool{"IsAdmin": true})
}

func (s *server) serveProtectedPage(w http.ResponseWriter, r *http.Request, name string) {
	if s.adminName == "" {
		destination := "/setup.html"
		if s.setupLocked() {
			destination = "/lock.html"
		}
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	session, ok := s.sessionFromRequest(r)
	if !ok {
		s.renderPage(w, "401.gohtml", http.StatusUnauthorized, nil)
		return
	}
	data := map[string]bool{"IsAdmin": session.role == "admin"}
	if name == "token.gohtml" {
		enforced, err := s.mtlsSettings()
		if err != nil {
			log.Printf("ERROR: could not read mTLS settings for token page: %v", err)
			http.Error(w, "could not read mTLS settings", http.StatusInternalServerError)
			return
		}
		data["EnforceMTLS"] = enforced
	}
	s.renderPage(w, name, http.StatusOK, data)
}

func (s *server) setupLocked() bool {
	return !s.setupDeadline.IsZero() && !time.Now().Before(s.setupDeadline)
}

func (s *server) serveLocked(w http.ResponseWriter, r *http.Request) {
	if s.adminName != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderPage(w, "lock.gohtml", http.StatusLocked, nil)
}

func (s *server) serveUnauthorized(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, "401.gohtml", http.StatusUnauthorized, nil)
}

func (s *server) serveNotFound(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.renderPage(w, "404.gohtml", http.StatusNotFound, nil)
}

func (s *server) renderPage(w http.ResponseWriter, name string, status int, data any) {
	var output bytes.Buffer
	if err := pageTemplate.ExecuteTemplate(&output, name, data); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = output.WriteTo(w)
}

func (s *server) webSession(w http.ResponseWriter, r *http.Request) {
	session, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":        true,
		"role":                 session.role,
		"must_change_password": session.mustChangePassword,
	})
}
