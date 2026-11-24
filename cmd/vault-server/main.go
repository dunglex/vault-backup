package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
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
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/CovenantSQL/go-sqlite3-encrypt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	databaseKeyLength  = 128
	argonTime          = uint32(3)
	argonMemory        = uint32(64 * 1024)
	argonThreads       = uint8(4)
	apiTokenLifetime   = 30 * 24 * time.Hour
	setupLifetime      = 20 * time.Minute
	loginAttemptLimit  = 5
	loginAttemptWindow = 10 * time.Minute
)

type encryptedKeyFile struct {
	Version    int    `json:"version"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type server struct {
	db            *sql.DB
	setupKey      string
	setupKeyPath  string
	setupDeadline time.Time
	adminName     string
	aead          cipher.AEAD

	mu             sync.Mutex
	sessions       map[string]time.Time
	attempts       map[string][]time.Time
	trustedProxies []*net.IPNet
}

type accountRequest struct {
	SetupKey             string `json:"setup_key"`
	Username             string `json:"username"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"password_confirmation"`
}

type secretRequest struct {
	Data map[string]any `json:"data"`
}

//go:embed *.gohtml
var embeddedFiles embed.FS

var pageTemplate = template.Must(template.ParseFS(embeddedFiles, "*.gohtml"))

func main() {
	envFile := envFileFromArgs()
	if envFile != "" {
		if err := loadDotEnv(envFile); err != nil {
			log.Fatal(err)
		}
	}
	var (
		addr             = flag.String("addr", envDefault("VAULT_SERVER_ADDR", "127.0.0.1:8200"), "HTTPS server address")
		httpAddr         = flag.String("http-addr", envDefault("VAULT_SERVER_HTTP_ADDR", ""), "HTTP server address (disabled by default)")
		dbPath           = flag.String("db", envDefault("VAULT_SERVER_DB", "vault.db"), "path to database file")
		tlsCert          = flag.String("tls-cert", envDefault("VAULT_SERVER_TLS_CERT", ""), "path to TLS certificate PEM")
		tlsKey           = flag.String("tls-key", envDefault("VAULT_SERVER_TLS_KEY", ""), "path to TLS private key PEM")
		dbPassword       = flag.String("db-password", envDefault("VAULT_SERVER_DB_PASSWORD", ""), "password used to decrypt the database key file")
		allowPlaintextDB = flag.Bool("allow-plaintext-db", envBool("VAULT_SERVER_ALLOW_PLAINTEXT_DB", false), "allow an existing plaintext SQLite database (insecure)")
		envFileFlag      = flag.String("env-file", envDefault("VAULT_SERVER_ENV_FILE", ".env"), "path to .env configuration file")
		mtlsCACert       = flag.String("mtls-ca-cert", envDefault("VAULT_SERVER_MTLS_CA_CERT", ""), "CA certificate PEM used to verify HTTPS client certificates")
		trustedProxies   = flag.String("trusted-proxies", envDefault("VAULT_SERVER_TRUSTED_PROXIES", ""), "comma-separated proxy IP/CIDR ranges allowed to set forwarding headers")
	)
	flag.Parse()
	_ = envFileFlag
	if strings.TrimSpace(*tlsCert) == "" || strings.TrimSpace(*tlsKey) == "" {
		log.Fatal("HTTPS startup requires --tls-cert and --tls-key (or VAULT_SERVER_TLS_CERT and VAULT_SERVER_TLS_KEY)")
	}
	if *dbPassword == "" {
		log.Fatal("database key password is required: set --db-password or VAULT_SERVER_DB_PASSWORD")
	}
	*httpAddr = strings.TrimSpace(*httpAddr)
	if *httpAddr != "" {
		log.Printf("WARNING: insecure HTTP listener enabled on %s; traffic is not encrypted", *httpAddr)
	}

	resolvedDB, err := filepath.Abs(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	*dbPath = filepath.Clean(resolvedDB)

	if dir := filepath.Dir(*dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatal(err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			log.Fatal(err)
		}
	}

	masterKey, err := loadOrCreateKey(*dbPath+".key", *dbPassword)
	if err != nil {
		log.Fatal(err)
	}

	db, _, err := openDatabaseWithOptions(*dbPath, masterKey, *allowPlaintextDB)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := os.Chmod(*dbPath, 0600); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS accounts (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS secrets (
			path TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			revoked_at INTEGER
		);
		CREATE TABLE IF NOT EXISTS server_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
	`); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(*dbPath, 0600); err != nil {
		log.Fatal(err)
	}

	var adminName string
	if err := db.QueryRow("SELECT username FROM accounts LIMIT 1").Scan(&adminName); err != nil && err != sql.ErrNoRows {
		log.Fatal(err)
	}

	setupKeyPath := *dbPath + ".setup-key"
	setupKey := ""
	if adminName == "" {
		setupKey = os.Getenv("VAULT_SERVER_SETUP_KEY")
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

	applicationKey := sha256.Sum256(masterKey)
	block, err := aes.NewCipher(applicationKey[:])
	if err != nil {
		log.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	trustedProxyRanges, err := parseTrustedProxies(*trustedProxies)
	if err != nil {
		log.Fatal(err)
	}
	s := &server{db: db, setupKey: setupKey, setupKeyPath: setupKeyPath, setupDeadline: setupDeadline, adminName: adminName, aead: aead, sessions: map[string]time.Time{}, attempts: map[string][]time.Time{}, trustedProxies: trustedProxyRanges}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
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
	for _, path := range []string{"/token", "/token.html"} {
		mux.HandleFunc("GET "+path, s.serveTokens)
	}
	for _, path := range []string{"/401", "/401.html"} {
		mux.HandleFunc("GET "+path, s.serveUnauthorized)
	}
	for _, path := range []string{"/404", "/404.html"} {
		mux.HandleFunc("GET "+path, s.serveNotFound)
	}

	// Web endpoints: use same-origin cookie sessions.
	mux.HandleFunc("POST /v1/setup", s.setup)
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("POST /v1/auth/logout", s.logout)
	mux.HandleFunc("GET /v1/secrets/{path...}", s.getSecret)
	mux.HandleFunc("PUT /v1/secrets/{path...}", s.putSecret)
	mux.HandleFunc("DELETE /v1/secrets/{path...}", s.deleteSecret)
	mux.HandleFunc("GET /v1/secrets", s.listSecrets)
	mux.HandleFunc("GET /v1/session", s.webSession)
	mux.HandleFunc("POST /v1/tokens", s.createAPIToken)
	mux.HandleFunc("GET /v1/tokens", s.listAPITokens)
	mux.HandleFunc("DELETE /v1/tokens/{id}", s.revokeAPIToken)

	// API endpoints: require bearer/X-Vault-Token authentication.
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("POST /api/v1/auth/ldap/login/{username}", s.loginLDAP)
	mux.HandleFunc("PUT /api/v1/auth/ldap/login/{username}", s.loginLDAP)
	mux.HandleFunc("GET /api/v1/{mount}/data/{path...}", s.getKVSecret)
	mux.HandleFunc("PUT /api/v1/{mount}/data/{path...}", s.putKVSecret)
	mux.HandleFunc("DELETE /api/v1/{mount}/data/{path...}", s.deleteKVSecret)
	mux.HandleFunc("LIST /api/v1/{mount}/metadata/{path...}", s.listKVMetadata)

	mux.HandleFunc("/", s.serveHome)

	handler := s.securityHeaders(s.setupLockAPIs(http.MaxBytesHandler(mux, 1<<20)))
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if strings.TrimSpace(*mtlsCACert) != "" {
		clientCAs, err := loadClientCAPool(*mtlsCACert)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = clientCAs
		log.Printf("Vault server HTTPS mutual TLS enabled using client CA %s", *mtlsCACert)
	}
	httpsServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         tlsConfig,
	}
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	httpsListener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	var httpListener net.Listener
	if *httpAddr != "" {
		httpListener, err = net.Listen("tcp", *httpAddr)
		if err != nil {
			_ = httpsListener.Close()
			log.Fatal(err)
		}
	}

	if setupKey != "" {
		fmt.Printf("Vault setup key: %s\n", setupKey)
	}
	log.Printf("Vault server listening on %s (SQLite: %s)", *addr, *dbPath)
	log.Printf("Vault server serving HTTPS on %s", *addr)
	if httpListener != nil {
		log.Printf("Vault server serving HTTP on %s", *httpAddr)
	}
	errCount := 1
	if httpListener != nil {
		errCount++
	}
	errs := make(chan error, errCount)
	go func() { errs <- httpsServer.ServeTLS(httpsListener, *tlsCert, *tlsKey) }()
	if httpListener != nil {
		go func() { errs <- httpServer.Serve(httpListener) }()
	}
	log.Fatal(<-errs)
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("WARNING: invalid boolean value for %s=%q; using %t", name, value, fallback)
		return fallback
	}
	return parsed
}

func loadClientCAPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read mTLS client CA certificate %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("mTLS client CA file %s contains no valid PEM certificates", path)
	}
	return pool, nil
}

func envFileFromArgs() string {
	path := envDefault("VAULT_SERVER_ENV_FILE", ".env")
	for i, arg := range os.Args[1:] {
		if arg == "--env-file" && i+2 < len(os.Args) {
			path = os.Args[i+2]
			break
		}
		if strings.HasPrefix(arg, "--env-file=") {
			path = strings.TrimPrefix(arg, "--env-file=")
			break
		}
	}
	return strings.TrimSpace(path)
}

func loadDotEnv(path string) error {
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("could not open env file %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if key != "" {
			if _, exists := os.LookupEnv(key); !exists {
				if err := os.Setenv(key, value); err != nil {
					return fmt.Errorf("could not load %s from env file %s: %w", key, path, err)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("could not read env file %s: %w", path, err)
	}
	return nil
}

func isPlaintextSQLite(path string) (bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()

	const sqliteHeader = "SQLite format 3\x00"
	header := make([]byte, len(sqliteHeader))
	if _, err := io.ReadFull(file, header); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	return string(header) == sqliteHeader, nil
}

func openDatabase(path string, key []byte) (*sql.DB, bool, error) {
	return openDatabaseWithOptions(path, key, false)
}

func openDatabaseWithOptions(path string, key []byte, allowPlaintext bool) (*sql.DB, bool, error) {
	legacyDatabase, err := isPlaintextSQLite(path)
	if err != nil {
		return nil, false, err
	}

	driverName := "sqlite3"
	dsn := path + "?_crypto_key=" + hex.EncodeToString(key) + "&_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=1"
	if legacyDatabase {
		if !allowPlaintext {
			return nil, true, fmt.Errorf("existing database %s is plaintext SQLite; use --allow-plaintext-db or VAULT_SERVER_ALLOW_PLAINTEXT_DB=true only after acknowledging it is insecure", path)
		}
		driverName = "sqlite"
		dsn = path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
		log.Printf("WARNING: plaintext SQLite database %s is allowed and remains unencrypted", path)
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, legacyDatabase, err
	}
	db.SetMaxOpenConns(1)
	return db, legacyDatabase, nil
}

func randomKey() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func loadOrCreateKey(path, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("database key password is required")
	}

	fileContents, err := os.ReadFile(path)
	if err == nil {
		if len(fileContents) == 0 || fileContents[0] != '{' {
			return nil, fmt.Errorf("unsupported legacy database key file format; remove it to create a new 128-byte protected key")
		}
		return decryptKeyFile(fileContents, password)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key := make([]byte, databaseKeyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := writeEncryptedKeyFile(path, key, password); err != nil {
		return nil, err
	}
	return key, nil
}

func deriveWrappingKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, 32)
}

func encryptKey(plaintext []byte, password string) (*encryptedKeyFile, error) {
	if len(plaintext) != databaseKeyLength {
		return nil, fmt.Errorf("database key must be exactly %d bytes", databaseKeyLength)
	}
	salt := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	wrappingKey := deriveWrappingKey(password, salt)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &encryptedKeyFile{
		Version:    1,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, nil),
	}, nil
}

func decryptKeyFile(contents []byte, password string) ([]byte, error) {
	var envelope encryptedKeyFile
	if err := json.Unmarshal(contents, &envelope); err != nil {
		return nil, fmt.Errorf("invalid encrypted database key file: %w", err)
	}
	if envelope.Version != 1 {
		return nil, fmt.Errorf("unsupported database key file version %d", envelope.Version)
	}
	if len(envelope.Salt) != 32 {
		return nil, fmt.Errorf("invalid database key salt length")
	}
	if len(envelope.Nonce) != 12 {
		return nil, fmt.Errorf("invalid database key nonce length")
	}

	wrappingKey := deriveWrappingKey(password, envelope.Salt)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt database key: wrong db password or corrupted key file")
	}
	if len(plaintext) != databaseKeyLength {
		return nil, fmt.Errorf("invalid decrypted database key length: got %d bytes", len(plaintext))
	}
	return plaintext, nil
}

func writeEncryptedKeyFile(path string, key []byte, password string) error {
	envelope, err := encryptKey(key, password)
	if err != nil {
		return err
	}
	contents, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".vault-db-key-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(contents); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	cleanup = false
	return os.Chmod(path, 0600)
}

func loadOrCreateSetupKey(path string) (string, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		setupKey := strings.TrimSpace(string(key))
		if setupKey == "" {
			return "", fmt.Errorf("invalid setup key file")
		}
		return setupKey, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}

	setupKey := randomKey()
	if err := os.WriteFile(path, []byte(setupKey+"\n"), 0600); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	return setupKey, nil
}

func loadOrCreateSetupDeadline(db *sql.DB) (time.Time, error) {
	const key = "setup_started_at"
	now := time.Now().Unix()
	if _, err := db.Exec(
		"INSERT OR IGNORE INTO server_settings(key, value) VALUES (?, ?)",
		key,
		strconv.FormatInt(now, 10),
	); err != nil {
		return time.Time{}, err
	}

	var value string
	if err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", key).Scan(&value); err != nil {
		return time.Time{}, err
	}
	startedAt, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid setup start time: %w", err)
	}
	return time.Unix(startedAt, 0).Add(setupLifetime), nil
}

func (s *server) encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (s *server) decrypt(encoded string) ([]byte, error) {
	sealed, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(sealed) < s.aead.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	nonce, ciphertext := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]
	return s.aead.Open(nil, nonce, ciphertext, nil)
}

func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *server) setupLockAPIs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAPI := strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/")
		if isAPI && s.adminName == "" && s.setupLocked() {
			writeJSON(w, http.StatusLocked, map[string]string{"error": "setup window expired"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) setup(w http.ResponseWriter, r *http.Request) {
	if s.adminName != "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account already configured"})
		return
	}
	if s.setupLocked() {
		writeJSON(w, http.StatusLocked, map[string]string{"error": "setup window expired"})
		return
	}
	var req accountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.SetupKey), []byte(s.setupKey)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid setup key"})
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

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create account"})
		return
	}
	if _, err := s.db.Exec("INSERT INTO accounts(username, password_hash) VALUES (?, ?)", req.Username, string(hash)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create account"})
		return
	}
	s.adminName = req.Username
	s.setupKey = ""
	if err := os.Remove(s.setupKeyPath); err != nil && !os.IsNotExist(err) {
		log.Printf("WARNING: could not remove setup key file %s: %v", s.setupKeyPath, err)
	}
	writeJSON(w, http.StatusCreated, map[string]string{"username": req.Username})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var req accountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	if !s.allowLoginAttempt(r, req.Username) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts"})
		return
	}

	var hash string
	if err := s.db.QueryRow("SELECT password_hash FROM accounts WHERE username = ?", req.Username).Scan(&hash); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}

	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create session"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(30 * time.Minute)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "vault_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((30 * time.Minute).Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *server) loginLDAP(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	var req accountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if !s.allowLoginAttempt(r, username) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts"})
		return
	}
	var hash string
	if err := s.db.QueryRow("SELECT password_hash FROM accounts WHERE username = ?", username).Scan(&hash); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create session"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(30 * time.Minute)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"auth": map[string]any{"client_token": token}})
}

func parseTrustedProxies(value string) ([]*net.IPNet, error) {
	var ranges []*net.IPNet
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy address %q", part)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			part += fmt.Sprintf("/%d", bits)
		}
		_, network, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", part, err)
		}
		ranges = append(ranges, network)
	}
	return ranges, nil
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
	cookie, err := r.Cookie("vault_session")
	if err != nil {
		return false
	}
	return s.authorizedToken(cookie.Value)
}

func (s *server) authorizedAPI(r *http.Request) bool {
	token := r.Header.Get("X-Vault-Token")
	if token == "" {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	return s.authorizedAPIToken(token)
}

func (s *server) authorizedToken(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.sessions[token]
	if !ok || time.Now().After(expires) {
		delete(s.sessions, token)
		return false
	}
	s.sessions[token] = time.Now().Add(30 * time.Minute)
	return true
}

func (s *server) authorizedAPIToken(token string) bool {
	if token == "" {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	now := time.Now().Unix()
	var expires int64
	err := s.db.QueryRow(
		"SELECT expires_at FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL",
		hex.EncodeToString(hash[:]),
	).Scan(&expires)
	if err == nil && expires >= now {
		return true
	}
	return false
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	token := ""
	if cookie, err := r.Cookie("vault_session"); err == nil {
		token = cookie.Value
	}
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "vault_session", Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required and must be at most 128 characters"})
		return
	}

	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create API token"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256([]byte(token))
	createdAt := time.Now()
	expiresAt := createdAt.Add(apiTokenLifetime)
	result, err := s.db.Exec(
		"INSERT INTO api_tokens(name, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
		req.Name,
		hex.EncodeToString(tokenHash[:]),
		createdAt.Unix(),
		expiresAt.Unix(),
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create API token"})
		return
	}
	id, err := result.LastInsertId()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create API token"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id,
		"name":       req.Name,
		"token":      token,
		"created_at": createdAt.UTC().Format(time.RFC3339),
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *server) listAPITokens(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	rows, err := s.db.Query(`
		SELECT id, name, created_at, expires_at, revoked_at
		FROM api_tokens
		ORDER BY created_at DESC, id DESC`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list API tokens"})
		return
	}
	defer rows.Close()

	tokens := make([]map[string]any, 0)
	for rows.Next() {
		var id, createdAt, expiresAt int64
		var revokedAt sql.NullInt64
		var name string
		if err := rows.Scan(&id, &name, &createdAt, &expiresAt, &revokedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read API tokens"})
			return
		}
		item := map[string]any{
			"id":         id,
			"name":       name,
			"created_at": time.Unix(createdAt, 0).UTC().Format(time.RFC3339),
			"expires_at": time.Unix(expiresAt, 0).UTC().Format(time.RFC3339),
			"expired":    expiresAt < time.Now().Unix(),
			"revoked":    revokedAt.Valid,
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
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token id"})
		return
	}
	result, err := s.db.Exec(
		"UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
		time.Now().Unix(),
		id,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke API token"})
		return
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "active API token not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *server) getKVSecret(w http.ResponseWriter, r *http.Request) {
	if !s.kvAuthorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	path := r.PathValue("mount") + "/" + r.PathValue("path")
	var encrypted string
	if err := s.db.QueryRow("SELECT data FROM secrets WHERE path = ?", path).Scan(&encrypted); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{"secret not found"}})
		return
	}
	plaintext, err := s.decrypt(encrypted)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid stored secret"})
		return
	}
	var data map[string]any
	if err := json.Unmarshal(plaintext, &data); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid stored secret"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"data": data}})
}

func (s *server) putKVSecret(w http.ResponseWriter, r *http.Request) {
	if !s.kvAuthorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Data == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid secret data"})
		return
	}
	plaintext, err := json.Marshal(req.Data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid secret data"})
		return
	}
	encrypted, err := s.encrypt(plaintext)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store secret"})
		return
	}
	path := r.PathValue("mount") + "/" + r.PathValue("path")
	if _, err := s.db.Exec(`INSERT INTO secrets(path, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(path) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`, path, encrypted); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store secret"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"version": 1}})
}

func (s *server) deleteKVSecret(w http.ResponseWriter, r *http.Request) {
	if !s.kvAuthorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	path := r.PathValue("mount") + "/" + r.PathValue("path")
	if _, err := s.db.Exec("DELETE FROM secrets WHERE path = ?", path); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not delete secret"})
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *server) listKVMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.kvAuthorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	prefix := r.PathValue("mount") + "/"
	secretPrefix := r.PathValue("path")
	if secretPrefix != "" {
		prefix += strings.Trim(secretPrefix, "/") + "/"
	}
	rows, err := s.db.Query("SELECT path FROM secrets WHERE path LIKE ? ORDER BY path", prefix+"%")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secrets"})
		return
	}
	defer rows.Close()
	keys := []string{}
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read secrets"})
			return
		}
		path = strings.TrimPrefix(path, prefix)
		if path != "" && !strings.Contains(path, "/") {
			keys = append(keys, path)
		}
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secrets"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"keys": keys}})
}

func (s *server) getSecret(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	path := r.PathValue("path")
	var encrypted string
	if err := s.db.QueryRow("SELECT data FROM secrets WHERE path = ?", path).Scan(&encrypted); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "secret not found"})
		return
	}
	plaintext, err := s.decrypt(encrypted)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid stored secret"})
		return
	}
	var data map[string]any
	if err := json.Unmarshal(plaintext, &data); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid stored secret"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

func (s *server) putSecret(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req secretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Data == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid secret data"})
		return
	}
	plaintext, err := json.Marshal(req.Data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid secret data"})
		return
	}
	encrypted, err := s.encrypt(plaintext)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store secret"})
		return
	}
	path := r.PathValue("path")
	if _, err := s.db.Exec(`INSERT INTO secrets(path, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(path) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`, path, encrypted); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store secret"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"path": path})
}

func (s *server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	path := r.PathValue("path")
	if _, err := s.db.Exec("DELETE FROM secrets WHERE path = ?", path); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not delete secret"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"path": path})
}

func (s *server) listSecrets(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	rows, err := s.db.Query("SELECT path FROM secrets ORDER BY path")
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
	writeJSON(w, http.StatusOK, paths)
}

func (s *server) kvAuthorized(r *http.Request) bool {
	return s.authorizedAPI(r)
}

func (s *server) serveHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.serveNotFound(w, r)
		return
	}
	destination := "/secret.html"
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
	s.renderPage(w, "setup.gohtml", http.StatusOK, nil)
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
		http.Redirect(w, r, "/secret.html", http.StatusSeeOther)
		return
	}
	s.renderPage(w, "login.gohtml", http.StatusOK, nil)
}

func (s *server) serveSecrets(w http.ResponseWriter, r *http.Request) {
	s.serveProtectedPage(w, r, "secret.gohtml")
}

func (s *server) serveTokens(w http.ResponseWriter, r *http.Request) {
	s.serveProtectedPage(w, r, "token.gohtml")
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
	if !s.authorizedWeb(r) {
		s.renderPage(w, "401.gohtml", http.StatusUnauthorized, nil)
		return
	}
	s.renderPage(w, name, http.StatusOK, nil)
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
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}
