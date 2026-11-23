package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type server struct {
	db        *sql.DB
	setupKey  string
	adminName string
	aead      cipher.AEAD

	mu       sync.Mutex
	sessions map[string]time.Time
	attempts map[string][]time.Time
}

type accountRequest struct {
	SetupKey string `json:"setup_key"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type secretRequest struct {
	Data map[string]any `json:"data"`
}

//go:embed index.gohtml
var embeddedFiles embed.FS

var pageTemplate = template.Must(template.ParseFS(embeddedFiles, "index.gohtml"))

func main() {
	var (
		addr   = flag.String("addr", envDefault("VAULT_SERVER_ADDR", "127.0.0.1:8200"), "server address")
		dbPath = flag.String("db", envDefault("VAULT_SERVER_DB", "vault.db"), "path to database file")
	)
	flag.Parse()

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

	db, err := sql.Open("sqlite", *dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(1)
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
	`); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(*dbPath, 0600); err != nil {
		log.Fatal(err)
	}

	setupKey := os.Getenv("VAULT_SERVER_SETUP_KEY")
	if setupKey == "" {
		var err error
		setupKey, err = loadOrCreateSetupKey(*dbPath + ".setup-key")
		if err != nil {
			log.Fatal(err)
		}
	}

	masterKey, err := loadOrCreateKey(*dbPath + ".key")
	if err != nil {
		log.Fatal(err)
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		log.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	var adminName string
	if err := db.QueryRow("SELECT username FROM accounts LIMIT 1").Scan(&adminName); err != nil && err != sql.ErrNoRows {
		log.Fatal(err)
	}

	s := &server{db: db, setupKey: setupKey, adminName: adminName, aead: aead, sessions: map[string]time.Time{}, attempts: map[string][]time.Time{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)

	// Web endpoints: use same-origin cookie sessions.
	mux.HandleFunc("POST /v1/setup", s.setup)
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("POST /v1/auth/logout", s.logout)
	mux.HandleFunc("GET /v1/secrets/{path...}", s.getSecret)
	mux.HandleFunc("PUT /v1/secrets/{path...}", s.putSecret)
	mux.HandleFunc("DELETE /v1/secrets/{path...}", s.deleteSecret)
	mux.HandleFunc("GET /v1/secrets", s.listSecrets)
	mux.HandleFunc("GET /v1/session", s.webSession)

	// API endpoints: require bearer/X-Vault-Token authentication.
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("POST /api/v1/auth/ldap/login/{username}", s.loginLDAP)
	mux.HandleFunc("PUT /api/v1/auth/ldap/login/{username}", s.loginLDAP)
	mux.HandleFunc("GET /api/v1/{mount}/data/{path...}", s.getKVSecret)
	mux.HandleFunc("PUT /api/v1/{mount}/data/{path...}", s.putKVSecret)
	mux.HandleFunc("DELETE /api/v1/{mount}/data/{path...}", s.deleteKVSecret)
	mux.HandleFunc("LIST /api/v1/{mount}/metadata/{path...}", s.listKVMetadata)

	mux.HandleFunc("GET /", s.serveHome)

	handler := s.securityHeaders(http.MaxBytesHandler(mux, 1<<20))
	server := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	fmt.Printf("Vault setup key: %s\n", setupKey)
	log.Printf("Vault server listening on %s (SQLite: %s)", *addr, *dbPath)

	certFile := os.Getenv("VAULT_SERVER_TLS_CERT")
	keyFile := os.Getenv("VAULT_SERVER_TLS_KEY")
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			log.Fatal("both VAULT_SERVER_TLS_CERT and VAULT_SERVER_TLS_KEY are required")
		}
		log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
	}
	log.Fatal(server.ListenAndServe())
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
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

func loadOrCreateKey(path string) ([]byte, error) {
	if key, err := os.ReadFile(path); err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("invalid encryption key length")
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, err
	}
	return key, os.Chmod(path, 0600)
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

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) setup(w http.ResponseWriter, r *http.Request) {
	var req accountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if s.adminName != "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account already configured"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.SetupKey), []byte(s.setupKey)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid setup key"})
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
	writeJSON(w, http.StatusCreated, map[string]string{"username": req.Username})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var req accountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	ip := r.RemoteAddr
	cutoff := time.Now().Add(-10 * time.Minute)
	s.mu.Lock()
	recent := s.attempts[ip][:0]
	for _, attempt := range s.attempts[ip] {
		if attempt.After(cutoff) {
			recent = append(recent, attempt)
		}
	}
	if len(recent) >= 5 {
		s.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts"})
		return
	}
	recent = append(recent, time.Now())
	s.attempts[ip] = recent
	s.mu.Unlock()

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
	return s.authorizedToken(token)
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
	data := map[string]any{
		"Title":      "Vault Server",
		"Configured": s.adminName != "",
	}
	if err := pageTemplate.Execute(w, data); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (s *server) webSession(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}
