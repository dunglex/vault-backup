package main

import (
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	requestTimeout     = 30 * time.Second
	serverWriteTimeout = requestTimeout + 5*time.Second
)

func (s *server) middleware(handler http.Handler) http.Handler {
	handler = http.MaxBytesHandler(handler, 1<<20)        // Limit incoming request bodies to 1 MiB.
	handler = s.setupLockAPIs(handler)                    // Lock setup APIs after the setup window expires.
	handler = s.apiClientCertificateGuard(handler)        // Enforce client-certificate rules on API requests.
	handler = s.mustChangePasswordGuard(handler)          // Restrict temporary-password sessions to account recovery.
	handler = s.mfaEnrollmentGuard(handler)               // Restrict accounts until required MFA is enrolled.
	handler = s.hostOriginGuard(handler)                  // Allow only configured hosts and origins.
	handler = withRequestTimeout(handler, requestTimeout) // Stop handlers that exceed the request time limit.
	handler = s.securityHeaders(handler)                  // Add standard security headers to responses.
	return handler
}

func (s *server) mustChangePasswordGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := s.sessionFromRequest(r)
		if !ok || !session.mustChangePassword || allowedPasswordChangeRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/") {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":                "password change is required",
				"must_change_password": true,
				"change_password_url":  "/account.html?password=required",
			})
			return
		}
		http.Redirect(w, r, "/account.html?password=required", http.StatusSeeOther)
	})
}

func allowedPasswordChangeRequest(r *http.Request) bool {
	if r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/account", "/account.html", "/v1/session", "/normalize.css", "/miligram.css", "/admin.css", "/qrcode.js":
			return true
		}
	}
	if r.Method == http.MethodPost {
		switch r.URL.Path {
		case "/v1/account/password", "/v1/auth/logout":
			return true
		}
	}
	return false
}

func (s *server) mfaEnrollmentGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		session, ok := s.sessionFromRequest(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		var totpEnabled int
		if err := s.db.QueryRow(
			"SELECT totp_enabled FROM accounts WHERE username = ?",
			session.username,
		).Scan(&totpEnabled); err != nil {
			log.Printf("ERROR: could not read MFA enrollment state: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify MFA enrollment"})
			return
		}
		if totpEnabled == 1 {
			next.ServeHTTP(w, r)
			return
		}
		enforced, err := s.mfaEnforcementEnabled()
		if err != nil {
			log.Printf("ERROR: could not read MFA enforcement setting: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify MFA enforcement"})
			return
		}
		if !enforced || allowedMFAEnrollmentRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/") {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":              "MFA setup is required",
				"requires_mfa_setup": true,
				"setup_url":          "/account.html?mfa=required",
			})
			return
		}
		http.Redirect(w, r, "/account.html?mfa=required", http.StatusSeeOther)
	})
}

func allowedMFAEnrollmentRequest(r *http.Request) bool {
	if r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/account", "/account.html", "/normalize.css", "/miligram.css", "/admin.css", "/qrcode.js":
			return true
		case "/v1/account/totp":
			return true
		}
	}
	if r.Method == http.MethodPost {
		switch r.URL.Path {
		case "/v1/auth/logout", "/v1/account/password", "/v1/account/totp/setup", "/v1/account/totp/enable":
			return true
		}
	}
	return false
}

func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func withRequestTimeout(next http.Handler, timeout time.Duration) http.Handler {
	return http.TimeoutHandler(next, timeout, `{"error":"request timed out"}`)
}

func (s *server) hostOriginGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}

		domains, err := loadConfiguredServerDomains(s.db)
		if err != nil {
			log.Printf("ERROR: could not load allowed request domains: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not validate request host"})
			return
		}
		if len(domains) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if s.adminName == "" && isSetupTraffic(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		allowedDomains := make(map[string]struct{}, len(domains))
		for _, domain := range domains {
			allowedDomains[domain] = struct{}{}
		}
		host, err := normalizeRequestHost(r.Host)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "request host or origin is not allowed"})
			return
		}
		if _, ok := allowedDomains[host]; !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "request host or origin is not allowed"})
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			originHost, err := normalizeOriginHost(origin)
			if err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "request host or origin is not allowed"})
				return
			}
			if _, ok := allowedDomains[originHost]; !ok {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "request host or origin is not allowed"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isSetupTraffic(path string) bool {
	if path == "/" || path == "/setup" || path == "/setup.html" || path == "/v1/setup" ||
		path == "/normalize.css" || path == "/miligram.css" || path == "/admin.css" {
		return true
	}
	return strings.HasPrefix(path, "/v1/setup/") || strings.HasPrefix(path, "/.well-known/acme-challenge/")
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

func (s *server) apiClientCertificateGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		enforced, err := s.mtlsSettings()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read mTLS settings"})
			return
		}
		if !enforced {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-Vault-Backup-Protocol") != "client-cert-v1" {
			writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "upgrade vault-backup to a client-certificate capable version"})
			return
		}
		token := apiTokenFromRequest(r)
		var expectedID int64
		if token != "" {
			if err := s.lookupActiveAPIToken(token, &expectedID); err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid API token"})
				return
			}
		}
		tokenID, ok := s.certificateTokenID(r)
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "a valid managed client certificate is required"})
			return
		}
		if token != "" && expectedID != tokenID {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "client certificate does not match the API token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
