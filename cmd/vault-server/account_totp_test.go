package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const totpTestPassword = "current-account-password"

func newTOTPTestServer(t *testing.T) *server {
	t.Helper()
	s := newOperatorTestServer(t)
	hash, err := bcrypt.GenerateFromPassword([]byte(totpTestPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE accounts SET password_hash = ? WHERE username = 'admin'", string(hash)); err != nil {
		t.Fatal(err)
	}
	s.attempts = make(map[string][]time.Time)
	return s
}

func totpRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.TLS = &tls.ConnectionState{}
	request.AddCookie(&http.Cookie{Name: "vault_session", Value: "admin-session"})
	return request
}

func totpLoginRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	request.TLS = &tls.ConnectionState{}
	return request
}

func setupAndEnableTOTP(t *testing.T, s *server) (string, []string) {
	t.Helper()
	setup := httptest.NewRecorder()
	s.setupAccountTOTP(setup, totpRequest(http.MethodPost, "/v1/account/totp/setup", ""))
	if setup.Code != http.StatusOK {
		t.Fatalf("TOTP setup status = %d, body %s", setup.Code, setup.Body.String())
	}
	var setupResult struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &setupResult); err != nil {
		t.Fatal(err)
	}
	code := currentTOTPCode(t, setupResult.Secret)
	enable := httptest.NewRecorder()
	s.enableAccountTOTP(enable, totpRequest(http.MethodPost, "/v1/account/totp/enable", `{"code":"`+code+`"}`))
	if enable.Code != http.StatusOK {
		t.Fatalf("TOTP enable status = %d, body %s", enable.Code, enable.Body.String())
	}
	var enableResult struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(enable.Body.Bytes(), &enableResult); err != nil {
		t.Fatal(err)
	}
	return setupResult.Secret, enableResult.RecoveryCodes
}

func currentTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	key, err := totpBase32.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	step := uint64(time.Now().Unix() / int64(totpPeriod/time.Second))
	return totpCodeAt(key, step)
}

func TestTOTPMatchesRFC6238SHA1Vector(t *testing.T) {
	secret := totpBase32.EncodeToString([]byte("12345678901234567890"))
	if !verifyTOTP(secret, "287082", time.Unix(59, 0)) {
		t.Fatal("RFC 6238 SHA-1 test code was not accepted")
	}
	if verifyTOTP(secret, "287083", time.Unix(59, 0)) {
		t.Fatal("invalid TOTP code was accepted")
	}
}

func TestAccountTOTPEnrollmentLoginRecoveryAndDisable(t *testing.T) {
	s := newTOTPTestServer(t)

	initialStatus := httptest.NewRecorder()
	s.getAccountTOTP(initialStatus, totpRequest(http.MethodGet, "/v1/account/totp", ""))
	if initialStatus.Code != http.StatusOK || !strings.Contains(initialStatus.Body.String(), `"enabled":false`) {
		t.Fatalf("default TOTP status = %d, body %s", initialStatus.Code, initialStatus.Body.String())
	}

	secret, recoveryCodes := setupAndEnableTOTP(t, s)
	if len(recoveryCodes) != totpRecoveryCodeCount {
		t.Fatalf("recovery code count = %d, want %d", len(recoveryCodes), totpRecoveryCodeCount)
	}

	challenge := httptest.NewRecorder()
	s.login(challenge, totpLoginRequest(`{"username":"admin","password":"`+totpTestPassword+`"}`))
	if challenge.Code != http.StatusOK || !strings.Contains(challenge.Body.String(), `"requires_totp":true`) {
		t.Fatalf("TOTP login challenge = %d, body %s", challenge.Code, challenge.Body.String())
	}
	if len(challenge.Result().Cookies()) != 0 {
		t.Fatal("login challenge issued a session cookie before second-factor verification")
	}

	totpCode := currentTOTPCode(t, secret)
	validLogin := httptest.NewRecorder()
	s.login(validLogin, totpLoginRequest(`{"username":"admin","password":"`+totpTestPassword+`","totp_code":"`+totpCode+`"}`))
	if validLogin.Code != http.StatusOK || len(validLogin.Result().Cookies()) == 0 {
		t.Fatalf("TOTP login status = %d, body %s", validLogin.Code, validLogin.Body.String())
	}

	recoveryLogin := httptest.NewRecorder()
	s.login(recoveryLogin, totpLoginRequest(`{"username":"admin","password":"`+totpTestPassword+`","totp_code":"`+recoveryCodes[0]+`"}`))
	if recoveryLogin.Code != http.StatusOK {
		t.Fatalf("recovery-code login status = %d, body %s", recoveryLogin.Code, recoveryLogin.Body.String())
	}
	reusedRecoveryLogin := httptest.NewRecorder()
	s.login(reusedRecoveryLogin, totpLoginRequest(`{"username":"admin","password":"`+totpTestPassword+`","totp_code":"`+recoveryCodes[0]+`"}`))
	if reusedRecoveryLogin.Code != http.StatusUnauthorized {
		t.Fatalf("reused recovery-code login status = %d, want %d", reusedRecoveryLogin.Code, http.StatusUnauthorized)
	}

	disable := httptest.NewRecorder()
	s.disableAccountTOTP(disable, totpRequest(
		http.MethodDelete,
		"/v1/account/totp",
		`{"password":"`+totpTestPassword+`","code":"`+currentTOTPCode(t, secret)+`"}`,
	))
	if disable.Code != http.StatusOK {
		t.Fatalf("disable TOTP status = %d, body %s", disable.Code, disable.Body.String())
	}
	finalStatus := httptest.NewRecorder()
	s.getAccountTOTP(finalStatus, totpRequest(http.MethodGet, "/v1/account/totp", ""))
	if finalStatus.Code != http.StatusOK || !strings.Contains(finalStatus.Body.String(), `"enabled":false`) {
		t.Fatalf("disabled TOTP status = %d, body %s", finalStatus.Code, finalStatus.Body.String())
	}
}

func TestLDAPLoginRequiresTOTPAndDoesNotConsumeRecoveryForWrongPassword(t *testing.T) {
	s := newTOTPTestServer(t)
	_, recoveryCodes := setupAndEnableTOTP(t, s)

	makeRequest := func(password, code string) *http.Request {
		body, err := json.Marshal(map[string]string{"password": password, "totp_code": code})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPut, "/api/v1/auth/ldap/login/admin", strings.NewReader(string(body)))
		request.SetPathValue("username", "admin")
		request.TLS = &tls.ConnectionState{}
		return request
	}

	wrongPassword := httptest.NewRecorder()
	s.loginLDAP(wrongPassword, makeRequest("wrong-password", recoveryCodes[0]))
	if wrongPassword.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-password LDAP login status = %d", wrongPassword.Code)
	}
	missingCode := httptest.NewRecorder()
	s.loginLDAP(missingCode, makeRequest(totpTestPassword, ""))
	if missingCode.Code != http.StatusUnauthorized || !strings.Contains(missingCode.Body.String(), "authentication code required") {
		t.Fatalf("LDAP login without TOTP = %d, body %s", missingCode.Code, missingCode.Body.String())
	}
	validRecovery := httptest.NewRecorder()
	s.loginLDAP(validRecovery, makeRequest(totpTestPassword, recoveryCodes[0]))
	if validRecovery.Code != http.StatusOK {
		t.Fatalf("LDAP login with recovery code status = %d, body %s", validRecovery.Code, validRecovery.Body.String())
	}
}

func TestAccountTOTPRequiresHTTPS(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "plain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	s := &server{
		db:       db,
		sessions: map[string]sessionInfo{"admin-session": {username: "admin", role: "admin", expiresAt: time.Now().Add(time.Hour)}},
	}
	if _, err := db.Exec("INSERT INTO accounts(username, password_hash, role) VALUES ('admin', 'hash', 'admin')"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/account/totp", nil)
	request.AddCookie(&http.Cookie{Name: "vault_session", Value: "admin-session"})
	response := httptest.NewRecorder()
	s.getAccountTOTP(response, request)
	if response.Code != http.StatusUpgradeRequired {
		t.Fatalf("HTTP account security status = %d, want %d", response.Code, http.StatusUpgradeRequired)
	}
}
