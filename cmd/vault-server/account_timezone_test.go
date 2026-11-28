package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAccountTimezoneCanBeReadAndUpdated(t *testing.T) {
	s := newTOTPTestServer(t)

	read := func() *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		s.getAccountTimezone(response, totpRequest(http.MethodGet, "/v1/account/timezone", ""))
		return response
	}
	response := read()
	if response.Code != http.StatusOK || response.Body.String() != "{\"timezone\":\"UTC\"}\n" {
		t.Fatalf("default timezone response = %d %s", response.Code, response.Body.String())
	}

	requestBody, err := json.Marshal(map[string]string{"timezone": "Asia/Ho_Chi_Minh"})
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	s.updateAccountTimezone(response, totpRequest(
		http.MethodPut,
		"/v1/account/timezone",
		string(requestBody),
	))
	if response.Code != http.StatusOK {
		t.Fatalf("update timezone status = %d, body %s", response.Code, response.Body.String())
	}
	response = read()
	var payload map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["timezone"] != "Asia/Ho_Chi_Minh" {
		t.Fatalf("updated timezone = %q", payload["timezone"])
	}
}

func TestAccountTimezoneRejectsInvalidValue(t *testing.T) {
	s := newTOTPTestServer(t)
	for _, timezone := range []string{"", "Not/A_Real_Zone", "Local", " Asia/Bangkok"} {
		t.Run(timezone, func(t *testing.T) {
			requestBody, err := json.Marshal(map[string]string{"timezone": timezone})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			s.updateAccountTimezone(response, totpRequest(
				http.MethodPut,
				"/v1/account/timezone",
				string(requestBody),
			))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("invalid timezone status = %d, body %s", response.Code, response.Body.String())
			}
		})
	}
	var timezone string
	if err := s.db.QueryRow("SELECT timezone FROM accounts WHERE username = 'admin'").Scan(&timezone); err != nil {
		t.Fatal(err)
	}
	if timezone != "UTC" {
		t.Fatalf("invalid update stored timezone %q", timezone)
	}
}

func TestAccountTimezoneCanonicalizesLegacyAlias(t *testing.T) {
	if got := sessionTimezone(sessionInfo{timezone: "Asia/Saigon"}); got != "Asia/Ho_Chi_Minh" {
		t.Fatalf("canonical timezone = %q, want Asia/Ho_Chi_Minh", got)
	}

	s := newTOTPTestServer(t)
	response := httptest.NewRecorder()
	s.updateAccountTimezone(response, totpRequest(
		http.MethodPut,
		"/v1/account/timezone",
		`{"timezone":"Asia/Saigon"}`,
	))
	if response.Code != http.StatusOK || response.Body.String() != "{\"timezone\":\"Asia/Ho_Chi_Minh\"}\n" {
		t.Fatalf("alias update = %d %s", response.Code, response.Body.String())
	}
}

func TestProtectedPagesReceiveAccountTimezone(t *testing.T) {
	s := newTOTPTestServer(t)
	s.db.Exec("UPDATE accounts SET timezone = 'Asia/Ho_Chi_Minh' WHERE username = 'admin'")
	for _, page := range []struct {
		name  string
		serve func(http.ResponseWriter, *http.Request)
	}{
		{"audit", s.serveAudit},
		{"tokens", s.serveTokens},
		{"secret", s.serveSecrets},
	} {
		t.Run(page.name, func(t *testing.T) {
			request := totpRequest(http.MethodGet, "/"+page.name+".html", "")
			response := httptest.NewRecorder()
			page.serve(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("page status = %d", response.Code)
			}
			if !strings.Contains(response.Body.String(), `window.vaultTimezone = "Asia/Ho_Chi_Minh";`) {
				body := response.Body.String()
				start := strings.Index(body, "window.vaultTimezone")
				end := start + 120
				if start < 0 {
					start = 0
					end = 0
				}
				if end > len(body) {
					end = len(body)
				}
				t.Fatalf("%s page did not receive account timezone: %q", page.name, body[start:end])
			}
		})
	}
}

func TestAccountTimezoneRequiresHTTPS(t *testing.T) {
	s := newTOTPTestServer(t)
	request := httptest.NewRequest(http.MethodPut, "/v1/account/timezone", nil)
	request.AddCookie(totpRequest(http.MethodGet, "/v1/account/totp", "").Cookies()[0])
	response := httptest.NewRecorder()

	s.updateAccountTimezone(response, request)

	if response.Code != http.StatusUpgradeRequired {
		t.Fatalf("timezone update without HTTPS status = %d, want %d", response.Code, http.StatusUpgradeRequired)
	}
}

func TestAccountTimezoneIsStoredPerOperator(t *testing.T) {
	s := newOperatorTestServer(t)
	encoded, err := encodeSecretMounts([]string{"kv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.operatorDB.Exec(
		"INSERT INTO accounts(username, password_hash, role, secret_mounts) VALUES ('operator-one', 'hash', 'operator', ?)",
		encoded,
	); err != nil {
		t.Fatal(err)
	}
	if err := s.storeSession("operator-timezone-session", sessionInfo{
		username:  "operator-one",
		role:      "operator",
		expiresAt: time.Now().Add(time.Hour),
		ttl:       time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	request := operatorRequestWithSession(
		http.MethodPut,
		"/v1/account/timezone",
		`{"timezone":"Europe/Paris"}`,
		"operator-timezone-session",
		true,
	)
	response := httptest.NewRecorder()
	s.updateAccountTimezone(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("operator timezone update = %d, body %s", response.Code, response.Body.String())
	}

	var adminTimezone, operatorTimezone string
	if err := s.db.QueryRow("SELECT timezone FROM accounts WHERE username = 'admin'").Scan(&adminTimezone); err != nil {
		t.Fatal(err)
	}
	if err := s.operatorDB.QueryRow("SELECT timezone FROM accounts WHERE username = 'operator-one'").Scan(&operatorTimezone); err != nil {
		t.Fatal(err)
	}
	if adminTimezone != "UTC" || operatorTimezone != "Europe/Paris" {
		t.Fatalf("stored timezones: admin=%q operator=%q", adminTimezone, operatorTimezone)
	}
}
