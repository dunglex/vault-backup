package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestChangeAccountPassword(t *testing.T) {
	s := newTOTPTestServer(t)

	change := func(currentPassword, newPassword, repeatNewPassword string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]string{
			"current_password":    currentPassword,
			"new_password":        newPassword,
			"repeat_new_password": repeatNewPassword,
		})
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		s.changeAccountPassword(response, totpRequest(
			http.MethodPost,
			"/v1/account/password",
			string(body),
		))
		return response
	}

	if response := change(totpTestPassword, "new-account-password", "different-password"); response.Code != http.StatusBadRequest {
		t.Fatalf("mismatched passwords status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if response := change(totpTestPassword, "short", "short"); response.Code != http.StatusBadRequest {
		t.Fatalf("short password status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if response := change("wrong-account-password", "new-account-password", "new-account-password"); response.Code != http.StatusUnauthorized {
		t.Fatalf("incorrect current password status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if response := change(totpTestPassword, "new-account-password", "new-account-password"); response.Code != http.StatusOK {
		t.Fatalf("password change status = %d, want %d", response.Code, http.StatusOK)
	}

	var passwordHash string
	if err := s.db.QueryRow("SELECT password_hash FROM accounts WHERE username = 'admin'").Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("new-account-password")); err != nil {
		t.Fatal("new password was not stored")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(totpTestPassword)); err == nil {
		t.Fatal("old password still matches")
	}
}

func TestChangeAccountPasswordRequiresHTTPS(t *testing.T) {
	s := newTOTPTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/account/password", nil)
	request.AddCookie(totpRequest(http.MethodGet, "/v1/account/totp", "").Cookies()[0])
	response := httptest.NewRecorder()

	s.changeAccountPassword(response, request)

	if response.Code != http.StatusUpgradeRequired {
		t.Fatalf("password change without HTTPS status = %d, want %d", response.Code, http.StatusUpgradeRequired)
	}
}
