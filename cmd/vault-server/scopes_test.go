package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func insertScopedAPIToken(t *testing.T, s *server, token string, mounts []string, createdBy string) {
	t.Helper()
	encoded, err := encodeSecretMounts(mounts)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(token))
	if _, err := s.db.Exec(`
		INSERT INTO api_tokens(name, token_hash, created_at, expires_at, secret_mounts, created_by)
		VALUES (?, ?, ?, ?, ?, ?)`,
		token, hex.EncodeToString(hash[:]), time.Now().Unix(), time.Now().Add(time.Hour).Unix(),
		encoded, nullableString(createdBy),
	); err != nil {
		t.Fatal(err)
	}
}

func apiScopeRequest(method, path, body, token string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	route := strings.TrimPrefix(request.URL.Path, "/api/v1/")
	mount, remainder, _ := strings.Cut(route, "/")
	if operation, pathPart, found := strings.Cut(remainder, "/"); found && operation == "data" {
		request.SetPathValue("mount", mount)
		request.SetPathValue("path", pathPart)
	} else if operation, pathPart, found := strings.Cut(remainder, "/"); found {
		request.SetPathValue("mount", mount)
		request.SetPathValue("operation", operation)
		request.SetPathValue("path", pathPart)
	}
	return request
}

func addActiveMount(t *testing.T, s *server, name string) {
	t.Helper()
	if _, err := s.secretsDB.Exec(
		"INSERT INTO secret_mounts(name, created_at) VALUES (?, ?)", name, time.Now().Unix(),
	); err != nil {
		t.Fatal(err)
	}
}

func TestAPITokenAccessIsIsolatedByMount(t *testing.T) {
	s := newOperatorTestServer(t)
	addActiveMount(t, s, "other")
	ciphertext := testSecretCiphertext(t, s)
	insertScopedAPIToken(t, s, "kv-token", []string{"kv"}, "")
	insertTestSecretRecord(t, s.secretsDB, "kv/team-a/database", ciphertext)
	insertTestSecretRecord(t, s.secretsDB, "other/team-a/database", ciphertext)

	response := httptest.NewRecorder()
	s.getKVSecret(response, apiScopeRequest(
		http.MethodGet, "/api/v1/kv/data/team-a/database", "", "kv-token",
	))
	if response.Code != http.StatusOK {
		t.Fatalf("allowed mount read = %d, body %s", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	s.getKVSecret(response, apiScopeRequest(
		http.MethodGet, "/api/v1/other/data/team-a/database", "", "kv-token",
	))
	if response.Code != http.StatusForbidden {
		t.Fatalf("out-of-mount read = %d, body %s", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	s.putKVSecret(response, apiScopeRequest(
		http.MethodPut, "/api/v1/other/data/new-secret", `{"data":{"value":"hidden"}}`, "kv-token",
	))
	if response.Code != http.StatusForbidden {
		t.Fatalf("out-of-mount write = %d, body %s", response.Code, response.Body.String())
	}

	request := apiScopeRequest(http.MethodGet, "/api/v1/kv/metadata", "", "kv-token")
	request.SetPathValue("mount", "kv")
	response = httptest.NewRecorder()
	s.listKVMetadata(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "team-a/") ||
		strings.Contains(response.Body.String(), "other") {
		t.Fatalf("mount metadata list = %d, body %s", response.Code, response.Body.String())
	}
}

func TestOperatorAndCreatedTokensAreLimitedByExactMountGrants(t *testing.T) {
	s := newOperatorTestServer(t)
	addActiveMount(t, s, "other")
	ciphertext := testSecretCiphertext(t, s)
	encoded, err := encodeSecretMounts([]string{"kv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.operatorDB.Exec(
		"INSERT INTO accounts(username, password_hash, role, secret_mounts) VALUES ('scoped-operator', 'hash', 'operator', ?)",
		encoded,
	); err != nil {
		t.Fatal(err)
	}
	if err := s.storeSession("scoped-operator-session", sessionInfo{
		username: "scoped-operator", role: "operator", expiresAt: time.Now().Add(time.Hour), ttl: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	insertScopedAPIToken(t, s, "operator-token", []string{"kv"}, "scoped-operator")
	insertScopedAPIToken(t, s, "admin-token", []string{"kv"}, "admin")
	insertTestSecretRecord(t, s.secretsDB, "kv/unrelated/path", ciphertext)
	insertTestSecretRecord(t, s.secretsDB, "other/unrelated/path", ciphertext)

	tokenList := httptest.NewRecorder()
	s.listAPITokens(tokenList, operatorRequestWithSession(
		http.MethodGet, "/v1/tokens", "", "scoped-operator-session", true,
	))
	if tokenList.Code != http.StatusOK || !strings.Contains(tokenList.Body.String(), "operator-token") ||
		strings.Contains(tokenList.Body.String(), "admin-token") {
		t.Fatalf("operator token list = %d, body %s", tokenList.Code, tokenList.Body.String())
	}

	var adminTokenID string
	if err := s.db.QueryRow("SELECT id FROM api_tokens WHERE name = 'admin-token'").Scan(&adminTokenID); err != nil {
		t.Fatal(err)
	}
	updateRequest := operatorRequestWithSession(
		http.MethodPut, "/v1/tokens/"+adminTokenID+"/mounts", `{"mounts":["kv"]}`, "scoped-operator-session", true,
	)
	updateRequest.SetPathValue("id", adminTokenID)
	response := httptest.NewRecorder()
	s.updateAPITokenSecretMounts(response, updateRequest)
	if response.Code != http.StatusNotFound {
		t.Fatalf("operator updated another user's token = %d, body %s", response.Code, response.Body.String())
	}
	revokeRequest := operatorRequestWithSession(
		http.MethodDelete, "/v1/tokens/"+adminTokenID, "", "scoped-operator-session", true,
	)
	revokeRequest.SetPathValue("id", adminTokenID)
	response = httptest.NewRecorder()
	s.revokeAPIToken(response, revokeRequest)
	if response.Code != http.StatusNotFound {
		t.Fatalf("operator revoked another user's token = %d, body %s", response.Code, response.Body.String())
	}
	certificateRequest := operatorRequestWithSession(
		http.MethodPost, "/v1/tokens/"+adminTokenID+"/certificate", "", "scoped-operator-session", true,
	)
	certificateRequest.SetPathValue("id", adminTokenID)
	response = httptest.NewRecorder()
	s.issueAPITokenCertificate(response, certificateRequest)
	if response.Code != http.StatusNotFound {
		t.Fatalf("operator issued a certificate for another user's token = %d, body %s", response.Code, response.Body.String())
	}

	webRequest := httptest.NewRequest(http.MethodGet, "/secrets?mount=kv", nil)
	webRequest.AddCookie(&http.Cookie{Name: "vault_session", Value: "scoped-operator-session"})
	response = httptest.NewRecorder()
	s.listSecrets(response, webRequest)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "unrelated/path") {
		t.Fatalf("operator list for granted mount = %d, body %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "other") {
		t.Fatalf("operator list exposed another mount: %s", response.Body.String())
	}

	response = httptest.NewRecorder()
	s.getKVSecret(response, apiScopeRequest(
		http.MethodGet, "/api/v1/kv/data/unrelated/path", "", "operator-token",
	))
	if response.Code != http.StatusOK {
		t.Fatalf("operator-created token could not access its granted mount: %d %s", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	s.getKVSecret(response, apiScopeRequest(
		http.MethodGet, "/api/v1/other/data/unrelated/path", "", "operator-token",
	))
	if response.Code != http.StatusForbidden {
		t.Fatalf("operator-created token escaped owner mount grant: %d %s", response.Code, response.Body.String())
	}

	if _, err := s.operatorDB.Exec(
		"UPDATE accounts SET secret_mounts = ? WHERE username = 'scoped-operator'", mustEncodeMounts(t, "other"),
	); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	s.getKVSecret(response, apiScopeRequest(
		http.MethodGet, "/api/v1/kv/data/unrelated/path", "", "operator-token",
	))
	if response.Code != http.StatusForbidden {
		t.Fatalf("token retained access after operator grant removal: %d %s", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	s.getKVSecret(response, apiScopeRequest(
		http.MethodGet, "/api/v1/other/data/unrelated/path", "", "operator-token",
	))
	if response.Code != http.StatusForbidden {
		t.Fatalf("token scope was implicitly expanded with operator grant: %d %s", response.Code, response.Body.String())
	}
}

func testSecretCiphertext(t *testing.T, s *server) string {
	t.Helper()
	aead, err := newDatabaseAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.secretsAEAD = aead
	ciphertext, err := s.encryptSecret([]byte(`{"value":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func mustEncodeMounts(t *testing.T, mounts ...string) string {
	t.Helper()
	encoded, err := encodeSecretMounts(mounts)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestMountGrantNormalizationUsesExactNames(t *testing.T) {
	mounts, err := normalizeSecretMounts([]string{"apps/cma", "kv", "apps/cma"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 || mounts[0] != "apps/cma" || mounts[1] != "kv" {
		t.Fatalf("normalized mounts = %v, want duplicate-free mount names", mounts)
	}
	access := secretMountAccess{mounts: mounts}
	if !access.allows("apps/cma") || access.allows("apps") {
		t.Fatalf("mount access must match exact mount names: %#v", access)
	}
}

func TestDecodeSecretMountsRejectsMalformedScope(t *testing.T) {
	if _, err := decodeSecretMounts(`["kv","../other"]`); err == nil {
		t.Fatal("invalid mount grant was accepted")
	}
	if _, err := decodeSecretMounts("not-json"); err == nil {
		t.Fatal("malformed mount grant was accepted")
	}
}
