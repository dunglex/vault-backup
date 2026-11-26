package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func insertScopedAPIToken(t *testing.T, s *server, token string, prefixes []string, createdBy string) {
	t.Helper()
	encodedPrefixes, err := encodeSecretPrefixes(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(token))
	var owner any
	if createdBy != "" {
		owner = createdBy
	}
	_, err = s.db.Exec(
		"INSERT INTO api_tokens(name, token_hash, created_at, expires_at, secret_prefixes, created_by) VALUES (?, ?, ?, ?, ?, ?)",
		"scope-test", hex.EncodeToString(hash[:]), time.Now().Unix(), time.Now().Add(time.Hour).Unix(), encodedPrefixes, owner,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func apiScopeRequest(method, path, body, token string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("X-Vault-Token", token)
	request.SetPathValue("mount", "kv")
	if strings.HasPrefix(path, "/api/v1/kv/metadata") {
		request.SetPathValue("path", strings.TrimPrefix(strings.TrimPrefix(path, "/api/v1/kv/metadata"), "/"))
	} else {
		request.SetPathValue("path", strings.TrimPrefix(strings.TrimPrefix(path, "/api/v1/kv/data"), "/"))
	}
	return request
}

func TestAPITokenScopesRestrictCRUDAndFilterList(t *testing.T) {
	s := newOperatorTestServer(t)
	var err error
	s.secretsAEAD, err = newDatabaseAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	const token = "scope-test-token"
	insertScopedAPIToken(t, s, token, []string{"team-a", "shared/build"}, "")
	if _, err := s.secretsDB.Exec(
		"INSERT INTO secrets(path, data) VALUES (?, ?)",
		"team-b/hidden", "unused",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := s.secretsDB.Exec(
		"INSERT INTO secrets(path, data) VALUES (?, ?)",
		"shared/build/visible", "unused",
	); err != nil {
		t.Fatal(err)
	}

	write := httptest.NewRecorder()
	s.putKVSecret(write, apiScopeRequest(
		http.MethodPut, "/api/v1/kv/data/team-a/database", `{"data":{"username":"alice"}}`, token,
	))
	if write.Code != http.StatusOK {
		t.Fatalf("allowed API write status = %d, body %s", write.Code, write.Body.String())
	}
	var storedPath string
	if err := s.secretsDB.QueryRow(
		"SELECT path FROM secrets WHERE path = ?",
		"team-a/database",
	).Scan(&storedPath); err != nil {
		t.Fatalf("secret was not stored without mount prefix: %v", err)
	}

	read := httptest.NewRecorder()
	s.getKVSecret(read, apiScopeRequest(http.MethodGet, "/api/v1/kv/data/team-a/database", "", token))
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"username":"alice"`) {
		t.Fatalf("allowed API read = %d, body %s", read.Code, read.Body.String())
	}
	otherMountRequest := httptest.NewRequest(http.MethodGet, "/api/v1/other/data/team-a/database", nil)
	otherMountRequest.Header.Set("X-Vault-Token", token)
	otherMountRequest.SetPathValue("mount", "other")
	otherMountRequest.SetPathValue("path", "team-a/database")
	otherMountRead := httptest.NewRecorder()
	s.getKVSecret(otherMountRead, otherMountRequest)
	if otherMountRead.Code != http.StatusOK || !strings.Contains(otherMountRead.Body.String(), `"username":"alice"`) {
		t.Fatalf("same secret through another mount = %d, body %s", otherMountRead.Code, otherMountRead.Body.String())
	}

	outOfScope := httptest.NewRecorder()
	s.putKVSecret(outOfScope, apiScopeRequest(
		http.MethodPut, "/api/v1/kv/data/team-archive/database", `{"data":{"username":"bob"}}`, token,
	))
	if outOfScope.Code != http.StatusForbidden {
		t.Fatalf("segment-boundary denial status = %d, want %d", outOfScope.Code, http.StatusForbidden)
	}

	list := httptest.NewRecorder()
	s.listKVMetadata(list, apiScopeRequest(http.MethodGet, "/api/v1/kv/metadata", "", token))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"team-a"`) ||
		!strings.Contains(list.Body.String(), `"shared"`) || strings.Contains(list.Body.String(), `"team-b"`) {
		t.Fatalf("scoped API list = %d, body %s", list.Code, list.Body.String())
	}

	delete := httptest.NewRecorder()
	s.deleteKVSecret(delete, apiScopeRequest(http.MethodDelete, "/api/v1/kv/data/team-a/database", "", token))
	if delete.Code != http.StatusNoContent {
		t.Fatalf("allowed API delete status = %d, body %s", delete.Code, delete.Body.String())
	}
}

func TestOperatorScopesRestrictWebSecretsAndLegacyEmptyScopesDeny(t *testing.T) {
	s := newOperatorTestServer(t)
	aead, err := newDatabaseAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.secretsAEAD = aead
	encrypted, err := s.encryptSecret([]byte(`{"password":"test-value"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.secretsDB.Exec(
		"INSERT INTO secrets(path, data) VALUES ('team-a/database', ?), ('team-b/database', ?)",
		encrypted, encrypted,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := s.operatorDB.Exec(
		"INSERT INTO accounts(username, password_hash, role) VALUES ('legacy-operator', 'hash', 'operator')",
	); err != nil {
		t.Fatal(err)
	}
	if err := s.storeSession("operator-session", sessionInfo{
		username: "legacy-operator", role: "operator", expiresAt: time.Now().Add(time.Hour), ttl: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.storeSession("admin-session-two", sessionInfo{
		username: "admin", role: "admin", expiresAt: time.Now().Add(time.Hour), ttl: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/secrets/team-a/database", nil)
	request.SetPathValue("path", "team-a/database")
	request.AddCookie(&http.Cookie{Name: "vault_session", Value: "operator-session"})
	denied := httptest.NewRecorder()
	s.getSecret(denied, request)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("legacy operator access status = %d, want %d", denied.Code, http.StatusForbidden)
	}

	prefixes, err := encodeSecretPrefixes([]string{"team-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.operatorDB.Exec("UPDATE accounts SET secret_prefixes = ? WHERE username = 'legacy-operator'", prefixes); err != nil {
		t.Fatal(err)
	}

	operatorList := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/secrets", nil)
	listRequest.AddCookie(&http.Cookie{Name: "vault_session", Value: "operator-session"})
	s.listSecrets(operatorList, listRequest)
	if operatorList.Code != http.StatusOK || strings.Contains(operatorList.Body.String(), "team-b") ||
		!strings.Contains(operatorList.Body.String(), "team-a/database") {
		t.Fatalf("operator secret list = %d, body %s", operatorList.Code, operatorList.Body.String())
	}
	allowed := httptest.NewRecorder()
	allowedRequest := httptest.NewRequest(http.MethodGet, "/v1/secrets/team-a/database", nil)
	allowedRequest.SetPathValue("path", "team-a/database")
	allowedRequest.AddCookie(&http.Cookie{Name: "vault_session", Value: "operator-session"})
	s.getSecret(allowed, allowedRequest)
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"password":"test-value"`) {
		t.Fatalf("operator allowed read = %d, body %s", allowed.Code, allowed.Body.String())
	}

	outOfScope := httptest.NewRecorder()
	outRequest := httptest.NewRequest(http.MethodGet, "/v1/secrets/team-archive/database", nil)
	outRequest.SetPathValue("path", "team-archive/database")
	outRequest.AddCookie(&http.Cookie{Name: "vault_session", Value: "operator-session"})
	s.getSecret(outOfScope, outRequest)
	if outOfScope.Code != http.StatusForbidden {
		t.Fatalf("operator segment-boundary status = %d, want %d", outOfScope.Code, http.StatusForbidden)
	}

	adminResponse := httptest.NewRecorder()
	adminRequest := httptest.NewRequest(http.MethodGet, "/v1/secrets/team-b/database", nil)
	adminRequest.SetPathValue("path", "team-b/database")
	adminRequest.AddCookie(&http.Cookie{Name: "vault_session", Value: "admin-session-two"})
	s.getSecret(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("admin unrestricted path status = %d, want %d", adminResponse.Code, http.StatusOK)
	}
}

func TestOperatorScopesConstrainCreatedTokensAfterScopeChanges(t *testing.T) {
	s := newOperatorTestServer(t)
	createdOperator := httptest.NewRecorder()
	s.createOperator(createdOperator, operatorRequestWithSession(
		http.MethodPost, "/v1/operators",
		`{"username":"scoped-operator","prefixes":["team-a"]}`,
		"admin-session", true,
	))
	if createdOperator.Code != http.StatusCreated {
		t.Fatalf("create operator status = %d, body %s", createdOperator.Code, createdOperator.Body.String())
	}
	if err := s.storeSession("scoped-operator-session", sessionInfo{
		username: "scoped-operator", role: "operator", expiresAt: time.Now().Add(time.Hour), ttl: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	emptyScopes := httptest.NewRecorder()
	s.createAPIToken(emptyScopes, operatorRequestWithSession(
		http.MethodPost, "/v1/tokens",
		`{"name":"unscoped-token"}`,
		"scoped-operator-session", true,
	))
	if emptyScopes.Code != http.StatusBadRequest {
		t.Fatalf("create token without scopes status = %d, want %d", emptyScopes.Code, http.StatusBadRequest)
	}
	outOfOperatorScope := httptest.NewRecorder()
	s.createAPIToken(outOfOperatorScope, operatorRequestWithSession(
		http.MethodPost, "/v1/tokens",
		`{"name":"broad-token","prefixes":["team-b"]}`,
		"scoped-operator-session", true,
	))
	if outOfOperatorScope.Code != http.StatusForbidden {
		t.Fatalf("create token outside operator scope status = %d, want %d", outOfOperatorScope.Code, http.StatusForbidden)
	}

	createToken := httptest.NewRecorder()
	s.createAPIToken(createToken, operatorRequestWithSession(
		http.MethodPost, "/v1/tokens",
		`{"name":"operator-token","prefixes":["team-a/private"]}`,
		"scoped-operator-session", true,
	))
	if createToken.Code != http.StatusCreated {
		t.Fatalf("create scoped token status = %d, body %s", createToken.Code, createToken.Body.String())
	}
	var tokenResponse struct {
		ID    int64  `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(createToken.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatal(err)
	}

	updateOutOfOperatorScope := httptest.NewRecorder()
	updateOutOfScopeRequest := operatorRequestWithSession(
		http.MethodPut, "/v1/tokens/"+strconv.FormatInt(tokenResponse.ID, 10)+"/prefixes",
		`{"prefixes":["team-b"]}`,
		"scoped-operator-session", true,
	)
	updateOutOfScopeRequest.SetPathValue("id", strconv.FormatInt(tokenResponse.ID, 10))
	s.updateAPITokenSecretPrefixes(updateOutOfOperatorScope, updateOutOfScopeRequest)
	if updateOutOfOperatorScope.Code != http.StatusForbidden {
		t.Fatalf("update token outside operator scope status = %d, want %d", updateOutOfOperatorScope.Code, http.StatusForbidden)
	}

	updateToken := httptest.NewRecorder()
	updateTokenRequest := operatorRequestWithSession(
		http.MethodPut, "/v1/tokens/"+strconv.FormatInt(tokenResponse.ID, 10)+"/prefixes",
		`{"prefixes":["team-a/private/only"]}`,
		"admin-session", true,
	)
	updateTokenRequest.SetPathValue("id", strconv.FormatInt(tokenResponse.ID, 10))
	s.updateAPITokenSecretPrefixes(updateToken, updateTokenRequest)
	if updateToken.Code != http.StatusOK {
		t.Fatalf("admin update token scopes status = %d, body %s", updateToken.Code, updateToken.Body.String())
	}

	updateOperator := httptest.NewRecorder()
	s.updateOperatorSecretPrefixes(updateOperator, operatorRequestWithSession(
		http.MethodPut, "/v1/operators/prefixes",
		`{"username":"scoped-operator","prefixes":["team-a/private"]}`,
		"admin-session", true,
	))
	if updateOperator.Code != http.StatusOK {
		t.Fatalf("update operator scopes status = %d, body %s", updateOperator.Code, updateOperator.Body.String())
	}

	access, ok := s.apiSecretAccessForRequest(httptest.NewRecorder(), apiScopeRequest(
		http.MethodGet, "/api/v1/kv/data/team-a/private/only/secret", "", tokenResponse.Token,
	))
	if !ok || !access.allows("team-a/private/only/secret") || access.allows("team-a/private/other") {
		t.Fatalf("operator token effective access = %#v, authorized=%v", access, ok)
	}
}

func TestPrefixValidationRequiresValidPaths(t *testing.T) {
	for _, invalid := range [][]string{nil, {}, {"team_a"}, {"team-a/"}, {strings.Repeat("a", 128)}} {
		if _, err := normalizeSecretPrefixes(invalid); err == nil {
			t.Errorf("normalizeSecretPrefixes(%q) succeeded, want error", invalid)
		}
	}
	got, err := normalizeSecretPrefixes([]string{" team-a ", "team-a", "shared/build"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "team-a" || got[1] != "shared/build" {
		t.Fatalf("normalized prefixes = %#v", got)
	}
}

func TestExistingTokenWithEmptyScopeIsDenied(t *testing.T) {
	s := newOperatorTestServer(t)
	const token = "legacy-token"
	insertScopedAPIToken(t, s, token, []string{}, "")

	response := httptest.NewRecorder()
	s.getKVSecret(response, apiScopeRequest(http.MethodGet, "/api/v1/kv/data/team-a/key", "", token))
	if response.Code != http.StatusForbidden {
		t.Fatalf("empty-scope token status = %d, want %d; body %s", response.Code, http.StatusForbidden, response.Body.String())
	}
}
