package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOperatorAuditEventsAreFilteredBySecretMounts(t *testing.T) {
	s := newOperatorTestServer(t)
	mounts, err := encodeSecretMounts([]string{"kv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.operatorDB.Exec(
		"INSERT INTO accounts(username, password_hash, role, secret_mounts) VALUES ('scoped-operator', 'hash', 'operator', ?)",
		mounts,
	); err != nil {
		t.Fatal(err)
	}
	if err := s.storeSession("scoped-operator-session", sessionInfo{
		username: "scoped-operator", role: "operator", expiresAt: time.Now().Add(time.Hour), ttl: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, 'true')",
		operatorAuditSetting,
	); err != nil {
		t.Fatal(err)
	}

	auditStore, err := openAnnualAuditStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	s.auditStore = auditStore

	now := time.Now().UTC().Unix()
	events := []struct {
		action   string
		actor    string
		source   string
		resource string
	}{
		{"read", "operator-token", "web", "kv/team-a/database"},
		{"read", "operator-token", "web", "kv-archive/database"},
		{"read", "api-token:abc123", "api", "kv/team-a/database"},
		{"read", "api-token:def456", "api", "other/team-b/database"},
		{"list", "api-token:abc123", "api", ""},
		{"list", "scoped-operator", "web", "*"},
		{"list", "other-operator", "web", "*"},
		{"login", "other-operator", "web", ""},
	}
	for _, event := range events {
		if err := auditStore.Record(
			now, event.action, "success", event.actor, "127.0.0.1",
			event.source, event.resource, "",
		); err != nil {
			t.Fatal(err)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/audit?year="+time.Now().UTC().Format("2006"), nil)
	request.AddCookie(&http.Cookie{Name: "vault_session", Value: "scoped-operator-session"})
	response := httptest.NewRecorder()
	s.listAuditEvents(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("operator audit status = %d, body %s", response.Code, response.Body.String())
	}
	var result struct {
		Events []struct {
			Action   string `json:"action"`
			Actor    string `json:"actor"`
			Resource string `json:"resource"`
		} `json:"events"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 4 || len(result.Events) != 4 {
		t.Fatalf("operator audit total/events = %d/%d, want 4/4: %s", result.Total, len(result.Events), response.Body.String())
	}
	visibleResources := map[string]bool{}
	for _, event := range result.Events {
		visibleResources[event.Resource] = true
	}
	for _, resource := range []string{"kv/team-a/database", "", "*"} {
		if !visibleResources[resource] {
			t.Errorf("operator audit omitted allowed resource %q", resource)
		}
	}

	hiddenSearch := httptest.NewRequest(http.MethodGet, "/v1/audit?year="+time.Now().UTC().Format("2006")+"&q=other", nil)
	hiddenSearch.AddCookie(&http.Cookie{Name: "vault_session", Value: "scoped-operator-session"})
	hiddenResponse := httptest.NewRecorder()
	s.listAuditEvents(hiddenResponse, hiddenSearch)
	if hiddenResponse.Code != http.StatusOK || !json.Valid(hiddenResponse.Body.Bytes()) {
		t.Fatalf("scoped audit search response = %d, body %s", hiddenResponse.Code, hiddenResponse.Body.String())
	}
	if err := json.Unmarshal(hiddenResponse.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 0 || len(result.Events) != 0 {
		t.Fatalf("out-of-scope audit search returned %d events", result.Total)
	}

	adminRequest := httptest.NewRequest(http.MethodGet, "/v1/audit?year="+time.Now().UTC().Format("2006"), nil)
	adminRequest.AddCookie(&http.Cookie{Name: "vault_session", Value: "admin-session"})
	adminResponse := httptest.NewRecorder()
	s.listAuditEvents(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("admin audit status = %d, body %s", adminResponse.Code, adminResponse.Body.String())
	}
	if err := json.Unmarshal(adminResponse.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != len(events) {
		t.Fatalf("admin audit total = %d, want %d", result.Total, len(events))
	}

	yearsRequest := httptest.NewRequest(http.MethodGet, "/v1/audit/years", nil)
	yearsRequest.AddCookie(&http.Cookie{Name: "vault_session", Value: "scoped-operator-session"})
	yearsResponse := httptest.NewRecorder()
	s.listAuditYears(yearsResponse, yearsRequest)
	if yearsResponse.Code != http.StatusOK || !json.Valid(yearsResponse.Body.Bytes()) {
		t.Fatalf("operator audit years response = %d, body %s", yearsResponse.Code, yearsResponse.Body.String())
	}
}

func TestOperatorAuditRequiresSecuritySetting(t *testing.T) {
	s := newOperatorTestServer(t)
	mounts, err := encodeSecretMounts([]string{"kv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.operatorDB.Exec(
		"INSERT INTO accounts(username, password_hash, role, secret_mounts) VALUES ('audit-operator', 'hash', 'operator', ?)",
		mounts,
	); err != nil {
		t.Fatal(err)
	}
	if err := s.storeSession("audit-operator-session", sessionInfo{
		username: "audit-operator", role: "operator", expiresAt: time.Now().Add(time.Hour), ttl: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	auditStore, err := openAnnualAuditStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	s.auditStore = auditStore
	if err := auditStore.Record(
		time.Now().UTC().Unix(), "read", "success", "audit-operator", "127.0.0.1",
		"web", "kv/team-a/database", "",
	); err != nil {
		t.Fatal(err)
	}

	settingsResponse := httptest.NewRecorder()
	s.getSettings(settingsResponse, operatorRequestWithSession(http.MethodGet, "/v1/settings", "", "admin-session", true))
	if settingsResponse.Code != http.StatusOK || !strings.Contains(settingsResponse.Body.String(), `"allow_operator_audit":false`) {
		t.Fatalf("default operator audit setting = %d, body %s", settingsResponse.Code, settingsResponse.Body.String())
	}

	operatorRequest := func(path string) *http.Request {
		return operatorRequestWithSession(http.MethodGet, path, "", "audit-operator-session", true)
	}
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		path    string
	}{
		{"audit events API", s.listAuditEvents, "/v1/audit"},
		{"audit years API", s.listAuditYears, "/v1/audit/years"},
		{"audit page", s.serveAudit, "/audits.html"},
	} {
		response := httptest.NewRecorder()
		test.handler.ServeHTTP(response, operatorRequest(test.path))
		if response.Code != http.StatusForbidden {
			t.Errorf("%s status = %d, want %d; body %s", test.name, response.Code, http.StatusForbidden, response.Body.String())
		}
	}

	secretsPage := httptest.NewRecorder()
	s.serveProtectedPage(secretsPage, operatorRequest("/secrets.html"), "secrets.gohtml")
	if secretsPage.Code != http.StatusOK || strings.Contains(secretsPage.Body.String(), `href="/audits.html"`) {
		t.Fatalf("audit link should be hidden before enabling: status %d, body contains link=%t", secretsPage.Code, strings.Contains(secretsPage.Body.String(), `href="/audits.html"`))
	}

	enableResponse := httptest.NewRecorder()
	s.updateSettings(enableResponse, operatorRequestWithSession(
		http.MethodPut,
		"/v1/settings",
		`{"allow_operator_audit":true}`,
		"admin-session",
		true,
	))
	if enableResponse.Code != http.StatusOK || !strings.Contains(enableResponse.Body.String(), `"allow_operator_audit":true`) {
		t.Fatalf("enable operator audit = %d, body %s", enableResponse.Code, enableResponse.Body.String())
	}

	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		path    string
	}{
		{"audit events API", s.listAuditEvents, "/v1/audit"},
		{"audit years API", s.listAuditYears, "/v1/audit/years"},
		{"audit page", s.serveAudit, "/audits.html"},
	} {
		response := httptest.NewRecorder()
		test.handler.ServeHTTP(response, operatorRequest(test.path))
		if response.Code != http.StatusOK {
			t.Errorf("%s status = %d, want %d; body %s", test.name, response.Code, http.StatusOK, response.Body.String())
		}
	}

	secretsPage = httptest.NewRecorder()
	s.serveProtectedPage(secretsPage, operatorRequest("/secrets.html"), "secrets.gohtml")
	if secretsPage.Code != http.StatusOK || !strings.Contains(secretsPage.Body.String(), `href="/audits.html"`) {
		t.Fatalf("audit link should be visible after enabling: status %d, body contains link=%t", secretsPage.Code, strings.Contains(secretsPage.Body.String(), `href="/audits.html"`))
	}
}

func TestOperatorAuditSettingIsVisibleOnlyWhenExtensionIsEnabled(t *testing.T) {
	s := newOperatorTestServer(t)
	renderSecurity := func() *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		s.serveAdminProtectedPage(response, operatorRequestWithSession(
			http.MethodGet,
			"/security.html",
			"",
			"admin-session",
			true,
		), "security.gohtml")
		return response
	}

	enabled := renderSecurity()
	if enabled.Code != http.StatusOK || !strings.Contains(enabled.Body.String(), "Allow Operator to audit") {
		t.Fatalf("operator audit setting should be visible with extension enabled: status %d, body %s", enabled.Code, enabled.Body.String())
	}

	s.operatorDB = nil
	disabled := renderSecurity()
	if disabled.Code != http.StatusOK || strings.Contains(disabled.Body.String(), "Allow Operator to audit") {
		t.Fatalf("operator audit setting should be hidden without extension: status %d, body %s", disabled.Code, disabled.Body.String())
	}

	update := httptest.NewRecorder()
	s.updateSettings(update, operatorRequestWithSession(
		http.MethodPut,
		"/v1/settings",
		`{"allow_operator_audit":true}`,
		"admin-session",
		true,
	))
	if update.Code != http.StatusBadRequest {
		t.Fatalf("enable operator audit without extension = %d, want %d; body %s", update.Code, http.StatusBadRequest, update.Body.String())
	}
}
