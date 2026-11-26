package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestOperatorAuditEventsAreFilteredBySecretPrefixes(t *testing.T) {
	s := newOperatorTestServer(t)
	prefixes, err := encodeSecretPrefixes([]string{"team-a", "kv/team-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		"INSERT INTO accounts(username, password_hash, role, secret_prefixes) VALUES ('scoped-operator', 'hash', 'operator', ?)",
		prefixes,
	); err != nil {
		t.Fatal(err)
	}
	if err := s.storeSession("scoped-operator-session", sessionInfo{
		username: "scoped-operator", role: "operator", expiresAt: time.Now().Add(time.Hour), ttl: time.Hour,
	}); err != nil {
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
		{"read", "operator-token", "web", "team-a/database"},
		{"read", "operator-token", "web", "team-a-archive/database"},
		{"read", "api-token:abc123", "api", "kv/team-a/database"},
		{"read", "api-token:def456", "api", "kv/team-b/database"},
		{"list", "api-token:abc123", "api", "kv"},
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
	for _, resource := range []string{"team-a/database", "kv/team-a/database", "kv", "*"} {
		if !visibleResources[resource] {
			t.Errorf("operator audit omitted allowed resource %q", resource)
		}
	}

	hiddenSearch := httptest.NewRequest(http.MethodGet, "/v1/audit?year="+time.Now().UTC().Format("2006")+"&q=team-b", nil)
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
