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

func TestMountCreationRejectsAncestorAndDescendantConflicts(t *testing.T) {
	s := newOperatorTestServer(t)

	create := func(name string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		s.createMount(response, operatorRequestWithSession(
			http.MethodPost, "/v1/mounts", `{"name":"`+name+`"}`, "admin-session", true,
		))
		return response
	}
	if response := create("apps/cma"); response.Code != http.StatusCreated {
		t.Fatalf("create nested mount = %d, body %s", response.Code, response.Body.String())
	}
	for _, conflict := range []string{"apps", "apps/cma"} {
		if response := create(conflict); response.Code != http.StatusConflict {
			t.Errorf("create conflicting mount %q = %d, body %s", conflict, response.Code, response.Body.String())
		}
	}
	if response := create("apps/cma2"); response.Code != http.StatusCreated {
		t.Fatalf("create non-overlapping sibling mount = %d, body %s", response.Code, response.Body.String())
	}
}

func TestMountsPageCreatesEnginesInDialog(t *testing.T) {
	var page strings.Builder
	if err := pageTemplate.ExecuteTemplate(&page, "mounts.gohtml", map[string]bool{
		"IsAdmin":      true,
		"HasOperators": true,
		"HasBackup":    true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		`id="openCreateEngine"`,
		`<dialog id="createEngineDialog"`,
		`id="enginePath"`,
		`createEngineDialog.showModal()`,
		`<th>Engine</th><th>Status</th><th>Actions</th>`,
		`<tbody id="mountList"`,
	} {
		if !strings.Contains(page.String(), marker) {
			t.Errorf("engines page missing %q", marker)
		}
	}
	if strings.Contains(page.String(), `id="createMountForm"`) {
		t.Error("engine creation form should be inside a dialog")
	}
	if strings.Contains(page.String(), "Existing engines") {
		t.Error("engines page should not render an Existing engines heading")
	}
}

func TestMountRouteAndSoftDeleteRestoreDoNotRestoreGrants(t *testing.T) {
	s := newOperatorTestServer(t)
	mount := "apps/cma"
	if _, err := s.secretsDB.Exec(
		"INSERT INTO secret_mounts(name, created_at) VALUES (?, ?)", mount, time.Now().Unix(),
	); err != nil {
		t.Fatal(err)
	}
	mounts := mustEncodeMounts(t, mount)
	if _, err := s.operatorDB.Exec(
		"INSERT INTO accounts(username, password_hash, role, secret_mounts) VALUES ('mount-operator', 'hash', 'operator', ?)",
		mounts,
	); err != nil {
		t.Fatal(err)
	}
	insertScopedAPIToken(t, s, "mount-token", []string{mount}, "")
	aead, err := newDatabaseAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.secretsAEAD = aead
	ciphertext, err := s.encryptSecret([]byte(`{"value":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	insertTestSecretRecord(t, s.secretsDB, mount+"/secret", ciphertext)

	apiRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/apps/cma/data/secret", nil)
		request.Header.Set("Authorization", "Bearer mount-token")
		request.SetPathValue("route", "apps/cma/data/secret")
		return request
	}
	response := httptest.NewRecorder()
	s.routeKVAPI(response, apiRequest())
	if response.Code != http.StatusOK {
		t.Fatalf("nested mount read = %d, body %s", response.Code, response.Body.String())
	}

	deleteRequest := func() *http.Request {
		return operatorRequestWithSession(http.MethodPost, "/v1/mounts/delete", `{"name":"apps/cma"}`, "admin-session", true)
	}
	deleted := httptest.NewRecorder()
	s.softDeleteMount(deleted, deleteRequest())
	if deleted.Code != http.StatusOK {
		t.Fatalf("soft-delete mount = %d, body %s", deleted.Code, deleted.Body.String())
	}

	var tokenMounts, operatorMounts string
	if err := s.db.QueryRow("SELECT secret_mounts FROM api_tokens WHERE name = 'mount-token'").Scan(&tokenMounts); err != nil {
		t.Fatal(err)
	}
	if err := s.operatorDB.QueryRow("SELECT secret_mounts FROM accounts WHERE username = 'mount-operator'").Scan(&operatorMounts); err != nil {
		t.Fatal(err)
	}
	if tokenMounts != "[]" || operatorMounts != "[]" {
		t.Fatalf("mount grants after deletion = token %s, operator %s; want empty", tokenMounts, operatorMounts)
	}
	response = httptest.NewRecorder()
	s.routeKVAPI(response, apiRequest())
	if response.Code != http.StatusNotFound {
		t.Fatalf("deleted mount route = %d, want not found", response.Code)
	}

	restored := httptest.NewRecorder()
	s.restoreMount(restored, operatorRequestWithSession(
		http.MethodPost, "/v1/mounts/restore", `{"name":"apps/cma"}`, "admin-session", true,
	))
	if restored.Code != http.StatusOK {
		t.Fatalf("restore mount = %d, body %s", restored.Code, restored.Body.String())
	}
	response = httptest.NewRecorder()
	s.routeKVAPI(response, apiRequest())
	if response.Code != http.StatusForbidden {
		t.Fatalf("restored mount kept old token grant: %d, body %s", response.Code, response.Body.String())
	}
	var restoredTokenMounts string
	if err := s.db.QueryRow("SELECT secret_mounts FROM api_tokens WHERE name = 'mount-token'").Scan(&restoredTokenMounts); err != nil {
		t.Fatal(err)
	}
	if restoredTokenMounts != "[]" {
		t.Fatalf("restored token grants = %s, want empty", restoredTokenMounts)
	}
}

func TestSoftDeleteMissingMountDoesNotChangeGrants(t *testing.T) {
	s := newOperatorTestServer(t)
	insertScopedAPIToken(t, s, "kv-token", []string{"kv"}, "")
	response := httptest.NewRecorder()
	s.softDeleteMount(response, operatorRequestWithSession(
		http.MethodPost, "/v1/mounts/delete", `{"name":"missing"}`, "admin-session", true,
	))
	if response.Code != http.StatusNotFound {
		t.Fatalf("delete missing mount = %d, body %s", response.Code, response.Body.String())
	}
	var mounts string
	if err := s.db.QueryRow("SELECT secret_mounts FROM api_tokens WHERE token_hash = ?", tokenHash("kv-token")).Scan(&mounts); err != nil {
		t.Fatal(err)
	}
	if mounts != `["kv"]` {
		t.Fatalf("missing mount altered token grant: %s", mounts)
	}
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func TestMountDataIsStoredInMountQualifiedNamespace(t *testing.T) {
	s := newOperatorTestServer(t)
	addActiveMount(t, s, "apps/cma")
	insertScopedAPIToken(t, s, "apps-token", []string{"apps/cma"}, "")
	aead, err := newDatabaseAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.secretsAEAD = aead
	request := httptest.NewRequest(
		http.MethodPut, "/api/v1/apps/cma/data/service/secret", strings.NewReader(`{"data":{"key":"value"}}`),
	)
	request.Header.Set("Authorization", "Bearer apps-token")
	request.SetPathValue("route", "apps/cma/data/service/secret")
	response := httptest.NewRecorder()
	s.routeKVAPI(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("write nested mount secret = %d, body %s", response.Code, response.Body.String())
	}
	var exists int
	if err := s.secretsDB.QueryRow("SELECT EXISTS(SELECT 1 FROM secrets WHERE path = 'apps/cma/service/secret')").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != 1 {
		t.Fatal("secret was not stored under its mount-qualified key")
	}
	if err := s.secretsDB.QueryRow("SELECT EXISTS(SELECT 1 FROM secrets WHERE path = 'service/secret')").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != 0 {
		t.Fatal("secret was also stored in the shared unqualified namespace")
	}
}
