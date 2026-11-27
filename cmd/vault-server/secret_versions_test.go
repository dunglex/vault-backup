package main

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func insertTestSecretRecord(t *testing.T, db *sql.DB, path, ciphertext string) {
	t.Helper()
	now := time.Now().UTC().Unix()
	if _, err := db.Exec(
		"INSERT INTO secrets(path, current_version, created_at, updated_at) VALUES (?, 1, ?, ?)",
		path, now, now,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		"INSERT INTO secret_versions(path, version, data, created_at) VALUES (?, 1, ?, ?)",
		path, ciphertext, now,
	); err != nil {
		t.Fatal(err)
	}
}

func assertSecretAuditDetail(t *testing.T, s *server, action, expected string) {
	t.Helper()
	var detail string
	err := s.auditStore.withYear(time.Now().UTC().Year(), func(db *sql.DB) error {
		return db.QueryRow(
			"SELECT detail FROM audit_events WHERE action = ? AND resource = ? ORDER BY id DESC LIMIT 1",
			action, "kv/app/key",
		).Scan(&detail)
	})
	if err != nil {
		t.Fatal(err)
	}
	if detail != expected {
		t.Fatalf("%s audit detail = %q, want %q", action, detail, expected)
	}
}

func TestInitializeSecretsDatabaseMigratesLegacyValuesToVersionOne(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`
		CREATE TABLE secrets (
			path TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO secrets(path, data, updated_at) VALUES ('app/key', 'ciphertext', '2026-01-02 03:04:05');
	`); err != nil {
		t.Fatal(err)
	}
	if err := initializeSecretsDatabase(db); err != nil {
		t.Fatalf("migrate legacy secrets: %v", err)
	}
	var currentVersion, version int64
	var ciphertext string
	if err := db.QueryRow("SELECT current_version FROM secrets WHERE path = 'kv/app/key'").Scan(&currentVersion); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(
		"SELECT version, data FROM secret_versions WHERE path = 'kv/app/key'",
	).Scan(&version, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if currentVersion != 1 || version != 1 || ciphertext != "ciphertext" {
		t.Fatalf("migrated value = current:%d version:%d data:%q", currentVersion, version, ciphertext)
	}
	if err := initializeSecretsDatabase(db); err != nil {
		t.Fatalf("reinitialize versioned secrets database: %v", err)
	}
}

func TestSecretVersionsCASDeleteRestoreAndDestroy(t *testing.T) {
	s := newOperatorTestServer(t)
	aead, err := newDatabaseAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.secretsAEAD = aead

	first, err := s.encryptSecret([]byte(`{"value":"first"}`))
	if err != nil {
		t.Fatal(err)
	}
	version, created, err := s.writeSecretVersion("kv/app/key", first, "admin", nil)
	if err != nil || version != 1 || !created {
		t.Fatalf("first write = version %d, created %v, error %v", version, created, err)
	}
	second, err := s.encryptSecret([]byte(`{"value":"second"}`))
	if err != nil {
		t.Fatal(err)
	}
	expected := int64(1)
	version, created, err = s.writeSecretVersion("kv/app/key", second, "admin", &expected)
	if err != nil || version != 2 || created {
		t.Fatalf("second write = version %d, created %v, error %v", version, created, err)
	}
	if _, _, err := s.writeSecretVersion("kv/app/key", first, "admin", &expected); !errors.Is(err, errSecretCASMismatch) {
		t.Fatalf("stale CAS write error = %v, want mismatch", err)
	}

	oldVersion := int64(1)
	record, err := s.readSecretVersion("kv/app/key", &oldVersion)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := s.decryptSecret(record.Data.String)
	if err != nil || string(plaintext) != `{"value":"first"}` {
		t.Fatalf("historical version = %q, error %v", plaintext, err)
	}
	if version, found, err := s.softDeleteCurrentSecret("kv/app/key"); err != nil || !found || version != 2 {
		t.Fatalf("soft delete result = version %d, found %t, error %v", version, found, err)
	}
	if _, err := s.readSecretVersion("kv/app/key", nil); !errors.Is(err, errSecretDeleted) {
		t.Fatalf("read deleted current version error = %v, want deleted", err)
	}
	rows, err := s.visibleSecretPaths(secretMountAccess{unrestricted: true}, "kv")
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		t.Fatal("soft-deleted path remained in the web secret list")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.updateSecretVersions("kv/app/key", "undelete", []int64{2}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readSecretVersion("kv/app/key", nil); err != nil {
		t.Fatalf("read restored current version: %v", err)
	}
	if err := s.updateSecretVersions("kv/app/key", "destroy", []int64{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readSecretVersion("kv/app/key", &oldVersion); !errors.Is(err, errSecretDestroyed) {
		t.Fatalf("read destroyed historical version error = %v, want destroyed", err)
	}
	var destroyedData sql.NullString
	if err := s.secretsDB.QueryRow(
		"SELECT data FROM secret_versions WHERE path = 'kv/app/key' AND version = 1",
	).Scan(&destroyedData); err != nil {
		t.Fatal(err)
	}
	if destroyedData.Valid {
		t.Fatal("destroyed secret version still contains ciphertext")
	}
}

func TestKVVersionAPIWritesReadsMetadataAndRestores(t *testing.T) {
	s := newOperatorTestServer(t)
	auditStore, err := openAnnualAuditStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	s.auditStore = auditStore
	defer auditStore.Close()
	aead, err := newDatabaseAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.secretsAEAD = aead
	const token = "version-test-token"
	insertScopedAPIToken(t, s, token, []string{"kv"}, "")

	put := func(body string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		s.putKVSecret(response, apiScopeRequest(
			http.MethodPut, "/api/v1/kv/data/app/key", body, token,
		))
		return response
	}
	if response := put(`{"data":{"value":"one"},"options":{"cas":0}}`); response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"version":1`) {
		t.Fatalf("create version response = %d %s", response.Code, response.Body.String())
	}
	if response := put(`{"data":{"value":"two"},"options":{"cas":1}}`); response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"version":2`) {
		t.Fatalf("update version response = %d %s", response.Code, response.Body.String())
	}
	if response := put(`{"data":{"value":"stale"},"options":{"cas":1}}`); response.Code != http.StatusConflict {
		t.Fatalf("stale CAS status = %d, body %s", response.Code, response.Body.String())
	}

	historicalRequest := apiScopeRequest(http.MethodGet, "/api/v1/kv/data/app/key?version=1", "", token)
	historicalRequest.SetPathValue("path", "app/key")
	historical := httptest.NewRecorder()
	s.getKVSecret(historical, historicalRequest)
	if historical.Code != http.StatusOK ||
		!strings.Contains(historical.Body.String(), `"value":"one"`) ||
		!strings.Contains(historical.Body.String(), `"version":1`) {
		t.Fatalf("historical read = %d %s", historical.Code, historical.Body.String())
	}

	metadataRequest := apiScopeRequest(http.MethodGet, "/api/v1/kv/metadata/app/key", "", token)
	metadata := httptest.NewRecorder()
	s.getKVMetadata(metadata, metadataRequest)
	if metadata.Code != http.StatusOK || !strings.Contains(metadata.Body.String(), `"current_version":2`) ||
		!strings.Contains(metadata.Body.String(), `"1"`) || !strings.Contains(metadata.Body.String(), `"2"`) {
		t.Fatalf("metadata response = %d %s", metadata.Code, metadata.Body.String())
	}

	deleteResponse := httptest.NewRecorder()
	s.deleteKVSecret(deleteResponse, apiScopeRequest(http.MethodDelete, "/api/v1/kv/data/app/key", "", token))
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("soft delete status = %d, body %s", deleteResponse.Code, deleteResponse.Body.String())
	}
	assertSecretAuditDetail(t, s, "delete", "version=2")
	current := httptest.NewRecorder()
	s.getKVSecret(current, apiScopeRequest(http.MethodGet, "/api/v1/kv/data/app/key", "", token))
	if current.Code != http.StatusNotFound {
		t.Fatalf("read deleted current version status = %d", current.Code)
	}
	restoreRequest := apiScopeRequest(http.MethodPost, "/api/v1/kv/undelete/app/key", `{"versions":[2]}`, token)
	restoreRequest.SetPathValue("operation", "undelete")
	restoreRequest.SetPathValue("path", "app/key")
	restored := httptest.NewRecorder()
	s.changeKVVersionState(restored, restoreRequest)
	if restored.Code != http.StatusNoContent {
		t.Fatalf("undelete status = %d, body %s", restored.Code, restored.Body.String())
	}
	assertSecretAuditDetail(t, s, "undelete", "versions=[2]")
	current = httptest.NewRecorder()
	s.getKVSecret(current, apiScopeRequest(http.MethodGet, "/api/v1/kv/data/app/key", "", token))
	if current.Code != http.StatusOK || !strings.Contains(current.Body.String(), `"value":"two"`) {
		t.Fatalf("restored current read = %d %s", current.Code, current.Body.String())
	}

	destroyRequest := apiScopeRequest(http.MethodPost, "/api/v1/kv/destroy/app/key", `{"versions":[1]}`, token)
	destroyRequest.SetPathValue("operation", "destroy")
	destroyRequest.SetPathValue("path", "app/key")
	destroyed := httptest.NewRecorder()
	s.changeKVVersionState(destroyed, destroyRequest)
	if destroyed.Code != http.StatusForbidden {
		t.Fatalf("non-admin token destroy status = %d, body %s", destroyed.Code, destroyed.Body.String())
	}

	const adminToken = "admin-version-test-token"
	insertScopedAPIToken(t, s, adminToken, []string{"kv"}, "admin")
	adminDestroyRequest := apiScopeRequest(
		http.MethodPost, "/api/v1/kv/destroy/app/key", `{"versions":[1]}`, adminToken,
	)
	adminDestroyRequest.SetPathValue("operation", "destroy")
	adminDestroyRequest.SetPathValue("path", "app/key")
	adminDestroyed := httptest.NewRecorder()
	s.changeKVVersionState(adminDestroyed, adminDestroyRequest)
	if adminDestroyed.Code != http.StatusNoContent {
		t.Fatalf("admin token destroy status = %d, body %s", adminDestroyed.Code, adminDestroyed.Body.String())
	}
	assertSecretAuditDetail(t, s, "destroy", "versions=[1]")
}
