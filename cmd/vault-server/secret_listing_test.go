package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func listMetadataKeys(t *testing.T, s *server, path string) []string {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/kv/metadata", nil)
	request.Header.Set("X-Vault-Token", "listing-test-token")
	request.SetPathValue("mount", "kv")
	request.SetPathValue("path", path)
	response := httptest.NewRecorder()
	s.listKVMetadata(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("list metadata status = %d, body %s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Data.Keys
}

func requireMetadataKeys(t *testing.T, actual []string, expected ...string) {
	t.Helper()
	if strings.Join(actual, "\x00") != strings.Join(expected, "\x00") {
		t.Fatalf("metadata keys = %q, want %q", actual, expected)
	}
}

func writeListingTestSecret(t *testing.T, s *server, path string) int64 {
	t.Helper()
	version, _, err := s.writeSecretVersion(path, "test-ciphertext", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func TestKVMetadataListingCacheTracksVisibleSecrets(t *testing.T) {
	s := newOperatorTestServer(t)
	insertScopedAPIToken(t, s, "listing-test-token", []string{"kv"}, "")

	writeListingTestSecret(t, s, "kv/infrastructure")
	writeListingTestSecret(t, s, "kv/infrastructure/kubernetes/000081")
	writeListingTestSecret(t, s, "kv/infrastructure/kubernetes/000082")
	writeListingTestSecret(t, s, "kv/infrastructure/ssh")

	requireMetadataKeys(t, listMetadataKeys(t, s, ""), "infrastructure", "infrastructure/")
	requireMetadataKeys(t, listMetadataKeys(t, s, "infrastructure"), "kubernetes/", "ssh")

	writeListingTestSecret(t, s, "kv/infrastructure/ssh")
	requireMetadataKeys(t, listMetadataKeys(t, s, "infrastructure"), "kubernetes/", "ssh")
	if _, found, err := s.softDeleteCurrentSecret("kv/infrastructure/ssh"); err != nil || !found {
		t.Fatalf("soft-delete ssh = found %t, error %v", found, err)
	}
	requireMetadataKeys(t, listMetadataKeys(t, s, "infrastructure"), "kubernetes/")
	if err := s.updateSecretVersions("kv/infrastructure/ssh", "undelete", []int64{2}); err != nil {
		t.Fatal(err)
	}
	requireMetadataKeys(t, listMetadataKeys(t, s, "infrastructure"), "kubernetes/", "ssh")

	for _, path := range []string{
		"kv/infrastructure/kubernetes/000081",
		"kv/infrastructure/kubernetes/000082",
	} {
		if _, found, err := s.softDeleteCurrentSecret(path); err != nil || !found {
			t.Fatalf("soft-delete %s = found %t, error %v", path, found, err)
		}
	}
	requireMetadataKeys(t, listMetadataKeys(t, s, "infrastructure"), "ssh")
	if err := s.updateSecretVersions(
		"kv/infrastructure/kubernetes/000081", "undelete", []int64{1},
	); err != nil {
		t.Fatal(err)
	}
	requireMetadataKeys(t, listMetadataKeys(t, s, "infrastructure"), "kubernetes/", "ssh")
	if err := s.updateSecretVersions(
		"kv/infrastructure/kubernetes/000081", "destroy", []int64{1},
	); err != nil {
		t.Fatal(err)
	}
	requireMetadataKeys(t, listMetadataKeys(t, s, "infrastructure"), "ssh")

	if _, found, err := s.softDeleteCurrentSecret("kv/infrastructure"); err != nil || !found {
		t.Fatalf("soft-delete direct secret = found %t, error %v", found, err)
	}
	requireMetadataKeys(t, listMetadataKeys(t, s, ""), "infrastructure/")
	if _, found, err := s.softDeleteCurrentSecret("kv/infrastructure/ssh"); err != nil || !found {
		t.Fatalf("soft-delete final child = found %t, error %v", found, err)
	}
	requireMetadataKeys(t, listMetadataKeys(t, s, ""))
}

func TestInitializeSecretListingCacheBackfillsExistingSecrets(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := initializeSecretsDatabase(db); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Unix()
	for _, path := range []string{"kv/existing/nested/key", "kv/hidden/key"} {
		if _, err := db.Exec(
			"INSERT INTO secrets(path, current_version, created_at, updated_at) VALUES (?, 1, ?, ?)",
			path, now, now,
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(
		"INSERT INTO secret_versions(path, version, data, created_at) VALUES ('kv/existing/nested/key', 1, 'ciphertext', ?)",
		now,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		"INSERT INTO secret_versions(path, version, data, created_at, deleted_at) VALUES ('kv/hidden/key', 1, 'ciphertext', ?, ?)",
		now, now,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM secret_listing"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM secret_listing_migrations"); err != nil {
		t.Fatal(err)
	}

	if err := initializeSecretsDatabase(db); err != nil {
		t.Fatal(err)
	}
	var childCount int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM secret_listing WHERE parent_path = 'kv' AND child_key = 'existing/'",
	).Scan(&childCount); err != nil {
		t.Fatal(err)
	}
	if childCount != 1 {
		t.Fatalf("backfilled visible child count = %d, want 1", childCount)
	}
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM secret_listing WHERE parent_path = 'kv' AND child_key = 'hidden/'",
	).Scan(&childCount); err != nil {
		t.Fatal(err)
	}
	if childCount != 0 {
		t.Fatalf("backfilled deleted child count = %d, want 0", childCount)
	}
}
