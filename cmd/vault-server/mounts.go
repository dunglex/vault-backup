package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type secretMount struct {
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
	DeletedAt int64  `json:"deleted_at,omitempty"`
	Deleted   bool   `json:"deleted"`
}

func validSecretMount(mount string) bool {
	return validSecretPath(mount)
}

func secretStoragePath(mount, path string) string {
	if path == "" {
		return mount
	}
	return mount + "/" + path
}

func (s *server) mountExists(mount string, includeDeleted bool) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM secret_mounts WHERE name = ?"
	if !includeDeleted {
		query += " AND deleted_at IS NULL"
	}
	query += ")"
	var exists bool
	err := s.secretsDB.QueryRow(query, mount).Scan(&exists)
	return exists, err
}

func (s *server) activeMountNames() ([]string, error) {
	rows, err := s.secretsDB.Query("SELECT name FROM secret_mounts WHERE deleted_at IS NULL ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	mounts := make([]string, 0)
	for rows.Next() {
		var mount string
		if err := rows.Scan(&mount); err != nil {
			return nil, err
		}
		mounts = append(mounts, mount)
	}
	return mounts, rows.Err()
}

func (s *server) routeKVAPI(w http.ResponseWriter, r *http.Request) {
	route := strings.Trim(r.PathValue("route"), "/")
	mounts, err := s.activeMountNames()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not resolve secret mount"})
		return
	}
	sort.Slice(mounts, func(i, j int) bool { return len(mounts[i]) > len(mounts[j]) })
	var mount, remaining string
	for _, candidate := range mounts {
		if route == candidate || strings.HasPrefix(route, candidate+"/") {
			mount = candidate
			remaining = strings.TrimPrefix(strings.TrimPrefix(route, candidate), "/")
			break
		}
	}
	if mount == "" {
		http.NotFound(w, r)
		return
	}
	operation, path, hasPath := strings.Cut(remaining, "/")
	if !hasPath {
		path = ""
	}
	r.SetPathValue("mount", mount)
	r.SetPathValue("path", path)
	switch {
	case operation == "data" && (r.Method == http.MethodGet || r.Method == http.MethodPut || r.Method == http.MethodDelete):
		switch r.Method {
		case http.MethodGet:
			s.getKVSecret(w, r)
		case http.MethodPut:
			s.putKVSecret(w, r)
		case http.MethodDelete:
			s.deleteKVSecret(w, r)
		}
	case operation == "metadata" && r.Method == http.MethodGet && path != "":
		s.getKVMetadata(w, r)
	case operation == "metadata" && (r.Method == "LIST" || (r.Method == http.MethodGet && path == "")):
		s.listKVMetadata(w, r)
	case (operation == "delete" || operation == "undelete" || operation == "destroy") && r.Method == http.MethodPost:
		r.SetPathValue("operation", operation)
		s.changeKVVersionState(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) listMounts(w http.ResponseWriter, r *http.Request) {
	access, ok := s.webSecretAccessForRequest(w, r)
	if !ok {
		return
	}
	rows, err := s.secretsDB.Query("SELECT name FROM secret_mounts WHERE deleted_at IS NULL ORDER BY name")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secret mounts"})
		return
	}
	defer rows.Close()
	mounts := make([]string, 0)
	for rows.Next() {
		var mount string
		if err := rows.Scan(&mount); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read secret mounts"})
			return
		}
		if access.allows(mount) {
			mounts = append(mounts, mount)
		}
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secret mounts"})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"mounts": mounts})
}

func (s *server) listManagedMounts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	rows, err := s.secretsDB.Query("SELECT name, created_at, deleted_at FROM secret_mounts ORDER BY name")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secret mounts"})
		return
	}
	defer rows.Close()
	mounts := make([]secretMount, 0)
	for rows.Next() {
		var mount secretMount
		var deletedAt sql.NullInt64
		if err := rows.Scan(&mount.Name, &mount.CreatedAt, &deletedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read secret mounts"})
			return
		}
		mount.Deleted = deletedAt.Valid
		if deletedAt.Valid {
			mount.DeletedAt = deletedAt.Int64
		}
		mounts = append(mounts, mount)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list secret mounts"})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]secretMount{"mounts": mounts})
}

func (s *server) createMount(w http.ResponseWriter, r *http.Request) {
	actor := s.auditRequestActor(r, "web")
	if !s.requireAdmin(w, r) {
		return
	}
	if !s.requestIsHTTPS(r) {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage secret mounts"})
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.recordAuditEvent(r, "create_mount", "failure", actor, "web", "secret-mount", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if !validSecretMount(request.Name) {
		s.recordAuditEvent(r, "create_mount", "failure", actor, "web", "secret-mount", "invalid_mount")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mount name must contain valid slash-separated path segments"})
		return
	}
	tx, err := s.secretsDB.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create secret mount"})
		return
	}
	defer tx.Rollback()
	var conflict bool
	err = tx.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM secret_mounts
			WHERE name = ?
			   OR substr(name, 1, length(?) + 1) = ? || '/'
			   OR substr(?, 1, length(name) + 1) = name || '/'
		)`, request.Name, request.Name, request.Name, request.Name).Scan(&conflict)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not check secret mount"})
		return
	}
	if conflict {
		s.recordAuditEvent(r, "create_mount", "failure", actor, "web", request.Name, "mount_conflict")
		writeJSON(w, http.StatusConflict, map[string]string{"error": "mount conflicts with an existing or deleted mount"})
		return
	}
	if _, err := tx.Exec("INSERT INTO secret_mounts(name, created_at) VALUES (?, ?)", request.Name, time.Now().UTC().Unix()); err != nil {
		s.recordAuditEvent(r, "create_mount", "failure", actor, "web", request.Name, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create secret mount"})
		return
	}
	if err := tx.Commit(); err != nil {
		s.recordAuditEvent(r, "create_mount", "failure", actor, "web", request.Name, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create secret mount"})
		return
	}
	s.recordAuditEvent(r, "create_mount", "success", actor, "web", request.Name, "")
	writeJSON(w, http.StatusCreated, secretMount{Name: request.Name, CreatedAt: time.Now().UTC().Unix()})
}

func (s *server) softDeleteMount(w http.ResponseWriter, r *http.Request) {
	actor := s.auditRequestActor(r, "web")
	if !s.requireAdmin(w, r) {
		return
	}
	if !s.requestIsHTTPS(r) {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage secret mounts"})
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || !validSecretMount(request.Name) {
		s.recordAuditEvent(r, "delete_mount", "failure", actor, "web", "secret-mount", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid mount name is required"})
		return
	}
	active, err := s.mountExists(request.Name, false)
	if err != nil {
		s.recordAuditEvent(r, "delete_mount", "failure", actor, "web", request.Name, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not check secret mount"})
		return
	}
	if !active {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "active secret mount not found"})
		return
	}
	if err := s.removeMountGrants(request.Name); err != nil {
		s.recordAuditEvent(r, "delete_mount", "failure", actor, "web", request.Name, "grant_update_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove secret mount access"})
		return
	}
	result, err := s.secretsDB.Exec(
		"UPDATE secret_mounts SET deleted_at = ? WHERE name = ? AND deleted_at IS NULL",
		time.Now().UTC().Unix(), request.Name,
	)
	if err != nil {
		s.recordAuditEvent(r, "delete_mount", "failure", actor, "web", request.Name, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not delete secret mount"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not delete secret mount"})
		return
	}
	if updated != 1 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "active secret mount not found"})
		return
	}
	s.recordAuditEvent(r, "delete_mount", "success", actor, "web", request.Name, "soft_deleted")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *server) restoreMount(w http.ResponseWriter, r *http.Request) {
	actor := s.auditRequestActor(r, "web")
	if !s.requireAdmin(w, r) {
		return
	}
	if !s.requestIsHTTPS(r) {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage secret mounts"})
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || !validSecretMount(request.Name) {
		s.recordAuditEvent(r, "restore_mount", "failure", actor, "web", "secret-mount", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid mount name is required"})
		return
	}
	result, err := s.secretsDB.Exec(
		"UPDATE secret_mounts SET deleted_at = NULL WHERE name = ? AND deleted_at IS NOT NULL",
		request.Name,
	)
	if err != nil {
		s.recordAuditEvent(r, "restore_mount", "failure", actor, "web", request.Name, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not restore secret mount"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not restore secret mount"})
		return
	}
	if updated != 1 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "deleted secret mount not found"})
		return
	}
	s.recordAuditEvent(r, "restore_mount", "success", actor, "web", request.Name, "access_must_be_regranted")
	writeJSON(w, http.StatusOK, map[string]string{"status": "restored"})
}

func (s *server) removeMountGrants(mount string) error {
	remove := func(encoded string) (string, error) {
		mounts, err := decodeSecretMounts(encoded)
		if err != nil {
			return "", err
		}
		filtered := mounts[:0]
		for _, current := range mounts {
			if current != mount {
				filtered = append(filtered, current)
			}
		}
		return encodeSecretMounts(filtered)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	rows, err := tx.Query("SELECT id, secret_mounts FROM api_tokens")
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	type tokenGrant struct {
		id      int64
		encoded string
	}
	grants := make([]tokenGrant, 0)
	for rows.Next() {
		var grant tokenGrant
		if err := rows.Scan(&grant.id, &grant.encoded); err != nil {
			_ = rows.Close()
			_ = tx.Rollback()
			return err
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		_ = tx.Rollback()
		return err
	}
	if err := rows.Close(); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, grant := range grants {
		encoded, err := remove(grant.encoded)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.Exec("UPDATE api_tokens SET secret_mounts = ? WHERE id = ?", encoded, grant.id); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.operatorDB != nil {
		tx, err := s.operatorDB.Begin()
		if err != nil {
			return err
		}
		rows, err := tx.Query("SELECT username, secret_mounts FROM accounts WHERE role = 'operator'")
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		type operatorGrant struct {
			username string
			encoded  string
		}
		operators := make([]operatorGrant, 0)
		for rows.Next() {
			var grant operatorGrant
			if err := rows.Scan(&grant.username, &grant.encoded); err != nil {
				_ = rows.Close()
				_ = tx.Rollback()
				return err
			}
			operators = append(operators, grant)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			_ = tx.Rollback()
			return err
		}
		if err := rows.Close(); err != nil {
			_ = tx.Rollback()
			return err
		}
		for _, grant := range operators {
			encoded, err := remove(grant.encoded)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			if _, err := tx.Exec("UPDATE accounts SET secret_mounts = ? WHERE username = ?", encoded, grant.username); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func ensureMountTable(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS secret_mounts (
			name TEXT PRIMARY KEY,
			created_at INTEGER NOT NULL,
			deleted_at INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_secret_mounts_deleted_at ON secret_mounts(deleted_at);
	`); err != nil {
		return fmt.Errorf("initialize secret mounts: %w", err)
	}
	if _, err := db.Exec(
		"INSERT OR IGNORE INTO secret_mounts(name, created_at) VALUES ('kv', ?)",
		time.Now().UTC().Unix(),
	); err != nil {
		return fmt.Errorf("initialize default secret mount: %w", err)
	}
	return nil
}

func migrateSecretNamespace(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS secret_mount_migrations (
			name TEXT PRIMARY KEY
		)
	`); err != nil {
		return err
	}
	var migrated bool
	if err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM secret_mount_migrations WHERE name = 'mount-qualified-v1')").Scan(&migrated); err != nil {
		return err
	}
	if migrated {
		return nil
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_secret_versions_created_at ON secret_versions(created_at)"); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DROP INDEX IF EXISTS idx_secret_versions_created_at"); err != nil {
		return err
	}
	if _, err := tx.Exec("ALTER TABLE secret_versions RENAME TO secret_versions_unmounted"); err != nil {
		return err
	}
	if _, err := tx.Exec("ALTER TABLE secrets RENAME TO secrets_unmounted"); err != nil {
		return err
	}
	if _, err := tx.Exec(versionedSecretsTableSchema + secretVersionsTableSchema); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		INSERT INTO secrets(path, current_version, created_at, updated_at)
		SELECT 'kv/' || path, current_version, created_at, updated_at FROM secrets_unmounted
	`); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		INSERT INTO secret_versions(path, version, data, created_at, created_by, deleted_at, destroyed_at)
		SELECT 'kv/' || path, version, data, created_at, created_by, deleted_at, destroyed_at
		FROM secret_versions_unmounted
	`); err != nil {
		return err
	}
	if _, err := tx.Exec("DROP TABLE secret_versions_unmounted"); err != nil {
		return err
	}
	if _, err := tx.Exec("DROP TABLE secrets_unmounted"); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO secret_mount_migrations(name) VALUES ('mount-qualified-v1')"); err != nil {
		return err
	}
	return tx.Commit()
}

var errMountNotFound = errors.New("secret mount not found")
