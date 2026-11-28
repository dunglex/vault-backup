package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"
)

var errSecretCASMismatch = errors.New("secret version does not match compare-and-set value")
var errSecretDeleted = errors.New("secret version is deleted")
var errSecretDestroyed = errors.New("secret version is destroyed")

type secretVersionRecord struct {
	Data        sql.NullString
	Version     int64
	CreatedAt   int64
	CreatedBy   sql.NullString
	DeletedAt   sql.NullInt64
	DestroyedAt sql.NullInt64
}

type secretVersionSummary struct {
	Version   int64 `json:"version"`
	Deleted   bool  `json:"deleted"`
	Destroyed bool  `json:"destroyed"`
}

func (s *server) writeSecretVersion(path, encrypted, actor string, cas *int64) (int64, bool, error) {
	tx, err := s.secretsDB.Begin()
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()

	wasVisible, err := currentSecretIsVisible(tx, path)
	if err != nil {
		return 0, false, err
	}
	var current int64
	err = tx.QueryRow("SELECT current_version FROM secrets WHERE path = ?", path).Scan(&current)
	created := err == sql.ErrNoRows
	if err != nil && !created {
		return 0, false, err
	}
	if created {
		if cas != nil && *cas != 0 {
			return 0, false, errSecretCASMismatch
		}
		current = 0
	} else if cas != nil && *cas != current {
		return 0, false, errSecretCASMismatch
	}

	next := current + 1
	now := time.Now().UTC().Unix()
	if created {
		if _, err := tx.Exec(
			"INSERT INTO secrets(path, current_version, created_at, updated_at) VALUES (?, ?, ?, ?)",
			path, next, now, now,
		); err != nil {
			return 0, false, err
		}
	} else {
		result, err := tx.Exec(
			"UPDATE secrets SET current_version = ?, updated_at = ? WHERE path = ? AND current_version = ?",
			next, now, path, current,
		)
		if err != nil {
			return 0, false, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, false, err
		}
		if affected != 1 {
			return 0, false, errSecretCASMismatch
		}
	}
	if _, err := tx.Exec(
		"INSERT INTO secret_versions(path, version, data, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
		path, next, encrypted, now, nullableString(actor),
	); err != nil {
		return 0, false, err
	}
	if err := syncSecretListingVisibility(tx, path, wasVisible); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return next, created, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func auditVersionDetail(reason string, version int64) string {
	if version <= 0 {
		return reason
	}
	if reason == "" {
		return fmt.Sprintf("version=%d", version)
	}
	return fmt.Sprintf("%s;version=%d", reason, version)
}

func auditVersionsDetail(versions []int64) string {
	ordered := append([]int64(nil), versions...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	return fmt.Sprintf("versions=%v", ordered)
}

func (s *server) readSecretVersion(path string, requestedVersion *int64) (secretVersionRecord, error) {
	var record secretVersionRecord
	query := `
		SELECT v.data, v.version, v.created_at, v.created_by, v.deleted_at, v.destroyed_at
		FROM secret_versions v`
	args := []any{path}
	if requestedVersion == nil {
		query += `
		JOIN secrets s ON s.path = v.path AND s.current_version = v.version
		WHERE v.path = ?`
	} else {
		query += " WHERE v.path = ? AND v.version = ?"
		args = append(args, *requestedVersion)
	}
	err := s.secretsDB.QueryRow(query, args...).Scan(
		&record.Data, &record.Version, &record.CreatedAt, &record.CreatedBy, &record.DeletedAt, &record.DestroyedAt,
	)
	if err != nil {
		return secretVersionRecord{}, err
	}
	if record.DestroyedAt.Valid || !record.Data.Valid {
		return record, errSecretDestroyed
	}
	if record.DeletedAt.Valid {
		return record, errSecretDeleted
	}
	return record, nil
}

func (s *server) secretVersionSummaries(path string) (int64, []secretVersionSummary, error) {
	var current int64
	if err := s.secretsDB.QueryRow(
		"SELECT current_version FROM secrets WHERE path = ?", path,
	).Scan(&current); err != nil {
		return 0, nil, err
	}
	rows, err := s.secretsDB.Query(`
		SELECT version, deleted_at, destroyed_at
		FROM secret_versions
		WHERE path = ?
		ORDER BY version DESC`, path)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	summaries := make([]secretVersionSummary, 0)
	for rows.Next() {
		var summary secretVersionSummary
		var deletedAt, destroyedAt sql.NullInt64
		if err := rows.Scan(&summary.Version, &deletedAt, &destroyedAt); err != nil {
			return 0, nil, err
		}
		summary.Deleted = deletedAt.Valid
		summary.Destroyed = destroyedAt.Valid
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	return current, summaries, nil
}

func (s *server) softDeleteCurrentSecret(path string) (int64, bool, error) {
	tx, err := s.secretsDB.Begin()
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	var currentVersion int64
	err = tx.QueryRow("SELECT current_version FROM secrets WHERE path = ?", path).Scan(&currentVersion)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	wasVisible, err := currentSecretIsVisible(tx, path)
	if err != nil {
		return 0, false, err
	}
	if _, err := tx.Exec(`
		UPDATE secret_versions
		SET deleted_at = ?
		WHERE path = ?
		  AND version = ?
		  AND deleted_at IS NULL
		  AND destroyed_at IS NULL
	`, time.Now().UTC().Unix(), path, currentVersion); err != nil {
		return 0, false, err
	}
	if err := syncSecretListingVisibility(tx, path, wasVisible); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return currentVersion, true, nil
}

func (s *server) updateSecretVersions(path, operation string, versions []int64) error {
	tx, err := s.secretsDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	wasVisible, err := currentSecretIsVisible(tx, path)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	for _, version := range versions {
		switch operation {
		case "delete":
			_, err = tx.Exec(
				"UPDATE secret_versions SET deleted_at = ? WHERE path = ? AND version = ? AND destroyed_at IS NULL AND deleted_at IS NULL",
				now, path, version,
			)
		case "undelete":
			_, err = tx.Exec(
				"UPDATE secret_versions SET deleted_at = NULL WHERE path = ? AND version = ? AND destroyed_at IS NULL AND deleted_at IS NOT NULL",
				path, version,
			)
		case "destroy":
			_, err = tx.Exec(
				"UPDATE secret_versions SET data = NULL, deleted_at = COALESCE(deleted_at, ?), destroyed_at = ? WHERE path = ? AND version = ? AND destroyed_at IS NULL",
				now, now, path, version,
			)
		default:
			return fmt.Errorf("unsupported secret version operation")
		}
		if err != nil {
			return err
		}
	}
	if err := syncSecretListingVisibility(tx, path, wasVisible); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *server) apiTokenOwnerIsAdmin(r *http.Request) (bool, error) {
	hash := sha256.Sum256([]byte(apiTokenFromRequest(r)))
	var createdBy sql.NullString
	if err := s.db.QueryRow(
		"SELECT created_by FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL AND expires_at >= ?",
		hex.EncodeToString(hash[:]), time.Now().Unix(),
	).Scan(&createdBy); err != nil {
		return false, err
	}
	if !createdBy.Valid {
		return false, nil
	}
	var role string
	var locked int
	if err := s.db.QueryRow(
		"SELECT role, locked FROM accounts WHERE username = ?", createdBy.String,
	).Scan(&role, &locked); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return role == "admin" && locked == 0, nil
}

func (s *server) authorizeVersionedAPIPath(w http.ResponseWriter, r *http.Request, action string) (string, string, bool) {
	mount, path := r.PathValue("mount"), r.PathValue("path")
	if !validSecretMount(mount) || !validSecretPath(path) {
		s.recordAuditEvent(r, action, "failure", s.auditRequestActor(r, "api"), "api", path, "invalid_secret_path")
		writeInvalidSecretPath(w)
		return "", "", false
	}
	access, ok := s.apiSecretAccessForRequest(w, r)
	if !ok {
		s.recordAuditEvent(r, action, "failure", s.auditRequestActor(r, "api"), "api", path, "unauthorized")
		return "", "", false
	}
	allowed, err := s.secretMountAllowed(access, mount)
	if err != nil {
		s.recordAuditEvent(r, action, "failure", s.auditRequestActor(r, "api"), "api", path, "scope_lookup_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
		return "", "", false
	}
	if !allowed {
		s.recordAuditEvent(r, action, "failure", s.auditRequestActor(r, "api"), "api", secretStoragePath(mount, path), "scope_denied")
		denySecretScope(w)
		return "", "", false
	}
	return secretStoragePath(mount, path), s.auditRequestActor(r, "api"), true
}

func (s *server) getKVMetadata(w http.ResponseWriter, r *http.Request) {
	path, actor, ok := s.authorizeVersionedAPIPath(w, r, "read_metadata")
	if !ok {
		return
	}
	var current int64
	var createdAt, updatedAt int64
	err := s.secretsDB.QueryRow(
		"SELECT current_version, created_at, updated_at FROM secrets WHERE path = ?", path,
	).Scan(&current, &createdAt, &updatedAt)
	if err != nil {
		if err != sql.ErrNoRows {
			s.recordAuditEvent(r, "read_metadata", "failure", actor, "api", path, "storage_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read secret metadata"})
			return
		}
		s.recordAuditEvent(r, "read_metadata", "failure", actor, "api", path, "not_found")
		writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{"secret not found"}})
		return
	}
	rows, err := s.secretsDB.Query(`
		SELECT version, created_at, deleted_at, destroyed_at
		FROM secret_versions WHERE path = ? ORDER BY version`, path)
	if err != nil {
		s.recordAuditEvent(r, "read_metadata", "failure", actor, "api", path, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read secret metadata"})
		return
	}
	defer rows.Close()
	versions := make(map[string]any)
	for rows.Next() {
		var version, versionCreatedAt int64
		var deletedAt, destroyedAt sql.NullInt64
		if err := rows.Scan(&version, &versionCreatedAt, &deletedAt, &destroyedAt); err != nil {
			s.recordAuditEvent(r, "read_metadata", "failure", actor, "api", path, "storage_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read secret metadata"})
			return
		}
		deletionTime := ""
		if deletedAt.Valid {
			deletionTime = time.Unix(deletedAt.Int64, 0).UTC().Format(time.RFC3339)
		}
		versions[strconv.FormatInt(version, 10)] = map[string]any{
			"created_time":  time.Unix(versionCreatedAt, 0).UTC().Format(time.RFC3339),
			"deletion_time": deletionTime,
			"destroyed":     destroyedAt.Valid,
		}
	}
	if err := rows.Err(); err != nil {
		s.recordAuditEvent(r, "read_metadata", "failure", actor, "api", path, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read secret metadata"})
		return
	}
	s.recordAuditEvent(r, "read_metadata", "success", actor, "api", path, fmt.Sprintf("current_version=%d", current))
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"current_version": current,
		"created_time":    time.Unix(createdAt, 0).UTC().Format(time.RFC3339),
		"updated_time":    time.Unix(updatedAt, 0).UTC().Format(time.RFC3339),
		"versions":        versions,
	}})
}

func (s *server) changeKVVersionState(w http.ResponseWriter, r *http.Request) {
	operation := r.PathValue("operation")
	if operation != "delete" && operation != "undelete" && operation != "destroy" {
		http.NotFound(w, r)
		return
	}
	action := operation
	path, actor, ok := s.authorizeVersionedAPIPath(w, r, action)
	if !ok {
		return
	}
	if operation == "destroy" {
		isAdmin, err := s.apiTokenOwnerIsAdmin(r)
		if err != nil {
			s.recordAuditEvent(r, action, "failure", actor, "api", path, "storage_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify token owner"})
			return
		}
		if !isAdmin {
			s.recordAuditEvent(r, action, "failure", actor, "api", path, "admin_token_required")
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "permanent destruction requires a token created by an active administrator"})
			return
		}
	}
	var request struct {
		Versions []int64 `json:"versions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Versions) == 0 {
		s.recordAuditEvent(r, action, "failure", actor, "api", path, "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide one or more secret versions"})
		return
	}
	seen := make(map[int64]struct{}, len(request.Versions))
	for _, version := range request.Versions {
		if version < 1 {
			s.recordAuditEvent(r, action, "failure", actor, "api", path, "invalid_request")
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "secret versions must be positive integers"})
			return
		}
		if _, exists := seen[version]; exists {
			continue
		}
		seen[version] = struct{}{}
	}
	versions := make([]int64, 0, len(seen))
	for version := range seen {
		versions = append(versions, version)
	}
	detail := auditVersionsDetail(versions)
	if err := s.updateSecretVersions(path, operation, versions); err != nil {
		s.recordAuditEvent(r, action, "failure", actor, "api", path, "storage_error;"+detail)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update secret versions"})
		return
	}
	s.recordAuditEvent(r, action, "success", actor, "api", path, detail)
	writeJSON(w, http.StatusNoContent, nil)
}
