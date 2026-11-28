package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"vault-backup/internal/operator"
)

type secretMountAccess struct {
	unrestricted bool
	mounts       []string
	encoded      string
}

func normalizeSecretMounts(mounts []string) ([]string, error) {
	return operator.NormalizeSecretMounts(mounts, validSecretMount)
}

func encodeSecretMounts(mounts []string) (string, error) {
	return operator.EncodeSecretMounts(mounts)
}

func decodeSecretMounts(encoded string) ([]string, error) {
	return operator.DecodeSecretMounts(encoded, validSecretMount)
}

func (access secretMountAccess) allows(mount string) bool {
	if access.unrestricted {
		return true
	}
	for _, allowed := range access.mounts {
		if mount == allowed {
			return true
		}
	}
	return false
}

func (access secretMountAccess) contains(mount string) bool {
	return access.allows(mount)
}

func (access secretMountAccess) intersect(other secretMountAccess) secretMountAccess {
	if access.unrestricted {
		return other
	}
	if other.unrestricted {
		return access
	}
	allowed := make(map[string]struct{}, len(other.mounts))
	for _, mount := range other.mounts {
		allowed[mount] = struct{}{}
	}
	result := secretMountAccess{mounts: make([]string, 0)}
	for _, mount := range access.mounts {
		if _, ok := allowed[mount]; ok {
			result.mounts = append(result.mounts, mount)
		}
	}
	result.encoded, _ = encodeSecretMounts(result.mounts)
	return result
}

func (access secretMountAccess) empty() bool {
	return !access.unrestricted && len(access.mounts) == 0
}

func denySecretScope(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error": "secret mount is outside the credential's allowed mounts",
	})
}

func (s *server) webSecretAccessForRequest(w http.ResponseWriter, r *http.Request) (secretMountAccess, bool) {
	session, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return secretMountAccess{}, false
	}
	if session.role == "admin" {
		return secretMountAccess{unrestricted: true}, true
	}
	if session.role != "operator" || s.operatorDB == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return secretMountAccess{}, false
	}
	var encoded string
	if err := s.operatorDB.QueryRow(
		"SELECT secret_mounts FROM accounts WHERE username = ? AND role = 'operator' AND locked = 0",
		session.username,
	).Scan(&encoded); err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return secretMountAccess{}, false
		}
		log.Printf("ERROR: could not read operator secret mounts: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
		return secretMountAccess{}, false
	}
	mounts, err := decodeSecretMounts(encoded)
	if err != nil {
		log.Printf("ERROR: invalid operator secret mounts: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
		return secretMountAccess{}, false
	}
	return secretMountAccess{mounts: mounts, encoded: encoded}, true
}

func (s *server) apiSecretAccessForRequest(w http.ResponseWriter, r *http.Request) (secretMountAccess, bool) {
	if !s.authorizedAPI(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return secretMountAccess{}, false
	}
	token := apiTokenFromRequest(r)
	hash := sha256.Sum256([]byte(token))
	var encoded string
	var createdBy sql.NullString
	_, err := measureDBQueryNamed(r, "token_scope_lookup", func() (struct{}, error) {
		return struct{}{}, s.db.QueryRow(
			"SELECT secret_mounts, created_by FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL AND expires_at >= ?",
			hex.EncodeToString(hash[:]), time.Now().Unix(),
		).Scan(&encoded, &createdBy)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return secretMountAccess{}, false
		}
		log.Printf("ERROR: could not read API token secret mounts: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
		return secretMountAccess{}, false
	}
	mounts, err := decodeSecretMounts(encoded)
	if err != nil {
		log.Printf("ERROR: invalid API token secret mounts: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
		return secretMountAccess{}, false
	}
	access := secretMountAccess{mounts: mounts, encoded: encoded}
	if createdBy.Valid {
		var role, accountMounts string
		var locked int
		_, err := measureDBQueryNamed(r, "token_owner_lookup", func() (struct{}, error) {
			return struct{}{}, s.db.QueryRow(
				"SELECT role, locked, secret_mounts FROM accounts WHERE username = ? AND role = 'admin'",
				createdBy.String,
			).Scan(&role, &locked, &accountMounts)
		})
		if err == sql.ErrNoRows && s.operatorDB != nil {
			_, err = measureDBQueryNamed(r, "token_owner_lookup", func() (struct{}, error) {
				return struct{}{}, s.operatorDB.QueryRow(
					"SELECT role, locked, secret_mounts FROM accounts WHERE username = ? AND role = 'operator'",
					createdBy.String,
				).Scan(&role, &locked, &accountMounts)
			})
		}
		if err != nil && err != sql.ErrNoRows {
			log.Printf("ERROR: could not read API token owner access: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
			return secretMountAccess{}, false
		}
		if err == sql.ErrNoRows || locked != 0 {
			return secretMountAccess{mounts: []string{}, encoded: "[]"}, true
		}
		if role == "operator" {
			operatorMounts, decodeErr := decodeSecretMounts(accountMounts)
			if decodeErr != nil {
				log.Printf("ERROR: invalid API token owner secret mounts: %v", decodeErr)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
				return secretMountAccess{}, false
			}
			access = access.intersect(secretMountAccess{mounts: operatorMounts})
		}
	}
	return access, true
}

func (s *server) secretMountAllowed(access secretMountAccess, mount string) (bool, error) {
	if !access.allows(mount) {
		return false, nil
	}
	return s.mountExists(mount, false)
}

func (s *server) secretMountAllowedForRequest(r *http.Request, access secretMountAccess, mount string) (bool, error) {
	if !access.allows(mount) {
		return false, nil
	}
	var allowed bool
	_, err := measureDBQueryNamed(r, "mount_access_check", func() (struct{}, error) {
		var err error
		allowed, err = s.mountExists(mount, false)
		return struct{}{}, err
	})
	return allowed, err
}

func (s *server) visibleSecretPaths(access secretMountAccess, mount string) (*sql.Rows, error) {
	if access.unrestricted {
		return s.secretsDB.Query(`
			SELECT substr(secrets.path, length(?) + 2)
			FROM secrets
			WHERE substr(secrets.path, 1, length(?) + 1) = ? || '/'
			  AND EXISTS (
				SELECT 1 FROM secret_versions v
				WHERE v.path = secrets.path
				  AND v.version = secrets.current_version
				  AND v.deleted_at IS NULL
				  AND v.destroyed_at IS NULL
			  )
			ORDER BY secrets.path`, mount, mount, mount)
	}
	return s.secretsDB.Query(`
		SELECT substr(secrets.path, length(?) + 2)
		FROM secrets
		WHERE substr(secrets.path, 1, length(?) + 1) = ? || '/'
		  AND EXISTS (
			SELECT 1 FROM secret_versions v
			WHERE v.path = secrets.path
			  AND v.version = secrets.current_version
			  AND v.deleted_at IS NULL
			  AND v.destroyed_at IS NULL
		  )
		  AND EXISTS (SELECT 1 FROM json_each(?) WHERE value = ?)
		ORDER BY secrets.path`,
		mount, mount, mount, access.encoded, mount,
	)
}

func (s *server) updateAPITokenSecretMounts(w http.ResponseWriter, r *http.Request) {
	actor := s.auditRequestActor(r, "web")
	session, ok := s.sessionFromRequest(r)
	if !ok {
		s.recordAuditEvent(r, "update_token_mounts", "failure", actor, "web", "api-token", "unauthorized")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if !s.requestIsHTTPS(r) {
		s.recordAuditEvent(r, "update_token_mounts", "failure", actor, "web", "api-token", "https_required")
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage API tokens"})
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token id"})
		return
	}
	resource := "api-token:" + strconv.FormatInt(id, 10)
	if session.role != "admin" {
		owned, err := s.operatorOwnsAPIToken(id, session.username)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify API token ownership"})
			return
		}
		if !owned {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "API token not found"})
			return
		}
	}
	var request struct {
		Mounts []string `json:"mounts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	mounts, err := normalizeSecretMounts(request.Mounts)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.requireActiveMounts(mounts); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if session.role != "admin" {
		operatorAccess, accessOK := s.webSecretAccessForRequest(w, r)
		if !accessOK {
			return
		}
		for _, mount := range mounts {
			if !operatorAccess.contains(mount) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "token mounts must be within your allowed mounts"})
				return
			}
		}
	}
	encoded, err := encodeSecretMounts(mounts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save secret mounts"})
		return
	}
	result, err := s.db.Exec("UPDATE api_tokens SET secret_mounts = ? WHERE id = ?", encoded, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update API token secret mounts"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update API token secret mounts"})
		return
	}
	if updated != 1 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "API token not found"})
		return
	}
	s.recordAuditEvent(r, "update_token_mounts", "success", actor, "web", resource, "")
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "mounts": mounts})
}

func (s *server) requireActiveMounts(mounts []string) error {
	for _, mount := range mounts {
		exists, err := s.mountExists(mount, false)
		if err != nil {
			return fmt.Errorf("could not verify secret mount")
		}
		if !exists {
			return fmt.Errorf("mount %q does not exist or is deleted", mount)
		}
	}
	return nil
}
