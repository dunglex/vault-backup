package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"vault-backup/internal/operator"
)

type secretPrefixAccess struct {
	unrestricted bool
	prefixes     []string
	encoded      string
}

func normalizeSecretPrefixes(prefixes []string) ([]string, error) {
	return operator.NormalizeSecretPrefixes(prefixes, validSecretPath)
}

func encodeSecretPrefixes(prefixes []string) (string, error) {
	return operator.EncodeSecretPrefixes(prefixes)
}

func decodeSecretPrefixes(encoded string) ([]string, error) {
	return operator.DecodeSecretPrefixes(encoded, validSecretPath)
}

func (access secretPrefixAccess) operatorAccess() operator.SecretAccess {
	return operator.SecretAccess{
		Unrestricted: access.unrestricted,
		Prefixes:     access.prefixes,
		Encoded:      access.encoded,
	}
}

func (access secretPrefixAccess) allows(path string) bool {
	return access.operatorAccess().Allows(path)
}

func (access secretPrefixAccess) contains(candidate string) bool {
	return access.operatorAccess().Contains(candidate)
}

func (access secretPrefixAccess) intersect(other secretPrefixAccess) secretPrefixAccess {
	result := access.operatorAccess().Intersect(other.operatorAccess())
	return secretPrefixAccess{
		unrestricted: result.Unrestricted,
		prefixes:     result.Prefixes,
		encoded:      result.Encoded,
	}
}

func (access secretPrefixAccess) empty() bool {
	return !access.unrestricted && len(access.prefixes) == 0
}

func denySecretScope(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error": "secret path is outside the credential's allowed prefixes",
	})
}

func (s *server) webSecretAccessForRequest(w http.ResponseWriter, r *http.Request) (secretPrefixAccess, bool) {
	session, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return secretPrefixAccess{}, false
	}
	if session.role == "admin" {
		return secretPrefixAccess{unrestricted: true}, true
	}
	if session.role != "operator" || s.operatorDB == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return secretPrefixAccess{}, false
	}
	var encoded string
	if err := s.operatorDB.QueryRow(
		"SELECT secret_prefixes FROM accounts WHERE username = ? AND role = 'operator' AND locked = 0",
		session.username,
	).Scan(&encoded); err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return secretPrefixAccess{}, false
		}
		log.Printf("ERROR: could not read operator secret path prefixes: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
		return secretPrefixAccess{}, false
	}
	prefixes, err := decodeSecretPrefixes(encoded)
	if err != nil {
		log.Printf("ERROR: invalid operator secret path prefixes: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
		return secretPrefixAccess{}, false
	}
	return secretPrefixAccess{prefixes: prefixes, encoded: encoded}, true
}

func (s *server) apiSecretAccessForRequest(w http.ResponseWriter, r *http.Request) (secretPrefixAccess, bool) {
	if !s.authorizedAPI(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return secretPrefixAccess{}, false
	}
	token := apiTokenFromRequest(r)
	hash := sha256.Sum256([]byte(token))
	var encoded string
	var createdBy sql.NullString
	err := s.db.QueryRow(
		"SELECT secret_prefixes, created_by FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL AND expires_at >= ?",
		hex.EncodeToString(hash[:]), time.Now().Unix(),
	).Scan(&encoded, &createdBy)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return secretPrefixAccess{}, false
		}
		log.Printf("ERROR: could not read API token secret path prefixes: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
		return secretPrefixAccess{}, false
	}
	prefixes, err := decodeSecretPrefixes(encoded)
	if err != nil {
		log.Printf("ERROR: invalid API token secret path prefixes: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
		return secretPrefixAccess{}, false
	}
	access := secretPrefixAccess{prefixes: prefixes, encoded: encoded}
	if createdBy.Valid {
		var role, accountPrefixes string
		var locked int
		err := s.db.QueryRow(
			"SELECT role, locked, secret_prefixes FROM accounts WHERE username = ? AND role = 'admin'",
			createdBy.String,
		).Scan(&role, &locked, &accountPrefixes)
		if err == sql.ErrNoRows && s.operatorDB != nil {
			err = s.operatorDB.QueryRow(
				"SELECT role, locked, secret_prefixes FROM accounts WHERE username = ? AND role = 'operator'",
				createdBy.String,
			).Scan(&role, &locked, &accountPrefixes)
		}
		if err != nil && err != sql.ErrNoRows {
			log.Printf("ERROR: could not read API token owner access: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
			return secretPrefixAccess{}, false
		}
		if err == sql.ErrNoRows || locked != 0 {
			return secretPrefixAccess{prefixes: []string{}, encoded: "[]"}, true
		}
		if role == "operator" {
			operatorPrefixes, decodeErr := decodeSecretPrefixes(accountPrefixes)
			if decodeErr != nil {
				log.Printf("ERROR: invalid API token owner secret path prefixes: %v", decodeErr)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify secret access"})
				return secretPrefixAccess{}, false
			}
			access = access.intersect(secretPrefixAccess{prefixes: operatorPrefixes})
		}
	}
	return access, true
}

func (s *server) secretPathAllowed(access secretPrefixAccess, path string) (bool, error) {
	if access.unrestricted {
		return true, nil
	}
	var allowed bool
	err := s.db.QueryRow(`
		SELECT EXISTS (
			SELECT 1
			FROM json_each(?) AS prefix
			WHERE ? = prefix.value
			   OR substr(?, 1, length(prefix.value) + 1) = prefix.value || '/'
		)`,
		access.encoded, path, path,
	).Scan(&allowed)
	return allowed, err
}

func (s *server) secretPathIntersects(access secretPrefixAccess, path string) (bool, error) {
	if access.unrestricted {
		return true, nil
	}
	var intersects bool
	err := s.db.QueryRow(`
		SELECT EXISTS (
			SELECT 1
			FROM json_each(?) AS prefix
			WHERE ? = prefix.value
			   OR substr(?, 1, length(prefix.value) + 1) = prefix.value || '/'
			   OR substr(prefix.value, 1, length(?) + 1) = ? || '/'
		)`,
		access.encoded, path, path, path, path,
	).Scan(&intersects)
	return intersects, err
}

func (s *server) visibleSecretPaths(access secretPrefixAccess) (*sql.Rows, error) {
	if access.unrestricted {
		return s.secretsDB.Query(`
			SELECT path
			FROM secrets
			WHERE EXISTS (
				SELECT 1 FROM secret_versions v
				WHERE v.path = secrets.path
				  AND v.version = secrets.current_version
				  AND v.deleted_at IS NULL
				  AND v.destroyed_at IS NULL
			)
			ORDER BY path`)
	}
	return s.secretsDB.Query(`
		SELECT path
		FROM secrets
		WHERE EXISTS (
				SELECT 1 FROM secret_versions v
				WHERE v.path = secrets.path
				  AND v.version = secrets.current_version
				  AND v.deleted_at IS NULL
				  AND v.destroyed_at IS NULL
			)
		  AND EXISTS (
				SELECT 1
				FROM json_each(?) AS prefix
				WHERE secrets.path = prefix.value
				   OR substr(secrets.path, 1, length(prefix.value) + 1) = prefix.value || '/'
		  )
		ORDER BY path`,
		access.encoded,
	)
}

func (s *server) updateAPITokenSecretPrefixes(w http.ResponseWriter, r *http.Request) {
	actor := s.auditRequestActor(r, "web")
	resource := "api-token"
	session, ok := s.sessionFromRequest(r)
	if !ok {
		s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "unauthorized")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var id int64
	if !s.requestIsHTTPS(r) {
		s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "https_required")
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage API tokens"})
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "invalid_token_id")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token id"})
		return
	}
	resource = "api-token:" + strconv.FormatInt(id, 10)
	var request struct {
		Prefixes []string `json:"prefixes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	prefixes, err := normalizeSecretPrefixes(request.Prefixes)
	if err != nil {
		s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "invalid_secret_prefixes")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if session.role != "admin" {
		operatorAccess, accessOK := s.webSecretAccessForRequest(w, r)
		if !accessOK {
			s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "unauthorized")
			return
		}
		for _, prefix := range prefixes {
			if !operatorAccess.contains(prefix) {
				s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "scope_denied")
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "token prefixes must be within your allowed secret paths"})
				return
			}
		}
	}
	encoded, err := encodeSecretPrefixes(prefixes)
	if err != nil {
		s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "encoding_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save secret path prefixes"})
		return
	}
	result, err := s.db.Exec("UPDATE api_tokens SET secret_prefixes = ? WHERE id = ?", encoded, id)
	if err != nil {
		s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update API token secret access"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update API token secret access"})
		return
	}
	if updated != 1 {
		s.recordAuditEvent(r, "update_token_scopes", "failure", actor, "web", resource, "token_not_found")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "API token not found"})
		return
	}
	s.recordAuditEvent(r, "update_token_scopes", "success", actor, "web", resource, "")
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "prefixes": prefixes})
}
