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
	"strings"
	"time"
)

const maxSecretPrefixes = 100

type secretPrefixAccess struct {
	unrestricted bool
	prefixes     []string
	encoded      string
}

func normalizeSecretPrefixes(prefixes []string) ([]string, error) {
	if len(prefixes) == 0 || len(prefixes) > maxSecretPrefixes {
		return nil, fmt.Errorf("provide between 1 and %d secret path prefixes", maxSecretPrefixes)
	}
	normalized := make([]string, 0, len(prefixes))
	seen := make(map[string]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if !validSecretPath(prefix) {
			return nil, fmt.Errorf("secret path prefixes must use valid secret paths")
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("provide at least one secret path prefix")
	}
	return normalized, nil
}

func encodeSecretPrefixes(prefixes []string) (string, error) {
	encoded, err := json.Marshal(prefixes)
	if err != nil {
		return "", fmt.Errorf("encode secret path prefixes: %w", err)
	}
	return string(encoded), nil
}

func decodeSecretPrefixes(encoded string) ([]string, error) {
	var prefixes []string
	if err := json.Unmarshal([]byte(encoded), &prefixes); err != nil {
		return nil, fmt.Errorf("decode secret path prefixes: %w", err)
	}
	if prefixes == nil {
		return nil, fmt.Errorf("secret path prefixes must be an array")
	}
	if len(prefixes) > maxSecretPrefixes {
		return nil, fmt.Errorf("too many secret path prefixes")
	}
	normalized := make([]string, 0, len(prefixes))
	seen := make(map[string]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if !validSecretPath(prefix) {
			return nil, fmt.Errorf("invalid stored secret path prefix")
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
	}
	return normalized, nil
}

func (access secretPrefixAccess) allows(path string) bool {
	if access.unrestricted {
		return true
	}
	for _, prefix := range access.prefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func (access secretPrefixAccess) intersects(path string) bool {
	if access.unrestricted {
		return true
	}
	for _, prefix := range access.prefixes {
		if path == prefix ||
			strings.HasPrefix(path, prefix+"/") ||
			strings.HasPrefix(prefix, path+"/") {
			return true
		}
	}
	return false
}

func (access secretPrefixAccess) contains(candidate string) bool {
	if access.unrestricted {
		return true
	}
	for _, prefix := range access.prefixes {
		if candidate == prefix || strings.HasPrefix(candidate, prefix+"/") {
			return true
		}
	}
	return false
}

func (access secretPrefixAccess) intersect(other secretPrefixAccess) secretPrefixAccess {
	if access.unrestricted {
		return other
	}
	if other.unrestricted {
		return access
	}
	intersection := secretPrefixAccess{prefixes: make([]string, 0)}
	seen := make(map[string]struct{})
	for _, left := range access.prefixes {
		for _, right := range other.prefixes {
			switch {
			case left == right || strings.HasPrefix(left, right+"/"):
				if _, exists := seen[left]; !exists {
					intersection.prefixes = append(intersection.prefixes, left)
					seen[left] = struct{}{}
				}
			case strings.HasPrefix(right, left+"/"):
				if _, exists := seen[right]; !exists {
					intersection.prefixes = append(intersection.prefixes, right)
					seen[right] = struct{}{}
				}
			}
		}
	}
	encoded, _ := json.Marshal(intersection.prefixes)
	intersection.encoded = string(encoded)
	return intersection
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
	var encoded string
	if err := s.db.QueryRow(
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
			"SELECT role, locked, secret_prefixes FROM accounts WHERE username = ?",
			createdBy.String,
		).Scan(&role, &locked, &accountPrefixes)
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
		return s.secretsDB.Query("SELECT path FROM secrets ORDER BY path")
	}
	return s.secretsDB.Query(`
		SELECT path
		FROM secrets
		WHERE EXISTS (
			SELECT 1
			FROM json_each(?) AS prefix
			WHERE secrets.path = prefix.value
			   OR substr(secrets.path, 1, length(prefix.value) + 1) = prefix.value || '/'
		)
		ORDER BY path`,
		access.encoded,
	)
}

func (s *server) updateOperatorSecretPrefixes(w http.ResponseWriter, r *http.Request) {
	actor := s.auditRequestActor(r, "web")
	if !s.requireAdmin(w, r) {
		s.recordAuditEvent(r, "update_operator_scopes", "failure", actor, "web", "operator", "unauthorized")
		return
	}
	if r.TLS == nil {
		s.recordAuditEvent(r, "update_operator_scopes", "failure", actor, "web", "operator", "https_required")
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request struct {
		Username string   `json:"username"`
		Prefixes []string `json:"prefixes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.recordAuditEvent(r, "update_operator_scopes", "failure", actor, "web", "operator", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		s.recordAuditEvent(r, "update_operator_scopes", "failure", actor, "web", "operator", "invalid_username")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid username is required"})
		return
	}
	prefixes, err := normalizeSecretPrefixes(request.Prefixes)
	if err != nil {
		s.recordAuditEvent(r, "update_operator_scopes", "failure", actor, "web", "operator:"+request.Username, "invalid_secret_prefixes")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	encoded, err := encodeSecretPrefixes(prefixes)
	if err != nil {
		s.recordAuditEvent(r, "update_operator_scopes", "failure", actor, "web", "operator:"+request.Username, "encoding_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save secret path prefixes"})
		return
	}
	result, err := s.db.Exec(
		"UPDATE accounts SET secret_prefixes = ? WHERE username = ? AND role = 'operator'",
		encoded, request.Username,
	)
	if err != nil {
		s.recordAuditEvent(r, "update_operator_scopes", "failure", actor, "web", "operator:"+request.Username, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update operator secret access"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		s.recordAuditEvent(r, "update_operator_scopes", "failure", actor, "web", "operator:"+request.Username, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update operator secret access"})
		return
	}
	if updated != 1 {
		s.recordAuditEvent(r, "update_operator_scopes", "failure", actor, "web", "operator:"+request.Username, "operator_not_found")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
		return
	}
	s.recordAuditEvent(r, "update_operator_scopes", "success", actor, "web", "operator:"+request.Username, "")
	writeJSON(w, http.StatusOK, map[string]any{"username": request.Username, "prefixes": prefixes})
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
	if r.TLS == nil {
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
