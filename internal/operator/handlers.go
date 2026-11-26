package operator

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type operatorRequest struct {
	Username             string   `json:"username"`
	Password             string   `json:"password"`
	PasswordConfirmation string   `json:"password_confirmation"`
	Prefixes             []string `json:"prefixes"`
}

type operatorSummary struct {
	Username      string   `json:"username"`
	Locked        bool     `json:"locked"`
	MFAEnabled    bool     `json:"mfa_enabled"`
	MFAConfigured bool     `json:"mfa_configured"`
	Prefixes      []string `json:"prefixes"`
}

func (h *Handler) ListOperators(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	rows, err := h.db.Query("SELECT username FROM accounts WHERE role = 'operator' ORDER BY username")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
		return
	}
	defer rows.Close()

	operators := make([]string, 0)
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
			return
		}
		operators = append(operators, username)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"operators": operators})
}

func (h *Handler) ListOperatorDetails(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	rows, err := h.db.Query(`
		SELECT username, locked, totp_enabled, (totp_secret IS NOT NULL AND totp_secret != ''), secret_prefixes
		FROM accounts WHERE role = 'operator' ORDER BY username`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
		return
	}
	defer rows.Close()

	operators := make([]operatorSummary, 0)
	for rows.Next() {
		var operator operatorSummary
		var locked, mfaEnabled, mfaPending int
		var encodedPrefixes string
		if err := rows.Scan(&operator.Username, &locked, &mfaEnabled, &mfaPending, &encodedPrefixes); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
			return
		}
		operator.Prefixes, err = h.decodeSecretPrefixes(encodedPrefixes)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operator secret access"})
			return
		}
		operator.Locked = locked == 1
		operator.MFAEnabled = mfaEnabled == 1
		operator.MFAConfigured = operator.MFAEnabled || mfaPending == 1
		operators = append(operators, operator)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operators"})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]operatorSummary{"operators": operators})
}

func (h *Handler) UpdateSecretPrefixes(w http.ResponseWriter, r *http.Request) {
	actor := h.actor(r, "web")
	if !h.requireAdmin(w, r) {
		h.audit(r, "update_operator_scopes", "failure", actor, "web", "operator", "unauthorized")
		return
	}
	if r.TLS == nil {
		h.audit(r, "update_operator_scopes", "failure", actor, "web", "operator", "https_required")
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request struct {
		Username string   `json:"username"`
		Prefixes []string `json:"prefixes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.audit(r, "update_operator_scopes", "failure", actor, "web", "operator", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		h.audit(r, "update_operator_scopes", "failure", actor, "web", "operator", "invalid_username")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid username is required"})
		return
	}
	prefixes, err := h.normalizeSecretPrefixes(request.Prefixes)
	if err != nil {
		h.audit(r, "update_operator_scopes", "failure", actor, "web", "operator:"+request.Username, "invalid_secret_prefixes")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	encoded, err := EncodeSecretPrefixes(prefixes)
	if err != nil {
		h.audit(r, "update_operator_scopes", "failure", actor, "web", "operator:"+request.Username, "encoding_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save secret path prefixes"})
		return
	}
	result, err := h.db.Exec(
		"UPDATE accounts SET secret_prefixes = ? WHERE username = ? AND role = 'operator'",
		encoded, request.Username,
	)
	if err != nil {
		h.audit(r, "update_operator_scopes", "failure", actor, "web", "operator:"+request.Username, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update operator secret access"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		h.audit(r, "update_operator_scopes", "failure", actor, "web", "operator:"+request.Username, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update operator secret access"})
		return
	}
	if updated != 1 {
		h.audit(r, "update_operator_scopes", "failure", actor, "web", "operator:"+request.Username, "operator_not_found")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
		return
	}
	h.audit(r, "update_operator_scopes", "success", actor, "web", "operator:"+request.Username, "")
	writeJSON(w, http.StatusOK, map[string]any{"username": request.Username, "prefixes": prefixes})
}

func (h *Handler) SetOperatorLock(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request struct {
		Username string `json:"username"`
		Locked   *bool  `json:"locked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Locked == nil {
		h.audit(r, "update_operator_lock", "failure", h.actor(r, "web"), "web", "", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and locked status are required"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		h.audit(r, "update_operator_lock", "failure", h.actor(r, "web"), "web", "", "invalid_username")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid username is required"})
		return
	}

	tx, err := h.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update operator"})
		return
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow("SELECT 1 FROM accounts WHERE username = ? AND role = 'operator'", request.Username).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			h.audit(r, "update_operator_lock", "failure", h.actor(r, "web"), "web", "operator:"+request.Username, "operator_not_found")
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operator"})
		return
	}
	if _, err := tx.Exec("UPDATE accounts SET locked = ? WHERE username = ? AND role = 'operator'", *request.Locked, request.Username); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update operator"})
		return
	}
	if *request.Locked {
		if _, err := tx.Exec("DELETE FROM web_sessions WHERE username = ?", request.Username); err != nil {
			log.Printf("ERROR: could not revoke locked operator sessions: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke operator sessions"})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update operator"})
		return
	}
	if *request.Locked {
		h.deps.RevokeSessions(request.Username)
	}
	action := "unlock_operator"
	if *request.Locked {
		action = "lock_operator"
	}
	h.audit(r, action, "success", h.actor(r, "web"), "web", "operator:"+request.Username, "")
	writeJSON(w, http.StatusOK, map[string]any{"username": request.Username, "locked": *request.Locked})
}

func (h *Handler) RemoveOperatorTOTP(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.audit(r, "remove_operator_mfa", "failure", h.actor(r, "web"), "web", "", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		h.audit(r, "remove_operator_mfa", "failure", h.actor(r, "web"), "web", "", "invalid_username")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid username is required"})
		return
	}

	tx, err := h.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator two-factor authentication"})
		return
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow("SELECT 1 FROM accounts WHERE username = ? AND role = 'operator'", request.Username).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			h.audit(r, "remove_operator_mfa", "failure", h.actor(r, "web"), "web", "operator:"+request.Username, "operator_not_found")
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operator"})
		return
	}
	if _, err := tx.Exec(
		"UPDATE accounts SET totp_secret = NULL, totp_enabled = 0, totp_recovery_codes = '[]' WHERE username = ? AND role = 'operator'",
		request.Username,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator two-factor authentication"})
		return
	}
	if _, err := tx.Exec("DELETE FROM web_sessions WHERE username = ?", request.Username); err != nil {
		log.Printf("ERROR: could not revoke operator sessions after MFA reset: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke operator sessions"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator two-factor authentication"})
		return
	}
	h.deps.RevokeSessions(request.Username)
	h.audit(r, "remove_operator_mfa", "success", h.actor(r, "web"), "web", "operator:"+request.Username, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"username":       request.Username,
		"mfa_enabled":    false,
		"mfa_configured": false,
	})
}

func (h *Handler) CreateOperator(w http.ResponseWriter, r *http.Request) {
	actor := h.actor(r, "web")
	if !h.requireAdmin(w, r) {
		h.audit(r, "create_operator", "failure", actor, "web", "operator", "unauthorized")
		return
	}
	if r.TLS == nil {
		h.audit(r, "create_operator", "failure", actor, "web", "operator", "https_required")
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request operatorRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.audit(r, "create_operator", "failure", actor, "web", "operator", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		h.audit(r, "create_operator", "failure", actor, "web", "operator", "invalid_username")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required and must be at most 128 characters"})
		return
	}
	prefixes, err := h.normalizeSecretPrefixes(request.Prefixes)
	if err != nil {
		h.audit(r, "create_operator", "failure", actor, "web", "operator:"+request.Username, "invalid_secret_prefixes")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	encodedPrefixes, err := EncodeSecretPrefixes(prefixes)
	if err != nil {
		h.audit(r, "create_operator", "failure", actor, "web", "operator:"+request.Username, "encoding_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create operator"})
		return
	}
	generatedPassword := request.Password == "" && request.PasswordConfirmation == ""
	if (request.Password == "") != (request.PasswordConfirmation == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passwords must both be provided or omitted"})
		return
	}
	if generatedPassword {
		password, err := generateOperatorTemporaryPassword()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate operator password"})
			return
		}
		request.Password = password
		request.PasswordConfirmation = request.Password
	}
	if subtle.ConstantTimeCompare([]byte(request.Password), []byte(request.PasswordConfirmation)) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passwords do not match"})
		return
	}
	if len(request.Password) < 12 || len(request.Password) > 72 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 12 characters and no more than 72 bytes"})
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create operator"})
		return
	}
	if exists, err := h.deps.AccountExists(request.Username); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not check account name"})
		return
	} else if exists {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an account with that username already exists"})
		return
	}
	result, err := h.db.Exec(
		"INSERT INTO accounts(username, password_hash, role, secret_prefixes, must_change_password) VALUES (?, ?, 'operator', ?, 1) ON CONFLICT(username) DO NOTHING",
		request.Username,
		string(passwordHash),
		encodedPrefixes,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create operator"})
		return
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create operator"})
		return
	}
	if inserted == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an account with that username already exists"})
		return
	}
	h.audit(r, "create_operator", "success", actor, "web", "operator:"+request.Username, "")
	response := map[string]any{
		"username":             request.Username,
		"role":                 "operator",
		"must_change_password": true,
	}
	if generatedPassword {
		response["initial_password"] = request.Password
	}
	writeJSON(w, http.StatusCreated, response)
}

func generateOperatorTemporaryPassword() (string, error) {
	length, err := rand.Int(rand.Reader, big.NewInt(9))
	if err != nil {
		return "", err
	}
	randomBytes := make([]byte, 15)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", err
	}
	password := base64.RawURLEncoding.EncodeToString(randomBytes)
	return password[:12+length.Int64()], nil
}

func (h *Handler) ResetOperatorPassword(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	actor := h.actor(r, "web")
	if r.TLS == nil {
		h.audit(r, "reset_operator_password", "failure", actor, "web", "", "https_required")
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.audit(r, "reset_operator_password", "failure", actor, "web", "", "invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		h.audit(r, "reset_operator_password", "failure", actor, "web", "", "invalid_username")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid username is required"})
		return
	}
	resource := "operator:" + request.Username
	temporaryPassword, err := generateOperatorTemporaryPassword()
	if err != nil {
		h.audit(r, "reset_operator_password", "failure", actor, "web", resource, "password_generation_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(temporaryPassword), bcrypt.DefaultCost)
	if err != nil {
		h.audit(r, "reset_operator_password", "failure", actor, "web", resource, "password_hash_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}

	tx, err := h.db.Begin()
	if err != nil {
		h.audit(r, "reset_operator_password", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow(
		"SELECT 1 FROM accounts WHERE username = ? AND role = 'operator'",
		request.Username,
	).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			h.audit(r, "reset_operator_password", "failure", actor, "web", resource, "operator_not_found")
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
			return
		}
		h.audit(r, "reset_operator_password", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operator"})
		return
	}
	result, err := tx.Exec(
		"UPDATE accounts SET password_hash = ?, must_change_password = 1 WHERE username = ? AND role = 'operator'",
		string(passwordHash),
		request.Username,
	)
	if err != nil {
		h.audit(r, "reset_operator_password", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		h.audit(r, "reset_operator_password", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}
	if updated != 1 {
		h.audit(r, "reset_operator_password", "failure", actor, "web", resource, "operator_not_found")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
		return
	}
	if _, err := tx.Exec("DELETE FROM web_sessions WHERE username = ?", request.Username); err != nil {
		log.Printf("ERROR: could not revoke sessions after operator password reset: %v", err)
		h.audit(r, "reset_operator_password", "failure", actor, "web", resource, "session_revocation_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke operator sessions"})
		return
	}
	if err := tx.Commit(); err != nil {
		h.audit(r, "reset_operator_password", "failure", actor, "web", resource, "storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not reset operator password"})
		return
	}
	h.deps.RevokeSessions(request.Username)
	h.audit(r, "reset_operator_password", "success", actor, "web", resource, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"username":             request.Username,
		"temporary_password":   temporaryPassword,
		"must_change_password": true,
	})
}

func (h *Handler) DeleteOperator(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to manage operator accounts"})
		return
	}
	var request struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid username is required"})
		return
	}
	var exists int
	if err := h.db.QueryRow(
		"SELECT 1 FROM accounts WHERE username = ? AND role = 'operator'",
		request.Username,
	).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "operator not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read operator"})
		return
	}
	if err := h.deps.RevokeTokens(request.Username); err != nil {
		log.Printf("ERROR: could not revoke operator API credentials: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator"})
		return
	}
	accountTx, err := h.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator"})
		return
	}
	defer accountTx.Rollback()
	if _, err := accountTx.Exec("DELETE FROM accounts WHERE username = ? AND role = 'operator'", request.Username); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator"})
		return
	}
	if _, err := accountTx.Exec("DELETE FROM web_sessions WHERE username = ?", request.Username); err != nil {
		log.Printf("ERROR: could not revoke deleted operator sessions: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke operator sessions"})
		return
	}
	if err := accountTx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove operator"})
		return
	}
	h.deps.RevokeSessions(request.Username)
	h.audit(r, "delete_operator", "success", h.actor(r, "web"), "web", "operator:"+request.Username, "")
	writeJSON(w, http.StatusOK, map[string]string{"username": request.Username, "status": "deleted"})
}
