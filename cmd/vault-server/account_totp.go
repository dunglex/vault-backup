package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type accountTOTPState struct {
	passwordHash       string
	secret             sql.NullString
	enabled            bool
	recoveryCodeHashes []string
}

func (s *server) getAccountTOTP(w http.ResponseWriter, r *http.Request) {
	session, ok := s.accountTOTPRequest(w, r)
	if !ok {
		return
	}
	state, err := s.loadAccountTOTP(session.username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read two-factor settings"})
		return
	}
	pending := !state.enabled && state.secret.Valid && state.secret.String != ""
	enforced, err := s.mfaEnforcementEnabled()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read MFA settings"})
		return
	}
	response := map[string]any{
		"enabled":                  state.enabled,
		"enforced":                 enforced,
		"setup_pending":            pending,
		"recovery_codes_remaining": len(state.recoveryCodeHashes),
	}
	if pending {
		response["secret"] = state.secret.String
		response["provisioning_uri"] = totpProvisioningURI(state.secret.String, session.username)
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *server) setupAccountTOTP(w http.ResponseWriter, r *http.Request) {
	session, ok := s.accountTOTPRequest(w, r)
	if !ok {
		return
	}
	state, err := s.loadAccountTOTP(session.username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read account"})
		return
	}
	if state.enabled {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "two-factor authentication is already enabled"})
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create authenticator secret"})
		return
	}
	result, err := s.db.Exec(
		"UPDATE accounts SET totp_secret = ?, totp_recovery_codes = '[]' WHERE username = ? AND totp_enabled = 0",
		secret,
		session.username,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save authenticator setup"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save authenticator setup"})
		return
	}
	if updated != 1 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account security settings changed; reload and try again"})
		return
	}
	s.recordAuditEvent(r, "start_mfa_setup", "success", session.username, "web", "account:"+session.username, "")
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":           secret,
		"provisioning_uri": totpProvisioningURI(secret, session.username),
	})
}

func (s *server) enableAccountTOTP(w http.ResponseWriter, r *http.Request) {
	session, ok := s.accountTOTPRequest(w, r)
	if !ok {
		return
	}
	var request struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	state, err := s.loadAccountTOTP(session.username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read account security settings"})
		return
	}
	if state.enabled {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "two-factor authentication is already enabled"})
		return
	}
	if !state.secret.Valid || state.secret.String == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "start authenticator setup before enabling it"})
		return
	}
	if !verifyTOTP(state.secret.String, request.Code, time.Now()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid authenticator code"})
		return
	}
	recoveryCodes, hashes, err := generateRecoveryCodes()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate recovery codes"})
		return
	}
	encodedHashes, err := json.Marshal(hashes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save recovery codes"})
		return
	}
	result, err := s.db.Exec(
		"UPDATE accounts SET totp_enabled = 1, totp_recovery_codes = ? WHERE username = ? AND totp_enabled = 0 AND totp_secret = ?",
		string(encodedHashes),
		session.username,
		state.secret.String,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not enable two-factor authentication"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not enable two-factor authentication"})
		return
	}
	if updated != 1 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account security settings changed; reload and try again"})
		return
	}
	s.recordAuditEvent(r, "enable_mfa", "success", session.username, "web", "account:"+session.username, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":        true,
		"recovery_codes": recoveryCodes,
	})
}

func (s *server) regenerateAccountRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	session, ok := s.accountTOTPRequest(w, r)
	if !ok {
		return
	}
	auditFailure := func(outcome string) {
		s.recordAuditEvent(r, "regenerate_mfa_recovery_codes", "failure", session.username, "web", "account:"+session.username, outcome)
	}
	var request struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		auditFailure("invalid_request")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		auditFailure("storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not regenerate recovery codes"})
		return
	}
	defer tx.Rollback()

	var passwordHash, encodedHashes string
	var secret sql.NullString
	var enabled int
	if err := tx.QueryRow(`
		SELECT password_hash, totp_secret, totp_enabled, totp_recovery_codes
		FROM accounts WHERE username = ?`, session.username,
	).Scan(&passwordHash, &secret, &enabled, &encodedHashes); err != nil {
		auditFailure("storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read account security settings"})
		return
	}
	if enabled != 1 || !secret.Valid || secret.String == "" {
		auditFailure("two_factor_not_enabled")
		writeJSON(w, http.StatusConflict, map[string]string{"error": "two-factor authentication is not enabled"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(request.Password)) != nil {
		auditFailure("invalid_password")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
		return
	}

	validFactor := verifyTOTP(secret.String, request.Code, time.Now())
	if !validFactor {
		var hashes []string
		if err := json.Unmarshal([]byte(encodedHashes), &hashes); err != nil {
			auditFailure("storage_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read recovery codes"})
			return
		}
		candidate := hashRecoveryCode(request.Code)
		for _, hash := range hashes {
			if subtle.ConstantTimeCompare([]byte(hash), []byte(candidate)) == 1 {
				validFactor = true
			}
		}
	}
	if !validFactor {
		auditFailure("invalid_authentication_code")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authentication code"})
		return
	}

	recoveryCodes, hashes, err := generateRecoveryCodes()
	if err != nil {
		auditFailure("generation_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate recovery codes"})
		return
	}
	encodedNewHashes, err := json.Marshal(hashes)
	if err != nil {
		auditFailure("storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save recovery codes"})
		return
	}
	result, err := tx.Exec(
		"UPDATE accounts SET totp_recovery_codes = ? WHERE username = ? AND totp_enabled = 1 AND totp_secret = ?",
		string(encodedNewHashes),
		session.username,
		secret.String,
	)
	if err != nil {
		auditFailure("storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save recovery codes"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		auditFailure("storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save recovery codes"})
		return
	}
	if updated != 1 {
		auditFailure("account_changed")
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account security settings changed; reload and try again"})
		return
	}
	if err := tx.Commit(); err != nil {
		auditFailure("storage_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save recovery codes"})
		return
	}
	s.recordAuditEvent(r, "regenerate_mfa_recovery_codes", "success", session.username, "web", "account:"+session.username, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": recoveryCodes,
	})
}

func (s *server) disableAccountTOTP(w http.ResponseWriter, r *http.Request) {
	session, ok := s.accountTOTPRequest(w, r)
	if !ok {
		return
	}
	enforced, err := s.mfaEnforcementEnabled()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read MFA settings"})
		return
	}
	if enforced {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MFA cannot be disabled while enforcement is enabled"})
		return
	}
	var request struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	state, err := s.loadAccountTOTP(session.username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read account security settings"})
		return
	}
	if !state.enabled {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "two-factor authentication is not enabled"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(state.passwordHash), []byte(request.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
		return
	}
	valid, err := s.verifyAccountSecondFactor(session.username, state.secret.String, request.Code)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not verify authentication code"})
		return
	}
	if !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authentication code"})
		return
	}
	result, err := s.db.Exec(
		"UPDATE accounts SET totp_secret = NULL, totp_enabled = 0, totp_recovery_codes = '[]' WHERE username = ? AND totp_enabled = 1",
		session.username,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not disable two-factor authentication"})
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not disable two-factor authentication"})
		return
	}
	if updated != 1 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account security settings changed; reload and try again"})
		return
	}
	s.recordAuditEvent(r, "disable_mfa", "success", session.username, "web", "account:"+session.username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": false})
}

func (s *server) accountTOTPRequest(w http.ResponseWriter, r *http.Request) (sessionInfo, bool) {
	session, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return sessionInfo{}, false
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required for account security settings"})
		return sessionInfo{}, false
	}
	return session, true
}

func (s *server) loadAccountTOTP(username string) (accountTOTPState, error) {
	var state accountTOTPState
	var enabled int
	var encodedHashes string
	err := s.db.QueryRow(`
		SELECT password_hash, totp_secret, totp_enabled, totp_recovery_codes
		FROM accounts WHERE username = ?`, username,
	).Scan(&state.passwordHash, &state.secret, &enabled, &encodedHashes)
	if err != nil {
		return accountTOTPState{}, err
	}
	state.enabled = enabled == 1
	if err := json.Unmarshal([]byte(encodedHashes), &state.recoveryCodeHashes); err != nil {
		return accountTOTPState{}, fmt.Errorf("decode account recovery codes: %w", err)
	}
	if state.recoveryCodeHashes == nil {
		state.recoveryCodeHashes = []string{}
	}
	return state, nil
}

func (s *server) verifyAccountSecondFactor(username, secret, code string) (bool, error) {
	if verifyTOTP(secret, code, time.Now()) {
		return true, nil
	}
	return s.consumeRecoveryCode(username, code)
}

func (s *server) consumeRecoveryCode(username, code string) (bool, error) {
	candidate := hashRecoveryCode(code)
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var encodedHashes string
	if err := tx.QueryRow(
		"SELECT totp_recovery_codes FROM accounts WHERE username = ? AND totp_enabled = 1",
		username,
	).Scan(&encodedHashes); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	var hashes []string
	if err := json.Unmarshal([]byte(encodedHashes), &hashes); err != nil {
		return false, fmt.Errorf("decode account recovery codes: %w", err)
	}
	match := -1
	for index, hash := range hashes {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(candidate)) == 1 {
			match = index
		}
	}
	if match < 0 {
		return false, nil
	}
	hashes = append(hashes[:match], hashes[match+1:]...)
	updatedHashes, err := json.Marshal(hashes)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(
		"UPDATE accounts SET totp_recovery_codes = ? WHERE username = ? AND totp_enabled = 1",
		string(updatedHashes),
		username,
	); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func totpProvisioningURI(secret, username string) string {
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", "Vault Server")
	query.Set("algorithm", "SHA1")
	query.Set("digits", "6")
	query.Set("period", fmt.Sprintf("%d", int(totpPeriod/time.Second)))
	return "otpauth://totp/Vault%20Server:" + url.PathEscape(username) + "?" + query.Encode()
}
