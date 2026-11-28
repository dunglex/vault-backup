package main

import (
	"database/sql"
	"net/http"

	"vault-backup/internal/operator"
)

type accountRecord struct {
	username           string
	passwordHash       string
	role               string
	secretMounts       string
	locked             int
	mustChangePassword int
	totpSecret         sql.NullString
	totpEnabled        int
	totpRecoveryCodes  string
}

func (s *server) accountDatabase(role string) *sql.DB {
	switch role {
	case "admin":
		return s.db
	case "operator":
		return s.operatorDB
	default:
		return nil
	}
}

func (s *server) loadAccount(username string) (accountRecord, *sql.DB, error) {
	return s.loadAccountForRequest(nil, username)
}

func (s *server) loadAccountForRequest(r *http.Request, username string) (accountRecord, *sql.DB, error) {
	var account accountRecord
	_, err := measureDBQuery(r, func() (struct{}, error) {
		return struct{}{}, s.db.QueryRow(`
			SELECT username, password_hash, role, secret_mounts, locked, must_change_password,
			       totp_secret, totp_enabled, totp_recovery_codes
			FROM accounts WHERE username = ? AND role = 'admin'`,
			username,
		).Scan(
			&account.username,
			&account.passwordHash,
			&account.role,
			&account.secretMounts,
			&account.locked,
			&account.mustChangePassword,
			&account.totpSecret,
			&account.totpEnabled,
			&account.totpRecoveryCodes,
		)
	})
	if err == nil {
		return account, s.db, nil
	}
	if err != sql.ErrNoRows {
		return accountRecord{}, nil, err
	}
	if s.operatorDB == nil {
		return accountRecord{}, nil, sql.ErrNoRows
	}
	operatorAccount, err := measureDBQuery(r, func() (operator.Account, error) {
		return operator.LoadAccount(s.operatorDB, username)
	})
	if err != nil {
		return accountRecord{}, nil, err
	}
	return accountRecord{
		username:           operatorAccount.Username,
		passwordHash:       operatorAccount.PasswordHash,
		role:               operatorAccount.Role,
		secretMounts:       operatorAccount.SecretMounts,
		locked:             operatorAccount.Locked,
		mustChangePassword: operatorAccount.MustChangePassword,
		totpSecret:         operatorAccount.TOTPSecret,
		totpEnabled:        operatorAccount.TOTPEnabled,
		totpRecoveryCodes:  operatorAccount.TOTPRecoveryCodes,
	}, s.operatorDB, nil
}

func (s *server) accountExists(username string) (bool, error) {
	var exists int
	if err := s.db.QueryRow("SELECT 1 FROM accounts WHERE username = ?", username).Scan(&exists); err == nil {
		return true, nil
	} else if err != sql.ErrNoRows {
		return false, err
	}
	if s.operatorDB == nil {
		return false, nil
	}
	if err := s.operatorDB.QueryRow("SELECT 1 FROM accounts WHERE username = ?", username).Scan(&exists); err == nil {
		return true, nil
	} else if err == sql.ErrNoRows {
		return false, nil
	} else {
		return false, err
	}
}
