package operator

import (
	"database/sql"
	"fmt"
)

type Account struct {
	Username           string
	PasswordHash       string
	Role               string
	SecretPrefixes     string
	Locked             int
	MustChangePassword int
	TOTPSecret         sql.NullString
	TOTPEnabled        int
	TOTPRecoveryCodes  string
}

func Initialize(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS accounts (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'operator' CHECK (role = 'operator'),
			secret_prefixes TEXT NOT NULL DEFAULT '[]',
			locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1)),
			must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
			totp_secret TEXT,
			totp_enabled INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1)),
			totp_recovery_codes TEXT NOT NULL DEFAULT '[]',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS web_sessions (
			token_hash TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			ttl_seconds INTEGER NOT NULL CHECK (ttl_seconds > 0),
			created_at INTEGER NOT NULL,
			FOREIGN KEY(username) REFERENCES accounts(username) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(username);
		CREATE INDEX IF NOT EXISTS idx_web_sessions_expires_at ON web_sessions(expires_at);
	`)
	if err != nil {
		return fmt.Errorf("initialize operator database: %w", err)
	}
	return nil
}

func LoadAccount(db *sql.DB, username string) (Account, error) {
	var account Account
	err := db.QueryRow(`
		SELECT username, password_hash, role, secret_prefixes, locked, must_change_password,
		       totp_secret, totp_enabled, totp_recovery_codes
		FROM accounts WHERE username = ? AND role = 'operator'`,
		username,
	).Scan(
		&account.Username,
		&account.PasswordHash,
		&account.Role,
		&account.SecretPrefixes,
		&account.Locked,
		&account.MustChangePassword,
		&account.TOTPSecret,
		&account.TOTPEnabled,
		&account.TOTPRecoveryCodes,
	)
	return account, err
}

func MigrateLegacyAccounts(source, destination *sql.DB) error {
	rows, err := source.Query(`
		SELECT username, password_hash, role, secret_prefixes, locked, must_change_password,
		       totp_secret, totp_enabled, totp_recovery_codes
		FROM accounts WHERE role = 'operator' ORDER BY username`)
	if err != nil {
		return fmt.Errorf("read legacy operator accounts: %w", err)
	}
	defer rows.Close()

	accounts := make([]Account, 0)
	for rows.Next() {
		var account Account
		if err := rows.Scan(
			&account.Username,
			&account.PasswordHash,
			&account.Role,
			&account.SecretPrefixes,
			&account.Locked,
			&account.MustChangePassword,
			&account.TOTPSecret,
			&account.TOTPEnabled,
			&account.TOTPRecoveryCodes,
		); err != nil {
			return fmt.Errorf("read legacy operator account: %w", err)
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read legacy operator accounts: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy operator accounts: %w", err)
	}
	if len(accounts) == 0 {
		return nil
	}

	tx, err := destination.Begin()
	if err != nil {
		return fmt.Errorf("begin operator account migration: %w", err)
	}
	defer tx.Rollback()

	for _, account := range accounts {
		if _, err := tx.Exec(`
			INSERT INTO accounts(
				username, password_hash, role, secret_prefixes, locked, must_change_password,
				totp_secret, totp_enabled, totp_recovery_codes
			) VALUES (?, ?, 'operator', ?, ?, ?, ?, ?, ?)
			ON CONFLICT(username) DO NOTHING`,
			account.Username,
			account.PasswordHash,
			account.SecretPrefixes,
			account.Locked,
			account.MustChangePassword,
			account.TOTPSecret,
			account.TOTPEnabled,
			account.TOTPRecoveryCodes,
		); err != nil {
			return fmt.Errorf("copy legacy operator account: %w", err)
		}
		migrated, err := LoadAccountTx(tx, account.Username)
		if err != nil {
			return fmt.Errorf("verify migrated operator account: %w", err)
		}
		if migrated != account {
			return fmt.Errorf("operator account migration conflicts with existing data")
		}

		sessionRows, err := source.Query(`
			SELECT token_hash, username, expires_at, ttl_seconds, created_at
			FROM web_sessions WHERE username = ?`, account.Username)
		if err != nil {
			return fmt.Errorf("read legacy operator sessions: %w", err)
		}
		for sessionRows.Next() {
			var tokenHash, username string
			var expiresAt, ttlSeconds, createdAt int64
			if err := sessionRows.Scan(&tokenHash, &username, &expiresAt, &ttlSeconds, &createdAt); err != nil {
				sessionRows.Close()
				return fmt.Errorf("read legacy operator session: %w", err)
			}
			if _, err := tx.Exec(`
				INSERT INTO web_sessions(token_hash, username, expires_at, ttl_seconds, created_at)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(token_hash) DO NOTHING`,
				tokenHash, username, expiresAt, ttlSeconds, createdAt,
			); err != nil {
				sessionRows.Close()
				return fmt.Errorf("copy legacy operator session: %w", err)
			}
		}
		if err := sessionRows.Err(); err != nil {
			sessionRows.Close()
			return fmt.Errorf("read legacy operator sessions: %w", err)
		}
		if err := sessionRows.Close(); err != nil {
			return fmt.Errorf("close legacy operator sessions: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit operator account migration: %w", err)
	}
	if _, err := source.Exec("DELETE FROM accounts WHERE role = 'operator'"); err != nil {
		return fmt.Errorf("remove migrated operator accounts from app database: %w", err)
	}
	return nil
}

func LoadAccountTx(tx *sql.Tx, username string) (Account, error) {
	var account Account
	err := tx.QueryRow(`
		SELECT username, password_hash, role, secret_prefixes, locked, must_change_password,
		       totp_secret, totp_enabled, totp_recovery_codes
		FROM accounts WHERE username = ? AND role = 'operator'`,
		username,
	).Scan(
		&account.Username,
		&account.PasswordHash,
		&account.Role,
		&account.SecretPrefixes,
		&account.Locked,
		&account.MustChangePassword,
		&account.TOTPSecret,
		&account.TOTPEnabled,
		&account.TOTPRecoveryCodes,
	)
	return account, err
}
