package operator

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestRenderPageIncludesOperatorManagementControls(t *testing.T) {
	var page bytes.Buffer
	if err := RenderPage(&page); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		`id="operatorForm"`,
		`id="operatorMounts"`,
		"/v1/operators",
		`href="/operators.html"`,
		`href="/mounts.html"`,
		`href="/security.html"`,
	} {
		if !strings.Contains(page.String(), marker) {
			t.Errorf("operator page missing %q", marker)
		}
	}
}

func TestRenderPageIncludesBackupNavigationWhenEnabled(t *testing.T) {
	var page bytes.Buffer
	if err := RenderPageWithOptions(&page, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), `href="/backup.html"`) {
		t.Error("operator page missing backup navigation")
	}
}

func TestMigrateLegacyAccountsMovesOperatorsAndSessions(t *testing.T) {
	source := openTestDB(t, "source.db")
	destination := openTestDB(t, "operator.db")
	if err := Initialize(destination); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`
		CREATE TABLE accounts (
			username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL,
			secret_prefixes TEXT NOT NULL, secret_mounts TEXT NOT NULL DEFAULT '[]',
			locked INTEGER NOT NULL, must_change_password INTEGER NOT NULL,
			totp_secret TEXT, totp_enabled INTEGER NOT NULL, totp_recovery_codes TEXT NOT NULL
		);
		CREATE TABLE web_sessions (
			token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL,
			ttl_seconds INTEGER NOT NULL, created_at INTEGER NOT NULL,
			FOREIGN KEY(username) REFERENCES accounts(username) ON DELETE CASCADE
		);
		PRAGMA foreign_keys = ON;
		INSERT INTO accounts(username, password_hash, role, secret_prefixes, secret_mounts, locked, must_change_password, totp_secret, totp_enabled, totp_recovery_codes)
		VALUES ('operator-one', 'password-hash', 'operator', '["team-a"]', '[]', 0, 1, NULL, 0, '[]');
		INSERT INTO web_sessions VALUES ('session-hash', 'operator-one', 200, 30, 100);
	`); err != nil {
		t.Fatal(err)
	}

	if err := MigrateLegacyAccounts(source, destination); err != nil {
		t.Fatal(err)
	}
	account, err := LoadAccount(destination, "operator-one")
	if err != nil {
		t.Fatal(err)
	}
	if account.PasswordHash != "password-hash" || account.SecretMounts != `[]` || account.MustChangePassword != 1 {
		t.Fatalf("migrated account = %#v", account)
	}
	var migratedSessions int
	if err := destination.QueryRow("SELECT COUNT(*) FROM web_sessions WHERE token_hash = 'session-hash'").Scan(&migratedSessions); err != nil {
		t.Fatal(err)
	}
	if migratedSessions != 1 {
		t.Fatalf("migrated session count = %d, want 1", migratedSessions)
	}
	var legacyAccounts int
	if err := source.QueryRow("SELECT COUNT(*) FROM accounts WHERE role = 'operator'").Scan(&legacyAccounts); err != nil {
		t.Fatal(err)
	}
	if legacyAccounts != 0 {
		t.Fatalf("legacy operator account count = %d, want 0", legacyAccounts)
	}
}

func TestMigrateLegacyAccountsDoesNotDeleteOnConflict(t *testing.T) {
	source := openTestDB(t, "source.db")
	destination := openTestDB(t, "operator.db")
	if err := Initialize(destination); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`
		CREATE TABLE accounts (
			username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL,
			secret_prefixes TEXT NOT NULL, secret_mounts TEXT NOT NULL DEFAULT '[]',
			locked INTEGER NOT NULL, must_change_password INTEGER NOT NULL,
			totp_secret TEXT, totp_enabled INTEGER NOT NULL, totp_recovery_codes TEXT NOT NULL
		);
		CREATE TABLE web_sessions (
			token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL,
			ttl_seconds INTEGER NOT NULL, created_at INTEGER NOT NULL
		);
		INSERT INTO accounts(username, password_hash, role, secret_prefixes, secret_mounts, locked, must_change_password, totp_secret, totp_enabled, totp_recovery_codes)
		VALUES ('operator-one', 'source-hash', 'operator', '[]', '[]', 0, 0, NULL, 0, '[]');
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := destination.Exec(
		"INSERT INTO accounts(username, password_hash, role) VALUES ('operator-one', 'different-hash', 'operator')",
	); err != nil {
		t.Fatal(err)
	}

	if err := MigrateLegacyAccounts(source, destination); err == nil {
		t.Fatal("migration succeeded despite conflicting destination account")
	}
	var legacyAccounts int
	if err := source.QueryRow("SELECT COUNT(*) FROM accounts WHERE role = 'operator'").Scan(&legacyAccounts); err != nil {
		t.Fatal(err)
	}
	if legacyAccounts != 1 {
		t.Fatalf("legacy account was deleted after conflict: count %d", legacyAccounts)
	}
}

func openTestDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})
	return db
}
