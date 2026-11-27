package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/CovenantSQL/go-sqlite3-encrypt"
	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

const (
	databaseKeyLength = 128
	argonTime         = uint32(3)
	argonMemory       = uint32(64 * 1024)
	argonThreads      = uint8(4)
)

type encryptedKeyFile struct {
	Version    int    `json:"version"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func isPlaintextSQLite(path string) (bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()

	const sqliteHeader = "SQLite format 3\x00"
	header := make([]byte, len(sqliteHeader))
	if _, err := io.ReadFull(file, header); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	return string(header) == sqliteHeader, nil
}

func openDatabase(path string, key []byte) (*sql.DB, bool, error) {
	return openDatabaseWithOptions(path, key, false)
}

func openDatabaseWithOptions(path string, key []byte, allowPlaintext bool) (*sql.DB, bool, error) {
	legacyDatabase, err := isPlaintextSQLite(path)
	if err != nil {
		return nil, false, err
	}

	driverName := "sqlite3"
	dsn := path + "?_crypto_key=" + hex.EncodeToString(key) + "&_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=1"
	if legacyDatabase {
		if !allowPlaintext {
			return nil, true, fmt.Errorf("existing database %s is plaintext SQLite; use --allow-plaintext-db or VAULT_SERVER_ALLOW_PLAINTEXT_DB=true only after acknowledging it is insecure", path)
		}
		driverName = "sqlite"
		dsn = path + "?_pragma=journal_mode(WAL)&_busy_timeout(5000)&_pragma=foreign_keys(1)"
		log.Printf("WARNING: plaintext SQLite database %s is allowed and remains unencrypted", path)
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, legacyDatabase, err
	}
	db.SetMaxOpenConns(1)
	return db, legacyDatabase, nil
}

func initializeDatabase(db *sql.DB) error {
	var legacySecretsTable int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'secrets'",
	).Scan(&legacySecretsTable); err != nil {
		return fmt.Errorf("check for legacy secrets table: %w", err)
	}
	if legacySecretsTable != 0 {
		return fmt.Errorf("legacy secrets table found in app database; this build does not migrate it, so reset the predeployment database before starting")
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS accounts (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'operator')),
			secret_prefixes TEXT NOT NULL DEFAULT '[]',
			secret_mounts TEXT NOT NULL DEFAULT '[]',
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
		CREATE TABLE IF NOT EXISTS api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			revoked_at INTEGER,
			secret_prefixes TEXT NOT NULL DEFAULT '[]',
			secret_mounts TEXT NOT NULL DEFAULT '[]',
			created_by TEXT
		);
		CREATE TABLE IF NOT EXISTS server_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS login_ip_failures (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_ip TEXT NOT NULL,
			failed_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_login_ip_failures_ip_time ON login_ip_failures(client_ip, failed_at);
		CREATE INDEX IF NOT EXISTS idx_login_ip_failures_time ON login_ip_failures(failed_at);
		CREATE TABLE IF NOT EXISTS blocked_login_ips (
			client_ip TEXT PRIMARY KEY,
			blocked_at INTEGER NOT NULL,
			failure_count INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS managed_client_certificates (
			serial_number TEXT PRIMARY KEY,
			token_id INTEGER NOT NULL,
			certificate_pem TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			not_after INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY(token_id) REFERENCES api_tokens(id)
		);
	`); err != nil {
		return err
	}
	if _, err := db.Exec("DELETE FROM server_settings WHERE key = 'auto_rotate_certificates'"); err != nil {
		return err
	}
	if err := ensureAccountRoleColumn(db); err != nil {
		return err
	}
	if err := ensureAccountTOTPColumns(db); err != nil {
		return err
	}
	if err := ensureAccountLockColumn(db); err != nil {
		return err
	}
	if err := ensureMustChangePasswordColumn(db); err != nil {
		return err
	}
	if err := allowDuplicateAPITokenNames(db); err != nil {
		return err
	}
	if err := ensureSecretMountColumns(db); err != nil {
		return err
	}
	if _, err := db.Exec("DELETE FROM web_sessions WHERE expires_at <= ?", time.Now().Unix()); err != nil {
		return fmt.Errorf("remove expired web sessions: %w", err)
	}
	return nil
}

func initializeSecretsDatabase(db *sql.DB) error {
	var exists int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'secrets'",
	).Scan(&exists); err != nil {
		return fmt.Errorf("check secrets table: %w", err)
	}
	if exists == 0 {
		if err := createVersionedSecretsSchema(db); err != nil {
			return err
		}
		if err := ensureMountTable(db); err != nil {
			return err
		}
		return migrateSecretNamespace(db)
	}

	columns, err := tableColumns(db, "secrets")
	if err != nil {
		return fmt.Errorf("inspect secrets table: %w", err)
	}
	if columns["current_version"] {
		if _, err := db.Exec(secretVersionsTableSchema); err != nil {
			return fmt.Errorf("initialize secret versions table: %w", err)
		}
		if err := ensureMountTable(db); err != nil {
			return err
		}
		return migrateSecretNamespace(db)
	}
	if !columns["path"] || !columns["data"] {
		return fmt.Errorf("unsupported secrets table schema")
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin secrets migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("ALTER TABLE secrets RENAME TO secrets_legacy"); err != nil {
		return fmt.Errorf("rename legacy secrets table: %w", err)
	}
	if _, err := tx.Exec(versionedSecretsTableSchema); err != nil {
		return fmt.Errorf("create versioned secrets table: %w", err)
	}
	if _, err := tx.Exec(secretVersionsTableSchema); err != nil {
		return fmt.Errorf("create secret versions table: %w", err)
	}
	timestamp := "CAST(strftime('%s', 'now') AS INTEGER)"
	if columns["updated_at"] {
		timestamp = "COALESCE(CAST(strftime('%s', updated_at) AS INTEGER), " + timestamp + ")"
	}
	if _, err := tx.Exec(`
		INSERT INTO secrets(path, current_version, created_at, updated_at)
		SELECT path, 1, ` + timestamp + `, ` + timestamp + `
		FROM secrets_legacy
	`); err != nil {
		return fmt.Errorf("migrate secret metadata: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO secret_versions(path, version, data, created_at)
		SELECT path, 1, data, ` + timestamp + `
		FROM secrets_legacy
	`); err != nil {
		return fmt.Errorf("migrate secret values: %w", err)
	}
	if _, err := tx.Exec("DROP TABLE secrets_legacy"); err != nil {
		return fmt.Errorf("remove legacy secrets table: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit secrets migration: %w", err)
	}
	if err := ensureMountTable(db); err != nil {
		return err
	}
	return migrateSecretNamespace(db)
}

const versionedSecretsTableSchema = `
	CREATE TABLE IF NOT EXISTS secrets (
		path TEXT PRIMARY KEY,
		current_version INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
`

const secretVersionsTableSchema = `
	CREATE TABLE IF NOT EXISTS secret_versions (
		path TEXT NOT NULL,
		version INTEGER NOT NULL CHECK (version > 0),
		data TEXT,
		created_at INTEGER NOT NULL,
		created_by TEXT,
		deleted_at INTEGER,
		destroyed_at INTEGER,
		PRIMARY KEY (path, version),
		FOREIGN KEY (path) REFERENCES secrets(path) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_secret_versions_created_at
		ON secret_versions(created_at);
`

func createVersionedSecretsSchema(db *sql.DB) error {
	if _, err := db.Exec(versionedSecretsTableSchema + secretVersionsTableSchema); err != nil {
		return fmt.Errorf("initialize secrets database: %w", err)
	}
	return nil
}

func newDatabaseAEAD(masterKey []byte) (cipher.AEAD, error) {
	applicationKey := sha256.Sum256(masterKey)
	block, err := aes.NewCipher(applicationKey[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func ensureSecretMountColumns(db *sql.DB) error {
	accountColumns, err := accountColumns(db)
	if err != nil {
		return err
	}
	if !accountColumns["secret_prefixes"] {
		if _, err := db.Exec("ALTER TABLE accounts ADD COLUMN secret_prefixes TEXT NOT NULL DEFAULT '[]'"); err != nil {
			return err
		}
	}
	if !accountColumns["secret_mounts"] {
		if _, err := db.Exec("ALTER TABLE accounts ADD COLUMN secret_mounts TEXT NOT NULL DEFAULT '[]'"); err != nil {
			return err
		}
	}

	tokenColumns, err := tableColumns(db, "api_tokens")
	if err != nil {
		return err
	}
	if !tokenColumns["secret_prefixes"] {
		if _, err := db.Exec("ALTER TABLE api_tokens ADD COLUMN secret_prefixes TEXT NOT NULL DEFAULT '[]'"); err != nil {
			return err
		}
	}
	if !tokenColumns["secret_mounts"] {
		if _, err := db.Exec("ALTER TABLE api_tokens ADD COLUMN secret_mounts TEXT NOT NULL DEFAULT '[]'"); err != nil {
			return err
		}
	}
	if !tokenColumns["created_by"] {
		if _, err := db.Exec("ALTER TABLE api_tokens ADD COLUMN created_by TEXT"); err != nil {
			return err
		}
	}
	return nil
}

func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var sequence, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&sequence, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

func ensureAccountRoleColumn(db *sql.DB) error {
	columns, err := accountColumns(db)
	if err != nil {
		return err
	}
	if columns["role"] {
		return nil
	}
	_, err = db.Exec("ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'operator'))")
	return err
}

func ensureAccountLockColumn(db *sql.DB) error {
	columns, err := accountColumns(db)
	if err != nil {
		return err
	}
	if columns["locked"] {
		return nil
	}
	_, err = db.Exec("ALTER TABLE accounts ADD COLUMN locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1))")
	return err
}

func ensureMustChangePasswordColumn(db *sql.DB) error {
	columns, err := accountColumns(db)
	if err != nil {
		return err
	}
	if columns["must_change_password"] {
		return nil
	}
	_, err = db.Exec("ALTER TABLE accounts ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1))")
	return err
}

func ensureAccountTOTPColumns(db *sql.DB) error {
	columns, err := accountColumns(db)
	if err != nil {
		return err
	}
	additions := []struct {
		name       string
		definition string
	}{
		{"totp_secret", "TEXT"},
		{"totp_enabled", "INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1))"},
		{"totp_recovery_codes", "TEXT NOT NULL DEFAULT '[]'"},
	}
	for _, column := range additions {
		if columns[column.name] {
			continue
		}
		if _, err := db.Exec("ALTER TABLE accounts ADD COLUMN " + column.name + " " + column.definition); err != nil {
			return err
		}
	}
	return nil
}

func accountColumns(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query("PRAGMA table_info(accounts)")
	if err != nil {
		return nil, err
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var sequence, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&sequence, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return nil, err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return columns, nil
}

func allowDuplicateAPITokenNames(db *sql.DB) error {
	type index struct {
		name   string
		unique bool
		origin string
	}

	rows, err := db.Query("PRAGMA index_list(api_tokens)")
	if err != nil {
		return err
	}
	var indexes []index
	for rows.Next() {
		var sequence, unique, partial int
		var item index
		if err := rows.Scan(&sequence, &item.name, &unique, &item.origin, &partial); err != nil {
			_ = rows.Close()
			return err
		}
		item.unique = unique != 0
		indexes = append(indexes, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	nameIndexes := make(map[string]struct{})
	for _, item := range indexes {
		if !item.unique {
			continue
		}
		quotedIndex := strings.ReplaceAll(item.name, "'", "''")
		indexRows, err := db.Query("PRAGMA index_info('" + quotedIndex + "')")
		if err != nil {
			return err
		}
		var columns []string
		for indexRows.Next() {
			var sequence, columnID int
			var columnName sql.NullString
			if err := indexRows.Scan(&sequence, &columnID, &columnName); err != nil {
				_ = indexRows.Close()
				return err
			}
			if columnName.Valid {
				columns = append(columns, columnName.String)
			} else {
				columns = append(columns, "")
			}
		}
		if err := indexRows.Err(); err != nil {
			_ = indexRows.Close()
			return err
		}
		if err := indexRows.Close(); err != nil {
			return err
		}
		if len(columns) == 1 && columns[0] == "name" {
			nameIndexes[item.name] = struct{}{}
		}
	}
	if len(nameIndexes) == 0 {
		return nil
	}

	indexRows, err := db.Query(`
		SELECT name, sql FROM sqlite_master
		WHERE type = 'index' AND tbl_name = 'api_tokens' AND sql IS NOT NULL`)
	if err != nil {
		return err
	}
	var preservedIndexes []string
	for indexRows.Next() {
		var name string
		var statement string
		if err := indexRows.Scan(&name, &statement); err != nil {
			_ = indexRows.Close()
			return err
		}
		if _, remove := nameIndexes[name]; remove {
			continue
		}
		preservedIndexes = append(preservedIndexes, statement)
	}
	if err := indexRows.Err(); err != nil {
		_ = indexRows.Close()
		return err
	}
	if err := indexRows.Close(); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
		CREATE TABLE api_tokens_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			revoked_at INTEGER
		);
		INSERT INTO api_tokens_new(id, name, token_hash, created_at, expires_at, revoked_at)
			SELECT id, name, token_hash, created_at, expires_at, revoked_at FROM api_tokens;
		DROP TABLE api_tokens;
		ALTER TABLE api_tokens_new RENAME TO api_tokens;
	`); err != nil {
		return err
	}
	for _, statement := range preservedIndexes {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func openAuditDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at INTEGER NOT NULL,
			action TEXT NOT NULL,
			outcome TEXT NOT NULL,
			actor TEXT NOT NULL,
			client_ip TEXT NOT NULL,
			source TEXT NOT NULL,
			resource TEXT NOT NULL,
			detail TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
		CREATE INDEX IF NOT EXISTS idx_audit_events_outcome ON audit_events(outcome);
		CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor);
	`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func loadOrCreateKey(path, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("database key password is required")
	}

	fileContents, err := os.ReadFile(path)
	if err == nil {
		if len(fileContents) == 0 || fileContents[0] != '{' {
			return nil, fmt.Errorf("unsupported legacy database key file format; remove it to create a new 128-byte protected key")
		}
		return decryptKeyFile(fileContents, password)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key := make([]byte, databaseKeyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := writeEncryptedKeyFile(path, key, password); err != nil {
		return nil, err
	}
	return key, nil
}

func deriveWrappingKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, 32)
}

func encryptKey(plaintext []byte, password string) (*encryptedKeyFile, error) {
	if len(plaintext) != databaseKeyLength {
		return nil, fmt.Errorf("database key must be exactly %d bytes", databaseKeyLength)
	}
	salt := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	wrappingKey := deriveWrappingKey(password, salt)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &encryptedKeyFile{
		Version:    1,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, nil),
	}, nil
}

func decryptKeyFile(contents []byte, password string) ([]byte, error) {
	var envelope encryptedKeyFile
	if err := json.Unmarshal(contents, &envelope); err != nil {
		return nil, fmt.Errorf("invalid encrypted database key file: %w", err)
	}
	if envelope.Version != 1 {
		return nil, fmt.Errorf("unsupported database key file version %d", envelope.Version)
	}
	if len(envelope.Salt) != 32 {
		return nil, fmt.Errorf("invalid database key salt length")
	}
	if len(envelope.Nonce) != 12 {
		return nil, fmt.Errorf("invalid database key nonce length")
	}

	wrappingKey := deriveWrappingKey(password, envelope.Salt)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt database key: wrong db password or corrupted key file")
	}
	if len(plaintext) != databaseKeyLength {
		return nil, fmt.Errorf("invalid decrypted database key length: got %d bytes", len(plaintext))
	}
	return plaintext, nil
}

func writeEncryptedKeyFile(path string, key []byte, password string) error {
	envelope, err := encryptKey(key, password)
	if err != nil {
		return err
	}
	contents, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".vault-db-key-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(contents); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	cleanup = false
	return os.Chmod(path, 0600)
}

func randomKey() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func loadOrCreateSetupKey(path string) (string, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		setupKey := strings.TrimSpace(string(key))
		if setupKey == "" {
			return "", fmt.Errorf("invalid setup key file")
		}
		return setupKey, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}

	setupKey := randomKey()
	if err := os.WriteFile(path, []byte(setupKey+"\n"), 0600); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	return setupKey, nil
}

func loadOrCreateSetupDeadline(db *sql.DB) (time.Time, error) {
	const key = "setup_started_at"
	now := time.Now().Unix()
	if _, err := db.Exec(
		"INSERT OR IGNORE INTO server_settings(key, value) VALUES (?, ?)",
		key,
		strconv.FormatInt(now, 10),
	); err != nil {
		return time.Time{}, err
	}

	var value string
	if err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", key).Scan(&value); err != nil {
		return time.Time{}, err
	}
	startedAt, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid setup start time: %w", err)
	}
	return time.Unix(startedAt, 0).Add(setupLifetime), nil
}
