package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS accounts (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS secrets (
			path TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			revoked_at INTEGER
		);
		CREATE TABLE IF NOT EXISTS server_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
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
	return allowDuplicateAPITokenNames(db)
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
