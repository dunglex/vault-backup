package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseKeyIsEncryptedAnd128Bytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db.key")
	password := "a-secure-test-password"

	key, err := loadOrCreateKey(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != databaseKeyLength {
		t.Fatalf("database key length: got %d, want %d", len(key), databaseKeyLength)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) == databaseKeyLength {
		t.Fatal("database key file contains a raw key")
	}

	loaded, err := loadOrCreateKey(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != databaseKeyLength {
		t.Fatalf("loaded database key length: got %d, want %d", len(loaded), databaseKeyLength)
	}
	for i := range key {
		if key[i] != loaded[i] {
			t.Fatal("database key changed after reopening")
		}
	}

	if _, err := loadOrCreateKey(path, "wrong-password"); err == nil {
		t.Fatal("wrong database password was accepted")
	}
}

func TestLegacy32ByteKeyIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db.key")
	if err := os.WriteFile(path, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKey(path, "password"); err == nil {
		t.Fatal("legacy 32-byte key was accepted")
	}
}

func TestLoadDotEnvPreservesExistingEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.env")
	contents := "VAULT_SERVER_DB_PASSWORD=from-file\nVAULT_SERVER_ADDR=127.0.0.1:8200\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_SERVER_DB_PASSWORD", "from-process")

	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("VAULT_SERVER_DB_PASSWORD"); got != "from-process" {
		t.Fatalf("existing environment was overwritten: got %q", got)
	}
	if got := os.Getenv("VAULT_SERVER_ADDR"); got != "127.0.0.1:8200" {
		t.Fatalf("env file value was not loaded: got %q", got)
	}
}

func TestLoadClientCAPoolRejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClientCAPool(path); err == nil {
		t.Fatal("invalid client CA PEM was accepted")
	}
}

func TestOpenDatabaseEncryptsNewDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	key := []byte("0123456789abcdef0123456789abcdef")

	db, legacy, err := openDatabase(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if legacy {
		t.Fatal("new database selected the legacy driver")
	}
	if _, err := db.Exec("CREATE TABLE test (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	plaintext, err := isPlaintextSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext {
		t.Fatal("new database has a plaintext SQLite header")
	}
}

func TestOpenDatabasePreservesPlaintextDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	legacyDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec("CREATE TABLE test (value TEXT); INSERT INTO test VALUES ('preserved')"); err != nil {
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	db, legacy, err := openDatabaseWithOptions(path, []byte("0123456789abcdef0123456789abcdef"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if !legacy {
		t.Fatal("plaintext database did not select the legacy driver")
	}

	var value string
	if err := db.QueryRow("SELECT value FROM test").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "preserved" {
		t.Fatalf("got %q, want %q", value, "preserved")
	}
}

func TestOpenDatabaseRejectsPlaintextDatabaseByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	legacyDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec("CREATE TABLE test (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	_, legacy, err := openDatabase(path, []byte("0123456789abcdef0123456789abcdef"))
	if err == nil {
		t.Fatal("plaintext database was accepted without an explicit insecure opt-in")
	}
	if !legacy {
		t.Fatal("plaintext database was not detected")
	}
}
