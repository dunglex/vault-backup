package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateAndRestoreServerDataArchive(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	backupDir := filepath.Join(root, "backups")
	if err := os.MkdirAll(filepath.Join(dataDir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "vault.db"), []byte("database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "nested", "state"), []byte("state"), 0600); err != nil {
		t.Fatal(err)
	}
	archive, err := Create(dataDir, backupDir, time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := Restore(backupDir, dataDir, filepath.Base(archive)); err != nil {
		t.Fatal(err)
	}
	database, err := os.ReadFile(filepath.Join(dataDir, "vault.db"))
	if err != nil || string(database) != "database" {
		t.Fatalf("restored database = %q, err %v", database, err)
	}
	state, err := os.ReadFile(filepath.Join(dataDir, "nested", "state"))
	if err != nil || string(state) != "state" {
		t.Fatalf("restored state = %q, err %v", state, err)
	}
}
