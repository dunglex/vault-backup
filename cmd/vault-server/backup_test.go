package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateServerDataBackupArchivesDataAndSkipsBackupDirectory(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	backupDir := filepath.Join(dataDir, "backups")
	files := map[string]string{
		"vault.db":             "encrypted db",
		"vault.db.key":         "protected key",
		"nested/acme/state":    "acme state",
		"nested/acme/metadata": "more state",
	}
	for name, content := range files {
		path := filepath.Join(dataDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	createdAt := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	archivePath, err := createServerDataBackup(dataDir, backupDir, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("archive permissions = %04o, want 0600", got)
	}

	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	gz, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	contents := make(map[string][]byte)
	seen := make(map[string]struct{})
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := seen[header.Name]; exists {
			t.Fatalf("duplicate archive entry %q", header.Name)
		}
		seen[header.Name] = struct{}{}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		contents[header.Name] = data
		if got := header.Mode & 0777; got != 0600 {
			t.Errorf("entry %q mode = %04o, want 0600", header.Name, got)
		}
	}
	manifest, ok := contents["vault-server/manifest.txt"]
	if !ok {
		t.Fatal("backup manifest missing")
	}
	for name, content := range files {
		path := filepath.ToSlash(filepath.Join("vault-server", "data", name))
		got, ok := contents[path]
		if !ok || string(got) != content {
			t.Errorf("backup entry %q = %q, want %q", path, got, content)
		}
		expected := fmt.Sprintf("%x  %s\n", sha256.Sum256([]byte(content)), strings.TrimPrefix(path, "vault-server/"))
		if !strings.Contains(string(manifest), expected) {
			t.Errorf("manifest missing checksum for %q", path)
		}
	}
	for path := range contents {
		if strings.Contains(path, "/backups/") {
			t.Errorf("backup recursively included archive %q", path)
		}
	}
}

func TestPruneServerBackupsOnlyRemovesExpiredArchives(t *testing.T) {
	directory := t.TempDir()
	oldBackup := filepath.Join(directory, "vault-server-backup-old.tar.gz")
	newBackup := filepath.Join(directory, "vault-server-backup-new.tar.gz")
	unrelated := filepath.Join(directory, "keep.tar.gz")
	for _, path := range []string{oldBackup, newBackup, unrelated} {
		if err := os.WriteFile(path, []byte("archive"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if err := os.Chtimes(oldBackup, now.Add(-31*24*time.Hour), now.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newBackup, now, now); err != nil {
		t.Fatal(err)
	}
	if err := pruneServerBackups(directory, now.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldBackup); !os.IsNotExist(err) {
		t.Fatalf("expired archive still exists, stat error = %v", err)
	}
	for _, path := range []string{newBackup, unrelated} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected archive to remain %q: %v", path, err)
		}
	}
}

func TestMaintenanceGateDrainsRequestsAndServesMaintenancePage(t *testing.T) {
	s := &server{requestsIdle: closedSignal()}
	started := make(chan struct{})
	release := make(chan struct{})
	handler := s.maintenanceGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(200)
	}))
	activeDone := make(chan struct{})
	go func() {
		defer close(activeDone)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}()
	<-started

	maintenanceDone := make(chan struct{})
	go func() {
		s.beginMaintenance()
		close(maintenanceDone)
	}()
	for {
		s.maintenanceMu.Lock()
		active := s.maintenance
		s.maintenanceMu.Unlock()
		if active {
			break
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-maintenanceDone:
		t.Fatal("maintenance started before active requests drained")
	default:
	}

	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest("GET", "/", nil))
	if page.Code != 503 || !strings.Contains(page.Body.String(), "under maintenance") {
		t.Fatalf("maintenance page response = %d, %q", page.Code, page.Body.String())
	}
	if page.Header().Get("Connection") != "close" {
		t.Fatal("maintenance response did not close the client connection")
	}
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest("GET", "/health", nil))
	if health.Code != 503 || !strings.Contains(health.Body.String(), `"maintenance":true`) {
		t.Fatalf("maintenance health response = %d, %q", health.Code, health.Body.String())
	}
	live := httptest.NewRecorder()
	handler.ServeHTTP(live, httptest.NewRequest("GET", "/live", nil))
	if live.Code != 200 {
		t.Fatalf("maintenance liveness status = %d, want 200", live.Code)
	}

	close(release)
	<-activeDone
	<-maintenanceDone
	s.failMaintenance()
	live = httptest.NewRecorder()
	handler.ServeHTTP(live, httptest.NewRequest("GET", "/live", nil))
	if live.Code != 503 {
		t.Fatalf("failed maintenance liveness status = %d, want 503", live.Code)
	}
	s.endMaintenance()
}

func TestValidateServerBackupCronRequiresSixFields(t *testing.T) {
	for _, expression := range []string{"0 0 2 * * *", "*/5 * * * * *"} {
		if err := validateServerBackupCron(expression); err != nil {
			t.Errorf("validate %q: %v", expression, err)
		}
	}
	for _, expression := range []string{"0 2 * * *", "not a cron expression", "TZ=UTC 0 0 2 * * *"} {
		if err := validateServerBackupCron(expression); err == nil {
			t.Errorf("validate %q succeeded, want error", expression)
		}
	}
}

func TestMiddlewareServesMaintenanceBeforeDatabaseGuards(t *testing.T) {
	s := &server{
		maintenance:  true,
		requestsIdle: closedSignal(),
	}
	handler := s.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request reached application handler during maintenance")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "https://vault.example/security.html", nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "under maintenance") {
		t.Fatalf("middleware maintenance response = %d, %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("maintenance response is missing standard security headers")
	}
}
