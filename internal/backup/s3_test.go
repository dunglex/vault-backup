package backup

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestS3TestConnectionAndCopy(t *testing.T) {
	var headCount, putCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("S3 request is missing AWS signature")
		}
		switch r.Method {
		case http.MethodHead:
			headCount++
			if r.URL.Path != "/test-bucket" {
				t.Errorf("HEAD path = %q, want /test-bucket", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodPut:
			putCount++
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if r.URL.Path != "/test-bucket/vault/backups/test.tar.gz" {
				t.Errorf("PUT path = %q", r.URL.Path)
			}
			if string(body) != "backup-data" {
				t.Errorf("PUT body = %q", body)
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	config := S3Config{
		Enabled:         true,
		Endpoint:        server.URL,
		Region:          "test-region",
		Bucket:          "test-bucket",
		Prefix:          "vault/backups",
		AccessKeyID:     "test-access",
		SecretAccessKey: "test-secret",
		ForcePathStyle:  true,
	}
	if err := TestS3Connection(config); err != nil {
		t.Fatalf("S3 test connection: %v", err)
	}
	if headCount != 1 {
		t.Fatalf("HEAD count = %d, want 1", headCount)
	}
	archive := filepath.Join(t.TempDir(), "test.tar.gz")
	if err := os.WriteFile(archive, []byte("backup-data"), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := CopyToS3(config, archive)
	if err != nil {
		t.Fatalf("copy backup to S3: %v", err)
	}
	if putCount != 1 {
		t.Fatalf("PUT count = %d, want 1", putCount)
	}
	if !strings.EqualFold(key, "vault/backups/test.tar.gz") {
		t.Fatalf("S3 key = %q", key)
	}
}
