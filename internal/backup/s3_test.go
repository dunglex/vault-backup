package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestS3TestConnectionAndCopy(t *testing.T) {
	config := S3Config{
		Enabled:         true,
		Endpoint:        "http://s3.example.test",
		Region:          "test-region",
		Bucket:          "test-bucket",
		Prefix:          "vault/backups",
		AccessKeyID:     "test-access",
		SecretAccessKey: "test-secret",
		ForcePathStyle:  true,
	}
	if err := TestS3Connection(config); err != nil {
		if !strings.Contains(err.Error(), "HTTPS URL") {
			t.Fatalf("HTTP S3 endpoint error = %v", err)
		}
	} else {
		t.Fatal("HTTP S3 endpoint was accepted")
	}
	archive := filepath.Join(t.TempDir(), "test.tar.gz")
	if err := os.WriteFile(archive, []byte("backup-data"), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := CopyToS3(config, archive)
	if err == nil || !strings.Contains(err.Error(), "HTTPS URL") {
		t.Fatalf("HTTP S3 copy error = %v, key = %q", err, key)
	}
}
