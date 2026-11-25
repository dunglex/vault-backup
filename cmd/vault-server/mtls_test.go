package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"database/sql"
)

func TestManagedCertificateUsesTokenExpiry(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	cipherBlock, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		t.Fatal(err)
	}
	server := &server{db: db, aead: aead}
	if err := server.loadOrCreateManagedClientCA(); err != nil {
		t.Fatal(err)
	}

	tokenExpiry := time.Now().UTC().Truncate(time.Second).Add(90 * 24 * time.Hour)
	issued, err := server.issueClientCertificate(42, tokenExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if !issued.ExpiresAt.Equal(tokenExpiry) {
		t.Fatalf("reported certificate expiry = %s, want %s", issued.ExpiresAt, tokenExpiry)
	}
	certBlock, _ := pem.Decode([]byte(issued.Certificate))
	if certBlock == nil {
		t.Fatal("issued certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.NotAfter.Equal(tokenExpiry) {
		t.Fatalf("certificate NotAfter = %s, want %s", certificate.NotAfter, tokenExpiry)
	}
	if _, err := tls.X509KeyPair([]byte(issued.Certificate), []byte(issued.PrivateKey)); err != nil {
		t.Fatalf("issued certificate and key do not match: %v", err)
	}
}
