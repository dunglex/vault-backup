package mkcert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFileNames(t *testing.T) {
	tests := []struct {
		name  string
		m     Mkcert
		hosts []string
		cert  string
		key   string
		p12   string
	}{
		{
			name:  "single hostname",
			m:     Mkcert{},
			hosts: []string{"example.com"},
			cert:  "./example.com.pem",
			key:   "./example.com-key.pem",
			p12:   "./example.com.p12",
		},
		{
			name:  "wildcard multiple IP and client",
			m:     Mkcert{Client: true},
			hosts: []string{"*.example.com", "127.0.0.1", "::1"},
			cert:  "./_wildcard.example.com+2-client.pem",
			key:   "./_wildcard.example.com+2-client-key.pem",
			p12:   "./_wildcard.example.com+2-client.p12",
		},
		{
			name:  "custom paths",
			m:     Mkcert{CertFile: "/tmp/cert.pem", KeyFile: "/tmp/key.pem", P12File: "/tmp/cert.p12"},
			hosts: []string{"localhost"},
			cert:  "/tmp/cert.pem",
			key:   "/tmp/key.pem",
			p12:   "/tmp/cert.p12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, p12 := tt.m.fileNames(tt.hosts)
			if cert != tt.cert || key != tt.key || p12 != tt.p12 {
				t.Fatalf("fileNames() = (%q, %q, %q), want (%q, %q, %q)", cert, key, p12, tt.cert, tt.key, tt.p12)
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	rsaMkcert := &Mkcert{}
	key, err := rsaMkcert.generateKey(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Fatalf("RSA key type = %T", key)
	}

	ecdsaMkcert := &Mkcert{Ecdsa: true}
	key, err = ecdsaMkcert.generateKey(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("ECDSA key type = %T", key)
	}
}

func TestNewCALoadCAAndMakeCertificate(t *testing.T) {
	caroot := t.TempDir()
	m := &Mkcert{CAROOT: caroot, CertFile: filepath.Join(t.TempDir(), "localhost.pem"), KeyFile: filepath.Join(t.TempDir(), "localhost-key.pem")}
	m.newCA()
	m.loadCA()

	if m.caCert == nil || m.caKey == nil {
		t.Fatal("loadCA did not populate the CA certificate and key")
	}
	if !m.caCert.IsCA {
		t.Fatal("generated certificate is not marked as a CA")
	}
	if got, err := os.Stat(filepath.Join(caroot, rootKeyName)); err != nil {
		t.Fatal(err)
	} else if got.Mode().Perm() != 0400 {
		t.Fatalf("CA key permissions = %o, want 400", got.Mode().Perm())
	}

	m.makeCert([]string{"localhost", "127.0.0.1", "client@example.com", "https://example.com/test"})

	certPEM, err := os.ReadFile(m.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatal("certificate file does not contain PEM certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cert.DNSNames, []string{"localhost"}) {
		t.Fatalf("DNS names = %#v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("IP addresses = %#v", cert.IPAddresses)
	}
	if !reflect.DeepEqual(cert.EmailAddresses, []string{"client@example.com"}) {
		t.Fatalf("email addresses = %#v", cert.EmailAddresses)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "https://example.com/test" {
		t.Fatalf("URI names = %#v", cert.URIs)
	}
	if err := cert.CheckSignatureFrom(m.caCert); err != nil {
		t.Fatalf("certificate was not signed by local CA: %v", err)
	}

	keyPEM, err := os.ReadFile(m.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("key file does not contain PKCS#8 private key")
	}
}

func TestMakeCertificateFromCSR(t *testing.T) {
	caroot := t.TempDir()
	m := &Mkcert{CAROOT: caroot}
	m.newCA()
	m.loadCA()

	key, err := m.generateKey(false)
	if err != nil {
		t.Fatal(err)
	}
	request := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "csr.example.com", Organization: []string{"Test"}},
		DNSNames:    []string{"csr.example.com", "alt.example.com"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
		URIs:        []*url.URL{mustParseURL(t, "spiffe://example.test/service")},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPath := filepath.Join(t.TempDir(), "request.csr")
	if err := os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), 0600); err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(t.TempDir(), "csr-cert.pem")
	m.CsrPath = csrPath
	m.CertFile = certPath
	m.makeCertFromCSR()

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "csr.example.com" {
		t.Fatalf("subject common name = %q", cert.Subject.CommonName)
	}
	if !reflect.DeepEqual(cert.DNSNames, []string{"csr.example.com", "alt.example.com"}) {
		t.Fatalf("CSR DNS names = %#v", cert.DNSNames)
	}
	if err := cert.CheckSignatureFrom(m.caCert); err != nil {
		t.Fatalf("CSR certificate was not signed by local CA: %v", err)
	}
}

func TestMakePKCS12Certificate(t *testing.T) {
	caroot := t.TempDir()
	p12Path := filepath.Join(t.TempDir(), "localhost.p12")
	m := &Mkcert{CAROOT: caroot, Pkcs12: true, P12File: p12Path}
	m.newCA()
	m.loadCA()
	m.makeCert([]string{"localhost"})

	info, err := os.Stat(p12Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("PKCS#12 file is empty")
	}
}

func TestRandomSerialNumber(t *testing.T) {
	serial := randomSerialNumber()
	if serial == nil || serial.Sign() <= 0 {
		t.Fatalf("random serial = %v", serial)
	}
	if serial.BitLen() > 128 {
		t.Fatalf("random serial has %d bits, want at most 128", serial.BitLen())
	}
}

func TestCAUniqueName(t *testing.T) {
	m := &Mkcert{caCert: &x509.Certificate{SerialNumber: big.NewInt(42)}}
	if got := m.caUniqueName(); got != "mkcert development CA 42" {
		t.Fatalf("caUniqueName() = %q", got)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
