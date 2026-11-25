package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
	internalacme "vault-backup/internal/acme"
)

const (
	serverCertificateModeSelfSigned = "self_signed"
	serverCertificateModeACME       = "acme"
	serverSettingMainDomain         = "main_domain"
	serverSettingAliasDomains       = "alias_domains"
	serverSettingCertificateMode    = "server_certificate_mode"
	serverSettingGeneratedCert      = "server_certificate_generated"
	serverSettingGeneratedCertPath  = "server_certificate_generated_cert_path"
	serverSettingGeneratedKeyPath   = "server_certificate_generated_key_path"
	maxServerDomains                = 100
)

type serverCertificateManager struct {
	mu            sync.RWMutex
	certificate   *tls.Certificate
	mode          string
	certPath      string
	keyPath       string
	generated     bool
	acmeAvailable bool
	acmeManager   *internalacme.Manager
}

func newServerCertificateManager(db *sql.DB, certPath, keyPath, cachePath, bindAddress string, acmeAvailable bool) (*serverCertificateManager, error) {
	if filepath.Clean(certPath) == filepath.Clean(keyPath) {
		return nil, fmt.Errorf("TLS certificate and key paths must differ")
	}

	mode, err := readServerSetting(db, serverSettingCertificateMode)
	if err != nil {
		return nil, err
	}
	if mode == "" {
		mode = serverCertificateModeSelfSigned
	}
	if mode != serverCertificateModeSelfSigned && mode != serverCertificateModeACME {
		return nil, fmt.Errorf("unsupported server certificate mode %q", mode)
	}
	if mode == serverCertificateModeACME && !acmeAvailable {
		return nil, fmt.Errorf("ACME certificates are configured but the HTTP listener is disabled")
	}

	domains, err := loadConfiguredServerDomains(db)
	if err != nil {
		return nil, err
	}
	generatedSetting, err := readServerSetting(db, serverSettingGeneratedCert)
	if err != nil {
		return nil, err
	}
	generatedCertPath, err := readServerSetting(db, serverSettingGeneratedCertPath)
	if err != nil {
		return nil, err
	}
	generatedKeyPath, err := readServerSetting(db, serverSettingGeneratedKeyPath)
	if err != nil {
		return nil, err
	}

	manager := &serverCertificateManager{
		mode:          mode,
		certPath:      certPath,
		keyPath:       keyPath,
		acmeAvailable: acmeAvailable,
		generated: generatedSetting == "true" &&
			filepath.Clean(generatedCertPath) == filepath.Clean(certPath) &&
			filepath.Clean(generatedKeyPath) == filepath.Clean(keyPath),
	}
	if acmeAvailable {
		manager.acmeManager, err = internalacme.New(cachePath, domains)
		if err != nil {
			return nil, err
		}
	}

	if mode == serverCertificateModeACME {
		return manager, nil
	}
	certExists, err := pathExists(certPath)
	if err != nil {
		return nil, err
	}
	keyExists, err := pathExists(keyPath)
	if err != nil {
		return nil, err
	}
	if certExists != keyExists {
		return nil, fmt.Errorf("TLS certificate and key must both exist or both be missing")
	}
	if certExists {
		certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load TLS certificate pair: %w", err)
		}
		manager.certificate = &certificate
		return manager, nil
	}

	names := domains
	if len(names) == 0 {
		names = bootstrapServerDomains(bindAddress)
	}
	if err := manager.installGeneratedCertificate(names); err != nil {
		return nil, err
	}
	if err := markGeneratedServerCertificate(db, certPath, keyPath); err != nil {
		return nil, err
	}
	manager.generated = true
	return manager, nil
}

func (m *serverCertificateManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	mode := m.mode
	certificate := m.certificate
	acmeManager := m.acmeManager
	m.mu.RUnlock()
	if mode == serverCertificateModeACME {
		if acmeManager == nil {
			return nil, fmt.Errorf("ACME certificates are unavailable without an HTTP listener")
		}
		return acmeManager.GetCertificate(hello)
	}
	if certificate == nil {
		return nil, fmt.Errorf("server TLS certificate is not configured")
	}
	return certificate, nil
}

func (m *serverCertificateManager) HTTPHandler(next http.Handler) http.Handler {
	if m.acmeManager == nil {
		return next
	}
	return m.acmeManager.HTTPHandler(next)
}

func (m *serverCertificateManager) prepareACME(domains []string) error {
	if !m.acmeAvailable || m.acmeManager == nil {
		return fmt.Errorf("ACME certificates require the HTTP listener")
	}
	return m.acmeManager.Prepare(domains)
}

func (m *serverCertificateManager) prepareSelfSigned(domains []string) error {
	m.mu.RLock()
	generated := m.generated
	m.mu.RUnlock()
	if !generated {
		return nil
	}
	return m.installGeneratedCertificate(domains)
}

func (m *serverCertificateManager) configure(mode string, domains []string) {
	if m.acmeManager != nil {
		m.acmeManager.SetDomains(domains)
	}
	m.mu.Lock()
	m.mode = mode
	m.mu.Unlock()
}

func (m *serverCertificateManager) configureTLS(config *tls.Config) {
	config.GetCertificate = m.GetCertificate
	if m.acmeManager != nil {
		m.acmeManager.ConfigureTLS(config)
	}
}

func (m *serverCertificateManager) installGeneratedCertificate(domains []string) error {
	certPEM, keyPEM, certificate, err := generateServerCertificate(domains)
	if err != nil {
		return err
	}
	if err := writeServerCertificatePair(m.certPath, m.keyPath, certPEM, keyPEM); err != nil {
		return err
	}
	m.mu.Lock()
	m.certificate = certificate
	m.mu.Unlock()
	return nil
}

func normalizeServerDomains(mainDomain string, aliases []string) (string, []string, []string, error) {
	main, err := normalizeServerHost(mainDomain)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid main domain: %w", err)
	}
	if len(aliases) > maxServerDomains-1 {
		return "", nil, nil, fmt.Errorf("no more than %d alias domains are allowed", maxServerDomains-1)
	}
	normalizedAliases := make([]string, 0, len(aliases))
	all := []string{main}
	seen := map[string]struct{}{main: {}}
	for _, alias := range aliases {
		if strings.TrimSpace(alias) == "" {
			continue
		}
		host, err := normalizeServerHost(alias)
		if err != nil {
			return "", nil, nil, fmt.Errorf("invalid alias domain %q: %w", alias, err)
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		normalizedAliases = append(normalizedAliases, host)
		all = append(all, host)
	}
	return main, normalizedAliases, all, nil
}

func normalizeServerHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
		if !strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]") {
			return "", fmt.Errorf("invalid IP address")
		}
		host = host[1 : len(host)-1]
		if net.ParseIP(host) == nil {
			return "", fmt.Errorf("invalid IP address")
		}
	}
	if host == "" {
		return "", fmt.Errorf("domain is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid DNS name")
	}
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", fmt.Errorf("DNS name must be between 1 and 253 characters")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS name")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') &&
				character != '-' {
				return "", fmt.Errorf("invalid DNS name")
			}
		}
	}
	return ascii, nil
}

func loadConfiguredServerDomains(db *sql.DB) ([]string, error) {
	main, err := readServerSetting(db, serverSettingMainDomain)
	if err != nil {
		return nil, err
	}
	if main == "" {
		return nil, nil
	}
	aliasesJSON, err := readServerSetting(db, serverSettingAliasDomains)
	if err != nil {
		return nil, err
	}
	var aliases []string
	if aliasesJSON != "" {
		if err := json.Unmarshal([]byte(aliasesJSON), &aliases); err != nil {
			return nil, fmt.Errorf("read saved alias domains: %w", err)
		}
	}
	_, _, domains, err := normalizeServerDomains(main, aliases)
	if err != nil {
		return nil, fmt.Errorf("read saved server domains: %w", err)
	}
	return domains, nil
}

func normalizeRequestHost(rawHost string) (string, error) {
	host := strings.TrimSpace(rawHost)
	if host == "" {
		return "", fmt.Errorf("host is empty")
	}

	switch {
	case strings.HasPrefix(host, "["):
		parsedHost, port, err := net.SplitHostPort(host)
		if err == nil {
			if net.ParseIP(parsedHost) == nil {
				return "", fmt.Errorf("bracketed host is not an IP address")
			}
			if _, err := strconv.ParseUint(port, 10, 16); err != nil {
				return "", fmt.Errorf("invalid host port")
			}
			host = parsedHost
		} else if strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
			if net.ParseIP(host) == nil {
				return "", fmt.Errorf("bracketed host is not an IP address")
			}
		} else {
			return "", fmt.Errorf("invalid host")
		}
	case strings.Count(host, ":") == 1:
		parsedHost, port, err := net.SplitHostPort(host)
		if err != nil {
			return "", fmt.Errorf("invalid host port")
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return "", fmt.Errorf("invalid host port")
		}
		host = parsedHost
	case strings.Contains(host, ":") && net.ParseIP(host) == nil:
		return "", fmt.Errorf("invalid host")
	}
	return normalizeServerHost(host)
}

func normalizeOriginHost(origin string) (string, error) {
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid origin")
	}
	return normalizeRequestHost(parsed.Host)
}

func bootstrapServerDomains(bindAddress string) []string {
	domains := []string{"localhost", "127.0.0.1", "::1"}
	host, _, err := net.SplitHostPort(bindAddress)
	if err != nil || host == "" {
		return domains
	}
	if host == "0.0.0.0" || host == "::" {
		return domains
	}
	if normalized, err := normalizeServerHost(host); err == nil {
		for _, existing := range domains {
			if existing == normalized {
				return domains
			}
		}
		return append(domains, normalized)
	}
	return domains
}

func generateServerCertificate(domains []string) ([]byte, []byte, *tls.Certificate, error) {
	if len(domains) == 0 {
		return nil, nil, nil, fmt.Errorf("at least one server certificate domain is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate TLS private key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate TLS certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0]},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, domain := range domains {
		if ip := net.ParseIP(domain); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, domain)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create self-signed TLS certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode TLS private key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load generated TLS certificate: %w", err)
	}
	return certPEM, keyPEM, &certificate, nil
}

func writeServerCertificatePair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	certTemp, err := stageServerCertificateFile(certPath, certPEM, 0644)
	if err != nil {
		return fmt.Errorf("stage TLS certificate: %w", err)
	}
	defer os.Remove(certTemp)
	keyTemp, err := stageServerCertificateFile(keyPath, keyPEM, 0600)
	if err != nil {
		return fmt.Errorf("stage TLS private key: %w", err)
	}
	defer os.Remove(keyTemp)

	certBackup, certExisted, err := backupServerCertificateFile(certPath)
	if err != nil {
		return fmt.Errorf("preserve existing TLS certificate: %w", err)
	}
	keyBackup, keyExisted, err := backupServerCertificateFile(keyPath)
	if err != nil {
		return errors.Join(fmt.Errorf("preserve existing TLS private key: %w", err), restoreServerCertificateFiles(certPath, certBackup, certExisted))
	}
	restore := func() error {
		return errors.Join(
			restoreServerCertificateFiles(certPath, certBackup, certExisted),
			restoreServerCertificateFiles(keyPath, keyBackup, keyExisted),
		)
	}
	if err := os.Rename(certTemp, certPath); err != nil {
		return errors.Join(fmt.Errorf("install TLS certificate: %w", err), restore())
	}
	if err := os.Rename(keyTemp, keyPath); err != nil {
		_ = os.Remove(certPath)
		return errors.Join(fmt.Errorf("install TLS private key: %w", err), restore())
	}
	if certExisted {
		if err := os.Remove(certBackup); err != nil {
			return fmt.Errorf("remove previous TLS certificate backup %s: %w", certBackup, err)
		}
	}
	if keyExisted {
		if err := os.Remove(keyBackup); err != nil {
			return fmt.Errorf("remove previous TLS private key backup %s: %w", keyBackup, err)
		}
	}
	return nil
}

func stageServerCertificateFile(path string, contents []byte, mode os.FileMode) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(dir, ".vault-server-tls-*")
	if err != nil {
		return "", err
	}
	tempPath := file.Name()
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		_ = os.Remove(tempPath)
		return "", err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		_ = os.Remove(tempPath)
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tempPath)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}
	return tempPath, nil
}

func backupServerCertificateFile(path string) (string, bool, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".vault-server-tls-backup-*")
	if err != nil {
		return "", false, err
	}
	backupPath := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(backupPath)
		return "", false, err
	}
	if err := os.Remove(backupPath); err != nil {
		return "", false, err
	}
	if err := os.Rename(path, backupPath); err != nil {
		return "", false, err
	}
	return backupPath, true, nil
}

func restoreServerCertificateFiles(path, backupPath string, existed bool) error {
	if existed {
		return os.Rename(backupPath, path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func readServerSetting(db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read server setting %q: %w", key, err)
	}
	return value, nil
}

func markGeneratedServerCertificate(db *sql.DB, certPath, keyPath string) error {
	settings := map[string]string{
		serverSettingGeneratedCert:     "true",
		serverSettingGeneratedCertPath: certPath,
		serverSettingGeneratedKeyPath:  keyPath,
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("save generated TLS certificate settings: %w", err)
	}
	defer tx.Rollback()
	for key, value := range settings {
		if _, err := tx.Exec(
			"INSERT INTO server_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			key, value,
		); err != nil {
			return fmt.Errorf("save generated TLS certificate setting %q: %w", key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit generated TLS certificate settings: %w", err)
	}
	return nil
}

func domainSet(domains []string) map[string]struct{} {
	set := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		set[domain] = struct{}{}
	}
	return set
}
