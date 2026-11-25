package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type managedClientCA struct {
	certificate *x509.Certificate
	signer      crypto.Signer
}

type issuedClientCertificate struct {
	Certificate string
	PrivateKey  string
	ExpiresAt   time.Time
	Serial      string
}

func (s *server) loadOrCreateManagedClientCA() error {
	const certKey = "managed_client_ca_certificate"
	const signerKey = "managed_client_ca_signer"

	var certPEM, encryptedSigner string
	certErr := s.db.QueryRow("SELECT value FROM server_settings WHERE key = ?", certKey).Scan(&certPEM)
	signerErr := s.db.QueryRow("SELECT value FROM server_settings WHERE key = ?", signerKey).Scan(&encryptedSigner)
	if certErr == nil && signerErr == nil {
		certBlock, _ := pem.Decode([]byte(certPEM))
		if certBlock == nil {
			return fmt.Errorf("stored managed client CA certificate is invalid")
		}
		certificate, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return fmt.Errorf("parse stored managed client CA certificate: %w", err)
		}
		signerPEM, err := s.decrypt(encryptedSigner)
		if err != nil {
			return fmt.Errorf("decrypt stored managed client CA key: %w", err)
		}
		signerBlock, _ := pem.Decode(signerPEM)
		if signerBlock == nil {
			return fmt.Errorf("stored managed client CA key is invalid")
		}
		signer, err := x509.ParsePKCS8PrivateKey(signerBlock.Bytes)
		if err != nil {
			return fmt.Errorf("parse stored managed client CA key: %w", err)
		}
		cryptoSigner, ok := signer.(crypto.Signer)
		if !ok {
			return fmt.Errorf("stored managed client CA key cannot sign certificates")
		}
		certPublicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
		if err != nil {
			return fmt.Errorf("marshal stored managed client CA public key: %w", err)
		}
		signerPublicKey, err := x509.MarshalPKIXPublicKey(cryptoSigner.Public())
		if err != nil {
			return fmt.Errorf("marshal stored managed client CA signer public key: %w", err)
		}
		if !bytes.Equal(certPublicKey, signerPublicKey) || !certificate.IsCA || time.Now().Before(certificate.NotBefore) || !time.Now().Before(certificate.NotAfter) {
			return fmt.Errorf("stored managed client CA certificate and key do not form a valid active signing pair")
		}
		s.clientCA = &managedClientCA{certificate: certificate, signer: cryptoSigner}
		return nil
	}
	if certErr != sql.ErrNoRows || signerErr != sql.ErrNoRows {
		if certErr != nil && certErr != sql.ErrNoRows {
			return certErr
		}
		if signerErr != nil && signerErr != sql.ErrNoRows {
			return signerErr
		}
		return fmt.Errorf("managed client CA certificate and key are inconsistent")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate managed client CA key: %w", err)
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Vault Backup Managed Client CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create managed client CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse generated managed client CA certificate: %w", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	signerDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal managed client CA key: %w", err)
	}
	signerPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: signerDER})
	encryptedSigner, err = s.encrypt(signerPEM)
	if err != nil {
		return fmt.Errorf("protect managed client CA key: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT OR IGNORE INTO server_settings(key, value) VALUES (?, ?)", certKey, certPEM); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO server_settings(key, value) VALUES (?, ?)", signerKey, encryptedSigner); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.clientCA = &managedClientCA{certificate: certificate, signer: key}
	return nil
}

func randomCertificateSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial number: %w", err)
	}
	return serial, nil
}

func (s *server) issueClientCertificate(tokenID int64, expiresAt time.Time) (issuedClientCertificate, error) {
	if s.clientCA == nil {
		return issuedClientCertificate{}, fmt.Errorf("managed client CA is not initialized")
	}
	expiresAt = time.Unix(expiresAt.Unix(), 0).UTC()
	now := time.Now().UTC()
	if !expiresAt.After(now) {
		return issuedClientCertificate{}, fmt.Errorf("API token expiry must be in the future")
	}
	if expiresAt.After(now.Add(maxAPITokenLifetime)) {
		return issuedClientCertificate{}, fmt.Errorf("API token expiry cannot exceed one year")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issuedClientCertificate{}, fmt.Errorf("generate client certificate key: %w", err)
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return issuedClientCertificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: fmt.Sprintf("vault-backup-token-%d", tokenID)},
		NotBefore:    now.Add(-2 * time.Minute),
		NotAfter:     expiresAt,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, s.clientCA.certificate, &key.PublicKey, s.clientCA.signer)
	if err != nil {
		return issuedClientCertificate{}, fmt.Errorf("issue client certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return issuedClientCertificate{}, fmt.Errorf("marshal client certificate key: %w", err)
	}
	return issuedClientCertificate{
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		ExpiresAt:   expiresAt,
		Serial:      serial.Text(16),
	}, nil
}

func (s *server) saveClientCertificate(tx *sql.Tx, tokenID int64, issued issuedClientCertificate) error {
	_, err := tx.Exec(`
		INSERT INTO managed_client_certificates(serial_number, token_id, certificate_pem, created_at, not_after)
		VALUES (?, ?, ?, ?, ?)`,
		issued.Serial,
		tokenID,
		issued.Certificate,
		time.Now().Unix(),
		issued.ExpiresAt.Unix(),
	)
	return err
}

func (s *server) mtlsSettings() (bool, error) {
	var enforced string
	err := s.db.QueryRow("SELECT value FROM server_settings WHERE key = 'enforce_mtls'").Scan(&enforced)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	return enforced == "true", nil
}

func (s *server) certificateTokenID(r *http.Request) (int64, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return 0, false
	}
	serial := r.TLS.PeerCertificates[0].SerialNumber.Text(16)
	var tokenID int64
	err := s.db.QueryRow(`
		SELECT certificates.token_id
		FROM managed_client_certificates AS certificates
		JOIN api_tokens ON api_tokens.id = certificates.token_id
		WHERE certificates.serial_number = ?
		  AND certificates.revoked_at IS NULL
		  AND certificates.not_after > ?
		  AND api_tokens.revoked_at IS NULL
		  AND api_tokens.expires_at >= ?`,
		serial,
		time.Now().Unix(),
		time.Now().Unix(),
	).Scan(&tokenID)
	return tokenID, err == nil
}

func apiTokenFromRequest(r *http.Request) string {
	token := r.Header.Get("X-Vault-Token")
	if token == "" {
		token = r.Header.Get("Authorization")
		if after, ok := strings.CutPrefix(token, "Bearer "); ok {
			token = after
		}
	}
	return token
}

func (s *server) lookupActiveAPIToken(token string, tokenID *int64) error {
	if token == "" {
		return sql.ErrNoRows
	}
	hash := sha256.Sum256([]byte(token))
	return s.db.QueryRow(
		"SELECT id FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL AND expires_at >= ?",
		hex.EncodeToString(hash[:]),
		time.Now().Unix(),
	).Scan(tokenID)
}

func (s *server) getSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	enforced, err := s.mtlsSettings()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read settings"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"enforce_mtls": enforced,
	})
}

func (s *server) updateSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to change security settings"})
		return
	}
	var request struct {
		EnforceMTLS bool `json:"enforce_mtls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid settings"})
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save settings"})
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		"INSERT INTO server_settings(key, value) VALUES ('enforce_mtls', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		strconv.FormatBool(request.EnforceMTLS),
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save settings"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save settings"})
		return
	}
	s.recordAuditEvent(r, "update_settings", "success", s.auditRequestActor(r, "web"), "web", "server-settings", "")
	writeJSON(w, http.StatusOK, map[string]bool{
		"enforce_mtls": request.EnforceMTLS,
	})
}

func (s *server) issueAPITokenCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedWeb(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.TLS == nil {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to issue client credentials"})
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token id"})
		return
	}
	var tokenExpiresAt int64
	if err := s.db.QueryRow(
		"SELECT expires_at FROM api_tokens WHERE id = ? AND revoked_at IS NULL AND expires_at > ?",
		id, time.Now().Unix(),
	).Scan(&tokenExpiresAt); err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "active API token not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read API token"})
		return
	}
	tokenExpiry := time.Unix(tokenExpiresAt, 0).UTC()
	issued, err := s.issueClientCertificate(id, tokenExpiry)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not issue client certificate"})
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not issue client certificate"})
		return
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err := tx.Exec(
		"UPDATE managed_client_certificates SET revoked_at = ? WHERE token_id = ? AND revoked_at IS NULL",
		now, id,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not issue client certificate"})
		return
	}
	if err := s.saveClientCertificate(tx, id, issued); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not issue client certificate"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not issue client certificate"})
		return
	}
	s.recordAuditEvent(r, "issue_certificate", "success", s.auditRequestActor(r, "web"), "web", "api-token:"+strconv.FormatInt(id, 10), "")
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_certificate":            issued.Certificate,
		"client_private_key":            issued.PrivateKey,
		"client_certificate_expires_at": issued.ExpiresAt.UTC().Format(time.RFC3339),
	})
}
