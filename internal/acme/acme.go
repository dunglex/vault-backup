package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	xacme "golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
)

const alpnProto = xacme.ALPNProto

type Manager struct {
	mu             sync.RWMutex
	manager        *autocert.Manager
	allowedDomains map[string]struct{}
}

func New(cachePath string, domains []string) (*Manager, error) {
	if err := os.MkdirAll(cachePath, 0700); err != nil {
		return nil, fmt.Errorf("create ACME certificate cache: %w", err)
	}
	allowedDomains, err := normalizedDomainSet(domains)
	if err != nil {
		return nil, err
	}
	manager := &Manager{allowedDomains: allowedDomains}
	manager.manager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cachePath),
		HostPolicy: func(_ context.Context, host string) error {
			return manager.allowHost(host)
		},
	}
	return manager, nil
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.manager.GetCertificate(hello)
}

func (m *Manager) HTTPHandler(next http.Handler) http.Handler {
	return m.manager.HTTPHandler(next)
}

func (m *Manager) ConfigureTLS(config *tls.Config) {
	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}
	for _, protocol := range config.NextProtos {
		if protocol == alpnProto {
			return
		}
	}
	config.NextProtos = append([]string{alpnProto}, config.NextProtos...)
}

func (m *Manager) SetDomains(domains []string) {
	set := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		set[domain] = struct{}{}
	}
	m.mu.Lock()
	m.allowedDomains = set
	m.mu.Unlock()
}

func (m *Manager) Prepare(domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("ACME requires a main domain")
	}
	set, err := normalizedDomainSet(domains)
	if err != nil {
		return err
	}
	for _, domain := range domains {
		if net.ParseIP(domain) != nil {
			return fmt.Errorf("ACME certificates require DNS names; %q is an IP address", domain)
		}
	}

	m.mu.Lock()
	previousDomains := m.allowedDomains
	m.allowedDomains = set
	m.mu.Unlock()

	mainDomain := domains[0]
	hello := &tls.ClientHelloInfo{
		ServerName:       mainDomain,
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
	}
	if _, err := m.manager.GetCertificate(hello); err != nil {
		m.mu.Lock()
		m.allowedDomains = previousDomains
		m.mu.Unlock()
		return fmt.Errorf("obtain ACME certificate for %s: %w", mainDomain, err)
	}
	return nil
}

func (m *Manager) allowHost(host string) error {
	domain, err := normalizeHost(host)
	if err != nil {
		return err
	}
	m.mu.RLock()
	_, allowed := m.allowedDomains[domain]
	m.mu.RUnlock()
	if !allowed {
		return fmt.Errorf("ACME certificate is not allowed for %q", host)
	}
	return nil
}

func normalizedDomainSet(domains []string) (map[string]struct{}, error) {
	set := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		normalized, err := normalizeHost(domain)
		if err != nil {
			return nil, err
		}
		set[normalized] = struct{}{}
	}
	return set, nil
}

func normalizeHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" {
		return "", fmt.Errorf("invalid ACME DNS name %q", host)
	}
	return ascii, nil
}
