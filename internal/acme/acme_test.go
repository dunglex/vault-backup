package acme

import (
	"crypto/tls"
	"path/filepath"
	"reflect"
	"testing"
)

func TestHostPolicyRestrictsCertificatesToConfiguredDomains(t *testing.T) {
	manager, err := New(filepath.Join(t.TempDir(), "cache"), []string{"Vault.Example.com."})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.allowHost("vault.example.com"); err != nil {
		t.Fatalf("configured domain was rejected: %v", err)
	}
	if err := manager.allowHost("other.example.com"); err == nil {
		t.Fatal("unconfigured domain was accepted")
	}
}

func TestPrepareRejectsIPAddresses(t *testing.T) {
	manager, err := New(filepath.Join(t.TempDir(), "cache"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Prepare([]string{"vault.example.com", "127.0.0.1"}); err == nil {
		t.Fatal("IP address was accepted for ACME")
	}
}

func TestConfigureTLSAddsChallengeProtocolWithoutRemovingHTTPProtocols(t *testing.T) {
	manager, err := New(filepath.Join(t.TempDir(), "cache"), nil)
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	manager.ConfigureTLS(config)
	if !reflect.DeepEqual(config.NextProtos, []string{alpnProto, "h2", "http/1.1"}) {
		t.Fatalf("TLS protocols = %#v", config.NextProtos)
	}
	manager.ConfigureTLS(config)
	if !reflect.DeepEqual(config.NextProtos, []string{alpnProto, "h2", "http/1.1"}) {
		t.Fatalf("TLS protocols after repeated configuration = %#v", config.NextProtos)
	}
	defaultConfig := &tls.Config{}
	manager.ConfigureTLS(defaultConfig)
	if !reflect.DeepEqual(defaultConfig.NextProtos, []string{alpnProto, "h2", "http/1.1"}) {
		t.Fatalf("default TLS protocols = %#v", defaultConfig.NextProtos)
	}
}
