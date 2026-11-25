package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadServerConfigAppliesEnvFileEnvironmentAndFlagPrecedence(t *testing.T) {
	unsetServerConfigEnvironment(t)
	dir := t.TempDir()
	envPath := filepath.Join(dir, "server.env")
	envFile := strings.Join([]string{
		"VAULT_SERVER_DB_PASSWORD=from-file",
		"VAULT_SERVER_HTTPS_ADDR=127.0.0.1:8100",
		"VAULT_SERVER_HTTP_ADDR=127.0.0.1:8101",
		"VAULT_SERVER_DB=" + filepath.Join(dir, "file.db"),
		"VAULT_SERVER_AUDIT_DB=" + filepath.Join(dir, "audit.db"),
		"VAULT_SERVER_ALLOW_PLAINTEXT_DB=true",
		"VAULT_SERVER_TRUSTED_PROXIES=10.10.0.0/16",
		"VAULT_SERVER_SETUP_KEY=from-file",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(envFile), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_SERVER_DB_PASSWORD", "from-process")
	t.Setenv("VAULT_SERVER_SETUP_KEY", "process-setup-key")

	config, err := loadServerConfig([]string{
		"--env-file", envPath,
		"--https-addr", "127.0.0.1:8200",
		"--db", filepath.Join(dir, "cli.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.Addr != "127.0.0.1:8200" || config.HTTPAddr != "127.0.0.1:8101" {
		t.Fatalf("addresses = %q / %q", config.Addr, config.HTTPAddr)
	}
	if config.DBPath != filepath.Join(dir, "cli.db") ||
		config.SecretsDBPath != filepath.Join(dir, "cli-secrets.db") ||
		config.AuditDBPath != filepath.Join(dir, "audit.db") {
		t.Fatalf("database paths = app:%q secrets:%q audit:%q", config.DBPath, config.SecretsDBPath, config.AuditDBPath)
	}
	if config.TLSCertPath != filepath.Join(dir, "server.crt") || config.TLSKeyPath != filepath.Join(dir, "server.key") {
		t.Fatalf("default TLS paths = %q / %q", config.TLSCertPath, config.TLSKeyPath)
	}
	if config.DBPassword != "from-process" || config.SetupKey != "process-setup-key" {
		t.Fatalf("process environment precedence failed: password %q, setup key %q", config.DBPassword, config.SetupKey)
	}
	if !config.AllowPlaintextDB || config.EnvFilePath != envPath {
		t.Fatalf("boolean or env-file config was not loaded: %#v", config)
	}
	if len(config.TrustedProxyRanges) != 1 || !config.TrustedProxyRanges[0].Contains(net.ParseIP("10.10.2.3")) {
		t.Fatalf("trusted proxy ranges = %#v", config.TrustedProxyRanges)
	}
}

func TestLoadServerConfigValidatesRequiredAndRelatedOptions(t *testing.T) {
	unsetServerConfigEnvironment(t)
	t.Setenv("VAULT_SERVER_DB_PASSWORD", "valid-password")
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "half TLS pair",
			args: []string{"--env-file=", "--tls-cert", "server.crt"},
			want: "must either both be set",
		},
		{
			name: "same database paths",
			args: []string{"--env-file=", "--db", "same.db", "--audit-db", "same.db"},
			want: "must differ",
		},
		{
			name: "secrets database reuses app path",
			args: []string{"--env-file=", "--db", "same.db", "--secrets-db", "same.db"},
			want: "secrets database path must differ",
		},
		{
			name: "invalid trusted proxy",
			args: []string{"--env-file=", "--trusted-proxies", "not-an-address"},
			want: "invalid trusted proxy",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadServerConfig(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("loadServerConfig error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestLoadServerConfigReportsHelpRequest(t *testing.T) {
	unsetServerConfigEnvironment(t)
	_, err := loadServerConfig([]string{"--help"})
	if !errors.Is(err, errHelpRequested) {
		t.Fatalf("help error = %v", err)
	}
}

func unsetServerConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"VAULT_SERVER_HTTPS_ADDR",
		"VAULT_SERVER_HTTP_ADDR",
		"VAULT_SERVER_DB",
		"VAULT_SERVER_SECRETS_DB",
		"VAULT_SERVER_AUDIT_DB",
		"VAULT_SERVER_TLS_CERT",
		"VAULT_SERVER_TLS_KEY",
		"VAULT_SERVER_DB_PASSWORD",
		"VAULT_SERVER_ALLOW_PLAINTEXT_DB",
		"VAULT_SERVER_ENV_FILE",
		"VAULT_SERVER_MTLS_CA_CERT",
		"VAULT_SERVER_TRUSTED_PROXIES",
		"VAULT_SERVER_SETUP_KEY",
	} {
		value, exists := os.LookupEnv(key)
		key := key
		t.Cleanup(func() {
			if exists {
				_ = os.Setenv(key, value)
			} else {
				_ = os.Unsetenv(key)
			}
		})
		_ = os.Unsetenv(key)
	}
}
