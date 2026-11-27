package main

import (
	"bufio"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var errHelpRequested = errors.New("help requested")

type serverConfig struct {
	Addr               string
	HTTPAddr           string
	DBPath             string
	DataDir            string
	BackupDir          string
	SecretsDBPath      string
	OperatorDBPath     string
	AuditDBPath        string
	TLSCertPath        string
	TLSKeyPath         string
	DBPassword         string
	AllowPlaintextDB   bool
	EnvFilePath        string
	MTLSCACertPath     string
	MTLSCAPool         *x509.CertPool
	TrustedProxyRanges []*net.IPNet
	SetupKey           string
}

func loadServerConfigFromProcess() (serverConfig, error) {
	return loadServerConfig(os.Args[1:])
}

func loadServerConfig(args []string) (serverConfig, error) {
	envFilePath := envFileFromArgs(args)
	if envFilePath != "" {
		if err := loadDotEnv(envFilePath); err != nil {
			return serverConfig{}, err
		}
	}

	flags := flag.NewFlagSet("vault-server", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := serverConfig{}
	flags.StringVar(&config.Addr, "https-addr", envDefault("VAULT_SERVER_HTTPS_ADDR", "127.0.0.1:8200"), "HTTPS server address")
	flags.StringVar(&config.HTTPAddr, "http-addr", envDefault("VAULT_SERVER_HTTP_ADDR", "127.0.0.1:8201"), "HTTP server address (disabled by default)")
	flags.StringVar(&config.DBPath, "db", envDefault("VAULT_SERVER_DB", "vault.db"), "path to database file")
	flags.StringVar(&config.DataDir, "data-dir", envDefault("VAULT_SERVER_DATA_DIR", ""), "directory containing server state files")
	flags.StringVar(&config.BackupDir, "backup-dir", envDefault("VAULT_SERVER_BACKUP_DIR", ""), "directory for scheduled server backups")
	flags.StringVar(&config.SecretsDBPath, "secrets-db", envDefault("VAULT_SERVER_SECRETS_DB", ""), "path to encrypted secrets database")
	flags.StringVar(&config.OperatorDBPath, "operator-db", envDefault("VAULT_SERVER_OPERATOR_DB", ""), "optional path to encrypted operator database (enables operator accounts)")
	flags.StringVar(&config.AuditDBPath, "audit-db", envDefault("VAULT_SERVER_AUDIT_DB", ""), "path to plaintext audit database file (default: alongside main database)")
	flags.StringVar(&config.TLSCertPath, "tls-cert", envDefault("VAULT_SERVER_TLS_CERT", ""), "path to TLS certificate PEM")
	flags.StringVar(&config.TLSKeyPath, "tls-key", envDefault("VAULT_SERVER_TLS_KEY", ""), "path to TLS private key PEM")
	flags.StringVar(&config.DBPassword, "db-password", envDefault("VAULT_SERVER_DB_PASSWORD", ""), "password used to decrypt the database key file")
	flags.BoolVar(&config.AllowPlaintextDB, "allow-plaintext-db", envBool("VAULT_SERVER_ALLOW_PLAINTEXT_DB", false), "allow an existing plaintext SQLite database (insecure)")
	flags.StringVar(&config.EnvFilePath, "env-file", envDefault("VAULT_SERVER_ENV_FILE", ".env"), "path to .env configuration file")
	flags.StringVar(&config.MTLSCACertPath, "mtls-ca-cert", envDefault("VAULT_SERVER_MTLS_CA_CERT", ""), "CA certificate PEM used to verify HTTPS client certificates")
	trustedProxies := flags.String("trusted-proxies", envDefault("VAULT_SERVER_TRUSTED_PROXIES", ""), "comma-separated proxy IP/CIDR ranges allowed to set forwarding headers")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return serverConfig{}, errHelpRequested
		}
		return serverConfig{}, fmt.Errorf("parse command-line arguments: %w", err)
	}
	config.EnvFilePath = strings.TrimSpace(config.EnvFilePath)
	config.HTTPAddr = strings.TrimSpace(config.HTTPAddr)
	config.SecretsDBPath = strings.TrimSpace(config.SecretsDBPath)
	config.OperatorDBPath = strings.TrimSpace(config.OperatorDBPath)
	config.DataDir = strings.TrimSpace(config.DataDir)
	config.BackupDir = strings.TrimSpace(config.BackupDir)
	config.TLSCertPath = strings.TrimSpace(config.TLSCertPath)
	config.TLSKeyPath = strings.TrimSpace(config.TLSKeyPath)
	config.SetupKey = os.Getenv("VAULT_SERVER_SETUP_KEY")

	if (config.TLSCertPath == "") != (config.TLSKeyPath == "") {
		return serverConfig{}, fmt.Errorf("--tls-cert and --tls-key must either both be set or both be omitted")
	}
	if config.DBPassword == "" {
		return serverConfig{}, fmt.Errorf("database key password is required: set --db-password or VAULT_SERVER_DB_PASSWORD")
	}

	resolvedDB, err := filepath.Abs(config.DBPath)
	if err != nil {
		return serverConfig{}, fmt.Errorf("resolve database path: %w", err)
	}
	config.DBPath = filepath.Clean(resolvedDB)
	if config.DataDir == "" {
		config.DataDir = filepath.Dir(config.DBPath)
	} else if config.DataDir, err = absoluteCleanPath(config.DataDir); err != nil {
		return serverConfig{}, fmt.Errorf("resolve data directory: %w", err)
	}
	if config.BackupDir == "" {
		config.BackupDir = filepath.Join(filepath.Dir(config.DataDir), "backup")
	} else if config.BackupDir, err = absoluteCleanPath(config.BackupDir); err != nil {
		return serverConfig{}, fmt.Errorf("resolve backup directory: %w", err)
	}
	if filepath.Clean(config.BackupDir) == filepath.Clean(config.DataDir) {
		return serverConfig{}, fmt.Errorf("backup directory must differ from the server data directory")
	}
	if config.SecretsDBPath == "" {
		config.SecretsDBPath = defaultSecretsDatabasePath(config.DBPath)
	} else if config.SecretsDBPath, err = absoluteCleanPath(config.SecretsDBPath); err != nil {
		return serverConfig{}, fmt.Errorf("resolve secrets database path: %w", err)
	}
	if config.OperatorDBPath != "" {
		if config.OperatorDBPath, err = absoluteCleanPath(config.OperatorDBPath); err != nil {
			return serverConfig{}, fmt.Errorf("resolve operator database path: %w", err)
		}
	}
	if config.TLSCertPath == "" {
		config.TLSCertPath = filepath.Join(filepath.Dir(config.DBPath), "server.crt")
		config.TLSKeyPath = filepath.Join(filepath.Dir(config.DBPath), "server.key")
	}
	if config.TLSCertPath, err = absoluteCleanPath(config.TLSCertPath); err != nil {
		return serverConfig{}, fmt.Errorf("resolve TLS certificate path: %w", err)
	}
	if config.TLSKeyPath, err = absoluteCleanPath(config.TLSKeyPath); err != nil {
		return serverConfig{}, fmt.Errorf("resolve TLS key path: %w", err)
	}

	config.AuditDBPath = strings.TrimSpace(config.AuditDBPath)
	if config.AuditDBPath == "" {
		config.AuditDBPath = filepath.Join(filepath.Dir(config.DBPath), "audit.db")
	}
	if config.AuditDBPath, err = absoluteCleanPath(config.AuditDBPath); err != nil {
		return serverConfig{}, fmt.Errorf("resolve audit database path: %w", err)
	}
	if config.AuditDBPath == config.DBPath {
		return serverConfig{}, fmt.Errorf("audit database path must differ from the encrypted main database path")
	}
	if config.SecretsDBPath == config.DBPath || config.SecretsDBPath == config.AuditDBPath {
		return serverConfig{}, fmt.Errorf("secrets database path must differ from the app and audit database paths")
	}
	if config.OperatorDBPath != "" &&
		(config.OperatorDBPath == config.DBPath ||
			config.OperatorDBPath == config.SecretsDBPath ||
			config.OperatorDBPath == config.AuditDBPath) {
		return serverConfig{}, fmt.Errorf("operator database path must differ from the app, secrets, and audit database paths")
	}
	config.TrustedProxyRanges, err = parseTrustedProxies(*trustedProxies)
	if err != nil {
		return serverConfig{}, err
	}
	if strings.TrimSpace(config.MTLSCACertPath) != "" {
		config.MTLSCAPool, err = loadClientCAPool(config.MTLSCACertPath)
		if err != nil {
			return serverConfig{}, err
		}
	}
	return config, nil
}

func defaultSecretsDatabasePath(appDBPath string) string {
	extension := filepath.Ext(appDBPath)
	name := strings.TrimSuffix(filepath.Base(appDBPath), extension)
	return filepath.Join(filepath.Dir(appDBPath), name+"-secrets"+extension)
}

func defaultOperatorDatabasePath(appDBPath string) string {
	extension := filepath.Ext(appDBPath)
	name := strings.TrimSuffix(filepath.Base(appDBPath), extension)
	return filepath.Join(filepath.Dir(appDBPath), name+"-operators"+extension)
}

func absoluteCleanPath(path string) (string, error) {
	resolved, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("WARNING: invalid boolean value for %s=%q; using %t", name, value, fallback)
		return fallback
	}
	return parsed
}

func envFileFromArgs(args []string) string {
	path := envDefault("VAULT_SERVER_ENV_FILE", ".env")
	for i, arg := range args {
		if arg == "--" {
			break
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if name != "env-file" {
			continue
		}
		if hasValue {
			path = value
		} else if i+1 < len(args) {
			path = args[i+1]
		}
		break
	}
	return strings.TrimSpace(path)
}

func loadDotEnv(path string) error {
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("could not open env file %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if key != "" {
			if _, exists := os.LookupEnv(key); !exists {
				if err := os.Setenv(key, value); err != nil {
					return fmt.Errorf("could not load %s from env file %s: %w", key, path, err)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("could not read env file %s: %w", path, err)
	}
	return nil
}

func loadClientCAPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read mTLS client CA certificate %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("mTLS client CA file %s contains no valid PEM certificates", path)
	}
	return pool, nil
}

func parseTrustedProxies(value string) ([]*net.IPNet, error) {
	var ranges []*net.IPNet
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy address %q", part)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			part += fmt.Sprintf("/%d", bits)
		}
		_, network, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", part, err)
		}
		ranges = append(ranges, network)
	}
	return ranges, nil
}
