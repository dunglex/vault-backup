package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	pflag "github.com/spf13/pflag"
	viper "github.com/spf13/viper"
)

type Arguments struct {
	Url           string
	User          string
	Pass          string
	Token         string
	SecretName    string
	SecretPath    string
	OutputMode    string
	OutputFormat  string
	OutputPath    string
	Insecure      bool
	RestoreMode   bool
	InputPath     string
	CACert        string
	ClientCert    string
	ClientKey     string
	TLSServerName string
}

func parseArguments() (Arguments, error) {
	// Define flags
	pflag.StringP("url", "h", "", "Vault server host url (required) [env: VAULT_URL]")
	pflag.StringP("user", "u", "", "Vault username (required) [env: VAULT_USER]")
	pflag.StringP("pass", "p", "", "Vault password (required) [env: VAULT_PASS]")
	pflag.StringP("token", "t", "", "Managed Vault API token (alternative to user/pass) [env: VAULT_TOKEN]")
	pflag.StringP("secret_name", "n", "", "Vault secret name [env: VAULT_SECRET_NAME]")
	pflag.StringP("secret_path", "s", "", "Vault secret path [env: VAULT_SECRET_PATH]")
	pflag.StringP("output_mode", "m", "all", "Print mode: all/data/file (optional, default: all) [env: VAULT_OUTPUT_MODE]")
	pflag.StringP("output_format", "f", "json", "Output format: json, yaml, ini, env (optional, default: json) [env: VAULT_OUTPUT_FORMAT]")
	pflag.StringP("output_path", "o", ".", "Output file name or folder name (optional, works only with file mode, default: current directory) [env: VAULT_OUTPUT_PATH]")
	pflag.BoolP("insecure", "k", false, "Skip TLS certificate verification (optional, default: false) [env: VAULT_INSECURE]")
	pflag.BoolP("restore", "r", false, "Restore mode: restore secrets from backup files to Vault (optional, default: false) [env: VAULT_RESTORE]")
	pflag.StringP("input_path", "i", "", "Input file or folder path for restore mode (required for restore) [env: VAULT_INPUT_PATH]")
	pflag.String("ca_cert", "", "CA certificate PEM used to verify the Vault server certificate [env: VAULT_CA_CERT]")
	pflag.String("client_cert", "", "Client certificate PEM for mutual TLS [env: VAULT_CLIENT_CERT]")
	pflag.String("client_key", "", "Client private key PEM for mutual TLS [env: VAULT_CLIENT_KEY]")
	pflag.String("tls_server_name", "", "TLS server name override [env: VAULT_TLS_SERVER_NAME]")
	pflag.Parse()

	// Bind flags to viper
	viper.BindPFlag("url", pflag.Lookup("url"))
	viper.BindPFlag("user", pflag.Lookup("user"))
	viper.BindPFlag("pass", pflag.Lookup("pass"))
	viper.BindPFlag("token", pflag.Lookup("token"))
	viper.BindPFlag("secret_name", pflag.Lookup("secret_name"))
	viper.BindPFlag("secret_path", pflag.Lookup("secret_path"))
	viper.BindPFlag("output_mode", pflag.Lookup("output_mode"))
	viper.BindPFlag("output_format", pflag.Lookup("output_format"))
	viper.BindPFlag("output_path", pflag.Lookup("output_path"))
	viper.BindPFlag("insecure", pflag.Lookup("insecure"))
	viper.BindPFlag("restore", pflag.Lookup("restore"))
	viper.BindPFlag("input_path", pflag.Lookup("input_path"))
	viper.BindPFlag("ca_cert", pflag.Lookup("ca_cert"))
	viper.BindPFlag("client_cert", pflag.Lookup("client_cert"))
	viper.BindPFlag("client_key", pflag.Lookup("client_key"))
	viper.BindPFlag("tls_server_name", pflag.Lookup("tls_server_name"))

	// Bind environment variables (upper case, underscores)
	viper.SetEnvPrefix("VAULT")
	viper.AutomaticEnv()
	viper.BindEnv("url")
	viper.BindEnv("user")
	viper.BindEnv("pass")
	viper.BindEnv("token")
	viper.BindEnv("secret_name")
	viper.BindEnv("secret_path")
	viper.BindEnv("output_mode")
	viper.BindEnv("output_format")
	viper.BindEnv("output_path")
	viper.BindEnv("insecure")
	viper.BindEnv("restore")
	viper.BindEnv("input_path")
	viper.BindEnv("ca_cert")
	viper.BindEnv("client_cert")
	viper.BindEnv("client_key")
	viper.BindEnv("tls_server_name")

	// Get values from viper
	vaultAddr := strings.TrimSpace(viper.GetString("url"))
	username := strings.TrimSpace(viper.GetString("user"))
	password := viper.GetString("pass")
	token := strings.TrimSpace(viper.GetString("token"))
	secretName := strings.TrimSpace(viper.GetString("secret_name"))
	secretPath := strings.TrimSpace(viper.GetString("secret_path"))
	outputMode := viper.GetString("output_mode")
	outputFormat := viper.GetString("output_format")
	outputPath := strings.TrimSpace(viper.GetString("output_path"))
	insecure := viper.GetBool("insecure")
	restoreMode := viper.GetBool("restore")
	inputPath := strings.TrimSpace(viper.GetString("input_path"))
	caCert := strings.TrimSpace(viper.GetString("ca_cert"))
	clientCert := strings.TrimSpace(viper.GetString("client_cert"))
	clientKey := strings.TrimSpace(viper.GetString("client_key"))
	tlsServerName := strings.TrimSpace(viper.GetString("tls_server_name"))

	// Allow secretName to be a full path or a relative path
	secretName = strings.TrimSuffix(strings.TrimPrefix(secretName, "/v1/"), "/")
	secretPath = strings.TrimPrefix(secretPath, "/")
	outputMode = strings.ToLower(strings.TrimSpace(outputMode))
	outputFormat = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(outputFormat), "."))

	arguments := Arguments{
		Url:           vaultAddr,
		User:          username,
		Pass:          password,
		Token:         token,
		SecretName:    secretName,
		SecretPath:    secretPath,
		OutputMode:    outputMode,
		OutputFormat:  outputFormat,
		OutputPath:    outputPath,
		Insecure:      insecure,
		RestoreMode:   restoreMode,
		InputPath:     inputPath,
		CACert:        caCert,
		ClientCert:    clientCert,
		ClientKey:     clientKey,
		TLSServerName: tlsServerName,
	}
	return arguments, validateArguments(arguments)
}

func validateArguments(arguments Arguments) error {
	var failures []string
	addFailure := func(message string) {
		failures = append(failures, message)
	}

	arguments.Url = strings.TrimSpace(arguments.Url)
	parsedURL, err := url.Parse(arguments.Url)
	if arguments.Url == "" {
		addFailure("url is required")
	} else if err != nil || parsedURL == nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		addFailure("url must be an absolute http or https URL")
	}

	hasUser := strings.TrimSpace(arguments.User) != ""
	hasPass := strings.TrimSpace(arguments.Pass) != ""
	hasToken := strings.TrimSpace(arguments.Token) != ""
	if hasUser != hasPass {
		addFailure("user and pass must be provided together")
	}
	if !hasToken && !(hasUser && hasPass) {
		addFailure("either token or user/pass is required")
	}
	if hasToken && (hasUser || hasPass) {
		addFailure("token cannot be combined with user or pass")
	}

	if strings.TrimSpace(arguments.ClientCert) == "" != (strings.TrimSpace(arguments.ClientKey) == "") {
		addFailure("client_cert and client_key must be provided together")
	}
	if arguments.Insecure && (strings.TrimSpace(arguments.CACert) != "" ||
		strings.TrimSpace(arguments.ClientCert) != "" ||
		strings.TrimSpace(arguments.ClientKey) != "") {
		addFailure("insecure cannot be combined with a custom CA or mTLS configuration")
	}

	if arguments.SecretName == "" {
		addFailure("secret_name is required")
	}
	if arguments.RestoreMode {
		if strings.TrimSpace(arguments.InputPath) == "" {
			addFailure("input_path is required for restore mode")
		}
	} else {
		if arguments.SecretPath == "" {
			addFailure("secret_path is required for backup mode")
		}
		switch arguments.OutputMode {
		case "all", "data", "file":
		default:
			addFailure("output_mode must be one of: all, data, file")
		}
		switch arguments.OutputFormat {
		case "json", "yaml", "yml", "ini", "env":
		default:
			addFailure("output_format must be one of: json, yaml, yml, ini, env")
		}
		if strings.EqualFold(arguments.OutputMode, "file") && strings.TrimSpace(arguments.OutputPath) == "" {
			addFailure("output_path is required when output_mode is file")
		}
	}

	if parsedURL != nil && strings.EqualFold(parsedURL.Scheme, "http") {
		fmt.Fprintln(os.Stderr, "WARNING: insecure HTTP Vault URL; credentials and secret data may be exposed without TLS")
	}
	if len(failures) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(failures, "; "))
	}
	return nil
}
