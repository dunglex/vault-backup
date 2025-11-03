package main

import (
	"fmt"
	"strings"

	pflag "github.com/spf13/pflag"
	viper "github.com/spf13/viper"
)

type Arguments struct {
	Url          string
	User         string
	Pass         string
	SecretName   string
	SecretPath   string
	OutputMode   string
	OutputFormat string
	OutputPath   string
	Insecure     bool
	RestoreMode  bool
	InputPath    string
}

func parseArguments() Arguments {
	// Define flags
	pflag.StringP("url", "h", "", "Vault server host url (required) [env: VAULT_URL]")
	pflag.StringP("user", "u", "", "Vault username (required) [env: VAULT_USER]")
	pflag.StringP("pass", "p", "", "Vault password (required) [env: VAULT_PASS]")
	pflag.StringP("secret_name", "n", "", "Vault secret name [env: VAULT_SECRET_NAME]")
	pflag.StringP("secret_path", "s", "", "Vault secret path [env: VAULT_SECRET_PATH]")
	pflag.StringP("output_mode", "m", "all", "Print mode: all/data/file (optional, default: all) [env: VAULT_OUTPUT_MODE]")
	pflag.StringP("output_format", "f", "json", "Output format: json, yaml, ini, env (optional, default: json) [env: VAULT_OUTPUT_FORMAT]")
	pflag.StringP("output_path", "o", ".", "Output file name or folder name (optional, works only with file mode, default: current directory) [env: VAULT_OUTPUT_PATH]")
	pflag.BoolP("insecure", "k", false, "Skip TLS certificate verification (optional, default: false) [env: VAULT_INSECURE]")
	pflag.BoolP("restore", "r", false, "Restore mode: restore secrets from backup files to Vault (optional, default: false) [env: VAULT_RESTORE]")
	pflag.StringP("input_path", "i", "", "Input file or folder path for restore mode (required for restore) [env: VAULT_INPUT_PATH]")
	pflag.Parse()

	// Bind flags to viper
	viper.BindPFlag("url", pflag.Lookup("url"))
	viper.BindPFlag("user", pflag.Lookup("user"))
	viper.BindPFlag("pass", pflag.Lookup("pass"))
	viper.BindPFlag("secret_name", pflag.Lookup("secret_name"))
	viper.BindPFlag("secret_path", pflag.Lookup("secret_path"))
	viper.BindPFlag("output_mode", pflag.Lookup("output_mode"))
	viper.BindPFlag("output_format", pflag.Lookup("output_format"))
	viper.BindPFlag("output_path", pflag.Lookup("output_path"))
	viper.BindPFlag("insecure", pflag.Lookup("insecure"))
	viper.BindPFlag("restore", pflag.Lookup("restore"))
	viper.BindPFlag("input_path", pflag.Lookup("input_path"))

	// Bind environment variables (upper case, underscores)
	viper.SetEnvPrefix("VAULT")
	viper.AutomaticEnv()
	viper.BindEnv("url")
	viper.BindEnv("user")
	viper.BindEnv("pass")
	viper.BindEnv("secret_name")
	viper.BindEnv("secret_path")
	viper.BindEnv("output_mode")
	viper.BindEnv("output_format")
	viper.BindEnv("output_path")
	viper.BindEnv("insecure")
	viper.BindEnv("restore")
	viper.BindEnv("input_path")

	// Get values from viper
	vaultAddr := viper.GetString("url")
	username := viper.GetString("user")
	password := viper.GetString("pass")
	secretName := viper.GetString("secret_name")
	secretPath := viper.GetString("secret_path")
	outputMode := viper.GetString("output_mode")
	outputFormat := viper.GetString("output_format")
	outputPath := viper.GetString("output_path")
	insecure := viper.GetBool("insecure")
	restoreMode := viper.GetBool("restore")
	inputPath := viper.GetString("input_path")

	// Validate arguments
	if vaultAddr == "" || username == "" || password == "" {
		fmt.Println("url, user, and pass are required (via flag or environment variable)")
	}

	if restoreMode {
		if inputPath == "" {
			fmt.Println("input_path is required for restore mode")
		}
		if secretName == "" {
			fmt.Println("secret_name is required for restore mode")
		}
	} else {
		if secretName == "" || secretPath == "" {
			fmt.Println("secret_name and secret_path are required for backup mode")
		}
	}

	// Allow secretName to be a full path or a relative path
	secretName = strings.TrimPrefix(secretName, "/v1/")
	secretName = strings.TrimSuffix(secretName, "/")
	secretPath = strings.TrimPrefix(secretPath, "/")

	return Arguments{
		Url:          vaultAddr,
		User:         username,
		Pass:         password,
		SecretName:   secretName,
		SecretPath:   secretPath,
		OutputMode:   outputMode,
		OutputFormat: outputFormat,
		OutputPath:   outputPath,
		Insecure:     insecure,
		RestoreMode:  restoreMode,
		InputPath:    inputPath,
	}
}
