package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	vault "github.com/hashicorp/vault/api"
	pflag "github.com/spf13/pflag"
	viper "github.com/spf13/viper"
	yaml "gopkg.in/yaml.v3"
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
}

func parseArguments() Arguments {
	// Define flags
	pflag.StringP("url", "h", "", "Vault server host url (required)")
	pflag.StringP("user", "u", "", "Vault username (required)")
	pflag.StringP("pass", "p", "", "Vault password (required)")
	pflag.StringP("secret_name", "n", "", "Vault secret name")
	pflag.StringP("secret_path", "s", "", "Vault secret path")
	pflag.StringP("output_mode", "m", "all", "Print mode: all/data/file (optional, default: all)")
	pflag.StringP("output_format", "f", "json", "Output format: json, yaml, ini, env (optional, default: json)")
	pflag.StringP("output_path", "o", ".", "Output file name or folder name (optional, works only with file mode, default: current directory)")
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

	// Get values from viper
	vaultAddr := viper.GetString("url")
	username := viper.GetString("user")
	password := viper.GetString("pass")
	secretName := viper.GetString("secret_name")
	secretPath := viper.GetString("secret_path")
	outputMode := viper.GetString("output_mode")
	outputFormat := viper.GetString("output_format")
	outputPath := viper.GetString("output_path")

	// Validate arguments
	if vaultAddr == "" || username == "" || password == "" || secretName == "" || secretPath == "" {
		log.Fatal("All of url, user, pass, secret_name and secret_path are required (via flag or environment variable)")
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
	}
}

// outputMode: "all" (console, key+data), "data" (console, only data), "file" (write to file)
func writeOutput(data map[string]any, outputMode, outputFormat, outputPath, fileName string) {
	var outputData string

	format := strings.ToLower(outputFormat)
	getFormatted := func(d map[string]any) string {
		switch format {
		case "ini", ".ini":
			return toINI(d)
		case "env", ".env":
			return toENV(d)
		case "json", ".json":
			return toJSON(d)
		case "yml", "yaml", ".yml", ".yaml":
			return toYAML(d)
		default:
			jsonBytes, _ := json.MarshalIndent(d, "", "  ")
			return string(jsonBytes)
		}
	}

	switch outputMode {
	case "all":
		outputData = getFormatted(data)
		fmt.Println(outputData)
		return
	case "data":
		if d, ok := data["data"].(map[string]any); ok {
			outputData = getFormatted(d)
		} else {
			log.Fatalf("Expected 'data' key in secret map")
		}
		fmt.Println(outputData)
		return
	case "file":
		if d, ok := data["data"].(map[string]any); ok {
			outputData = getFormatted(d)
		} else {
			log.Fatalf("Expected 'data' key in secret map")
		}
		filePath := outputPath + "/" + fileName
		if err := os.MkdirAll(outputPath, 0755); err != nil {
			log.Fatalf("Failed to create output directory: %v", err)
		}
		if !strings.HasSuffix(fileName, ".ini") &&
			!strings.HasSuffix(fileName, ".env") &&
			!strings.HasSuffix(fileName, ".json") &&
			!strings.HasSuffix(fileName, ".yml") &&
			!strings.HasSuffix(fileName, ".yaml") {
			filePath = filePath + "." + strings.Replace(outputFormat, ".", "", -1)
		}
		err := os.WriteFile(filePath, []byte(outputData), 0644)
		if err != nil {
			log.Fatalf("Failed to write to file: %v", err)
		}
		fmt.Printf("Secrets written to %s\n", filePath)
		return
	default:
		log.Fatalf("Unknown output mode: %s", outputMode)
	}
}

func toINI(data map[string]any) string {
	var sb strings.Builder
	for k, v := range data {
		sb.WriteString(fmt.Sprintf("%s=%v\n", k, v))
	}
	return sb.String()
}

func toENV(data map[string]any) string {
	var sb strings.Builder
	for k, v := range data {
		sb.WriteString(fmt.Sprintf("%s=%v\n", strings.ToUpper(k), v))
	}
	return sb.String()
}

func toJSON(data map[string]any) string {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal data to JSON: %v", err)
	}
	return string(jsonBytes)
}

func toYAML(data map[string]any) string {
	yamlBytes, err := yaml.Marshal(data)
	if err != nil {
		log.Fatalf("Failed to marshal data to YAML: %v", err)
	}
	return string(yamlBytes)
}

func main() {
	// Get arguments from command line or environment variables
	arguments := parseArguments()

	// Connect to Vault
	config := vault.DefaultConfig()
	config.Address = arguments.Url
	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create Vault client: %v", err)
	}

	// Authenticate with LDAP username/password
	data := map[string]any{
		"password": arguments.Pass,
	}
	loginPath := fmt.Sprintf("auth/ldap/login/%s", arguments.User)
	secret, err := client.Logical().Write(loginPath, data)
	if err != nil || secret == nil || secret.Auth == nil {
		log.Fatalf("Failed to authenticate with LDAP: %v", err)
	}
	client.SetToken(secret.Auth.ClientToken)

	// Read secrets or list folder
	if strings.HasSuffix(arguments.SecretPath, "/") {
		// List keys in the folder
		metadataPath := arguments.SecretName + "/metadata/" + arguments.SecretPath
		list, err := client.Logical().List(metadataPath)
		if err != nil || list == nil || list.Data == nil {
			log.Fatalf("Failed to list secrets in folder %s: %v", arguments.SecretPath, err)
		}
		keys, ok := list.Data["keys"].([]any)
		if !ok {
			log.Fatalf("Unexpected data format when listing folder %s", arguments.SecretPath)
		}
		for _, key := range keys {
			keyStr, ok := key.(string)
			if !ok {
				continue
			}
			keyStr = strings.TrimPrefix(keyStr, "/")
			fullPath := arguments.SecretName + "/data/" + arguments.SecretPath + keyStr
			secretData, err := client.Logical().Read(fullPath)
			if err != nil || secretData == nil || secretData.Data == nil {
				log.Printf("Failed to read secret %s: %v (maybe a folder)", arguments.SecretPath+keyStr, err)
				continue
			}
			secrets := map[string]any{
				"key":  fullPath,
				"data": secretData.Data["data"],
			}
			var outputPath string
			// Because we are exporting a folder, so treat outputPath as a folder
			// If OutputPath does not end with "/", add it
			// Preseve folder structure in file name
			if !strings.HasSuffix(arguments.OutputPath, "/") {
				outputPath = arguments.OutputPath + "/" + strings.TrimSuffix(arguments.SecretPath, "/")
			} else {
				outputPath = arguments.OutputPath + strings.TrimSuffix(arguments.SecretPath, "/")
			}
			writeOutput(secrets, arguments.OutputMode, arguments.OutputFormat, outputPath, keyStr)
		}
	} else {
		// Read a single secret
		fullPath := arguments.SecretName + "/data/" + arguments.SecretPath
		secretData, err := client.Logical().Read(fullPath)
		if err != nil || secretData == nil || secretData.Data == nil {
			log.Printf("Failed to read secret %s: %v (invalid path or maybe a folder)", arguments.SecretPath, err)
		}
		secrets := map[string]any{
			"key":  fullPath,
			"data": secretData.Data["data"],
		}
		// Because we are exporting a single secret, so treat outputPath as a file if it does not end with "/"
		// If outputPath ends with "/", it is treated as a folder, concat actual file name to it
		// To get file name from secret path, obmit the folder structure, only keep the last part of the path
		var outputPath, fileName string
		if strings.HasSuffix(arguments.OutputPath, "/") {
			outputPath = strings.TrimSuffix(arguments.OutputPath, "/")
			lastIndex := len(strings.Split(arguments.SecretPath, "/")) - 1
			fileName = strings.Split(arguments.SecretPath, "/")[lastIndex]
		} else {
			outputPath, fileName = filepath.Split(arguments.OutputPath)
			if outputPath == "" {
				outputPath = "."
			}
			if fileName == "" {
				fileName = strings.TrimSuffix(arguments.SecretPath, "/")
			}
		}
		writeOutput(secrets, arguments.OutputMode, arguments.OutputFormat, outputPath, fileName)
	}
}
