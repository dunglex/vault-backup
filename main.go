package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
	pflag "github.com/spf13/pflag"
	viper "github.com/spf13/viper"
	yaml "gopkg.in/yaml.v3"
)

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
	data := map[string]interface{}{
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
		metadataPath := arguments.EnginePath + "/metadata/" + arguments.SecretPath
		list, err := client.Logical().List(metadataPath)
		if err != nil || list == nil || list.Data == nil {
			log.Fatalf("Failed to list secrets in folder %s: %v", arguments.SecretPath, err)
		}
		keys, ok := list.Data["keys"].([]interface{})
		if !ok {
			log.Fatalf("Unexpected data format when listing folder %s", arguments.SecretPath)
		}
		for _, key := range keys {
			keyStr, ok := key.(string)
			if !ok {
				continue
			}
			fullPath := arguments.EnginePath + "/data/" + arguments.SecretPath + keyStr
			secretData, err := client.Logical().Read(fullPath)
			if err != nil || secretData == nil || secretData.Data == nil {
				log.Printf("Failed to read secret %s: %v", arguments.SecretPath+keyStr, err)
				continue
			}
			secrets := map[string]interface{}{
				"key":  fullPath,
				"data": secretData.Data["data"],
			}
			// Preseve folder structure in file name
			outputPath := arguments.OutputPath + "/" + arguments.SecretPath
			// Ensure the output directory exists
			if err := os.MkdirAll(outputPath, 0755); err != nil {
				log.Fatalf("Failed to create output directory: %v", err)
			}
			writeOutput(secrets, outputPath, arguments.OutputFormat, keyStr, arguments.PrintToStdout)
		}
	} else {
		// Read a single secret
		fullPath := arguments.EnginePath + "/data/" + arguments.SecretPath
		secretData, err := client.Logical().Read(fullPath)
		if err != nil || secretData == nil || secretData.Data == nil {
			log.Fatalf("Failed to read secrets from path %s: %v", arguments.SecretPath, err)
		}
		secrets := map[string]interface{}{
			"key":  fullPath,
			"data": secretData.Data["data"],
		}
		// Get file name from secret path
		// Obmit the folder structure, only keep the last part of the path
		fileName := strings.Split(arguments.SecretPath, "/")[len(strings.Split(arguments.SecretPath, "/"))-1]
		writeOutput(secrets, arguments.OutputPath, arguments.OutputFormat, fileName, arguments.PrintToStdout)
	}
}

type Arguments struct {
	Url           string
	User          string
	Pass          string
	EnginePath    string
	SecretPath    string
	OutputPath    string
	OutputFormat  string
	PrintToStdout bool
}

func parseArguments() Arguments {
	// Define flags
	pflag.String("url", "", "Vault server URL")
	pflag.String("user", "", "Vault username")
	pflag.String("pass", "", "Vault password")
	pflag.String("engine_path", "", "Vault engine path")
	pflag.String("secret_path", "", "Vault secret path")
	pflag.String("output_path", ".", "Output file name or folder name (optional, if not provided, keep as is)")
	pflag.String("output_format", "json", "Output format: json, yaml, ini, env (optional, default: json)")
	pflag.Bool("print_to_stdout", false, "Print output to stdout instead of file (optional, default: false)")
	pflag.Parse()

	// Bind flags to viper
	viper.BindPFlag("url", pflag.Lookup("url"))
	viper.BindPFlag("user", pflag.Lookup("user"))
	viper.BindPFlag("pass", pflag.Lookup("pass"))
	viper.BindPFlag("engine_path", pflag.Lookup("engine_path"))
	viper.BindPFlag("secret_path", pflag.Lookup("secret_path"))
	viper.BindPFlag("output_path", pflag.Lookup("output_path"))
	viper.BindPFlag("output_format", pflag.Lookup("output_format"))
	viper.BindPFlag("print_to_stdout", pflag.Lookup("print_to_stdout"))

	// Bind environment variables (upper case, underscores)
	viper.SetEnvPrefix("VAULT")
	viper.AutomaticEnv()
	viper.BindEnv("url")
	viper.BindEnv("user")
	viper.BindEnv("pass")
	viper.BindEnv("engine_path")
	viper.BindEnv("secret_path")
	viper.BindEnv("output_path")
	viper.BindEnv("output_format")
	viper.BindEnv("print_to_stdout")

	// Get values from viper
	vaultAddr := viper.GetString("url")
	username := viper.GetString("user")
	password := viper.GetString("pass")
	enginePath := viper.GetString("engine_path")
	secretPath := viper.GetString("secret_path")
	outputPath := viper.GetString("output_path")
	outputFormat := viper.GetString("output_format")
	printToStdOut := viper.GetBool("print_to_stdout")

	// Validate arguments
	if vaultAddr == "" || username == "" || password == "" || secretPath == "" {
		log.Fatal("All of url, user, pass, and path are required (via flag or environment variable)")
	}

	// Allow enginePath to be a full path or a relative path
	enginePath = strings.TrimPrefix(enginePath, "/v1/")
	enginePath = strings.TrimSuffix(enginePath, "/")
	secretPath = strings.TrimPrefix(secretPath, "/")
	outputPath = strings.TrimSuffix(outputPath, "/")

	return Arguments{
		Url:           vaultAddr,
		User:          username,
		Pass:          password,
		EnginePath:    enginePath,
		SecretPath:    secretPath,
		OutputPath:    outputPath,
		OutputFormat:  outputFormat,
		PrintToStdout: printToStdOut,
	}
}

func writeOutput(data map[string]interface{}, outputPath, outputFormat string, fileName string, printToStdout bool) {
	var outputData string

	// Output to console
	if printToStdout {
		switch strings.ToLower(outputFormat) {
		case "ini", ".ini":
			outputData = toINI(data)
		case "env", ".env":
			outputData = toENV(data)
		case "json", ".json":
			outputData = toJSON(data)
		case "yml", "yaml", ".yml", ".yaml":
			outputData = toYAML(data)
		default:
			jsonBytes, _ := json.MarshalIndent(data, "", "  ")
			outputData = string(jsonBytes)
		}
		fmt.Println(outputData)
		return
	}

	// Output to file
	switch strings.ToLower(outputFormat) {
	case "ini", ".ini":
		outputData = toINI(data["data"].(map[string]interface{}))
	case "env", ".env":
		outputData = toENV(data["data"].(map[string]interface{}))
	case "json", ".json":
		outputData = toJSON(data["data"].(map[string]interface{}))
	case "yml", "yaml", ".yml", ".yaml":
		outputData = toYAML(data["data"].(map[string]interface{}))
	default:
		jsonBytes, _ := json.MarshalIndent(data, "", "  ")
		outputData = string(jsonBytes)
	}

	filePath := outputPath + fileName
	// Ensure the output directory exists
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// If fileName does not end with a file extension, append the output format
	if !strings.HasSuffix(fileName, ".ini") &&
		!strings.HasSuffix(fileName, ".env") &&
		!strings.HasSuffix(fileName, ".json") &&
		!strings.HasSuffix(fileName, ".yml") &&
		!strings.HasSuffix(fileName, ".yaml") {
		filePath = filePath + "." + strings.Replace(outputFormat, ".", "", -1)
	}

	// Write to file
	err := os.WriteFile(filePath, []byte(outputData), 0644)
	if err != nil {
		log.Fatalf("Failed to write to file: %v", err)
	}
	fmt.Printf("Secrets written to %s\n", filePath)
}

func toINI(data map[string]interface{}) string {
	var sb strings.Builder
	for k, v := range data {
		sb.WriteString(fmt.Sprintf("%s=%v\n", k, v))
	}
	return sb.String()
}

func toENV(data map[string]interface{}) string {
	var sb strings.Builder
	for k, v := range data {
		sb.WriteString(fmt.Sprintf("%s=%v\n", strings.ToUpper(k), v))
	}
	return sb.String()
}

func toJSON(data map[string]interface{}) string {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal data to JSON: %v", err)
	}
	return string(jsonBytes)
}

func toYAML(data map[string]interface{}) string {
	yamlBytes, err := yaml.Marshal(data)
	if err != nil {
		log.Fatalf("Failed to marshal data to YAML: %v", err)
	}
	return string(yamlBytes)
}
