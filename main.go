package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	vault "github.com/hashicorp/vault/api"
	yaml "gopkg.in/yaml.v3"
)

func main() {
	// Get arguments from command line or environment variables
	arguments := parseArguments()

	// Connect to Vault
	client := connectToVault(arguments)

	if arguments.RestoreMode {
		// Restore secrets from backup files to Vault
		restoreSecrets(client, arguments)
	} else {
		// Backup secrets from Vault
		backupSecrets(client, arguments)
	}
}

func connectToVault(arguments Arguments) *vault.Client {
	// Connect to Vault
	config := vault.DefaultConfig()
	config.Address = arguments.Url

	// Skip TLS verification if insecure flag is set
	if arguments.Insecure {
		config.ConfigureTLS(&vault.TLSConfig{
			Insecure: true,
		})
	}

	client, err := vault.NewClient(config)
	if err != nil {
		panic(fmt.Sprintf("Failed to create Vault client: %v", err))
	}

	// Authenticate with LDAP username/password
	data := map[string]any{
		"password": arguments.Pass,
	}
	loginPath := fmt.Sprintf("auth/ldap/login/%s", arguments.User)
	secret, err := client.Logical().Write(loginPath, data)
	if err != nil || secret == nil || secret.Auth == nil {
		panic(fmt.Sprintf("Failed to authenticate with LDAP: %v", err))
	}
	client.SetToken(secret.Auth.ClientToken)
	return client

}

func backupSecrets(client *vault.Client, arguments Arguments) {

	// Read secrets or list folder
	if strings.HasSuffix(arguments.SecretPath, "/") {
		// List keys in the folder
		metadataPath := arguments.SecretName + "/metadata/" + arguments.SecretPath
		list, err := client.Logical().List(metadataPath)
		if err != nil || list == nil || list.Data == nil {
			panic(fmt.Sprintf("Failed to list secrets in folder %s: %v", arguments.SecretPath, err))
		}
		keys, ok := list.Data["keys"].([]any)
		if !ok {
			panic(fmt.Sprintf("Unexpected data format when listing folder %s", arguments.SecretPath))
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
				fmt.Printf("Failed to read secret %s: %v (maybe a folder)", arguments.SecretPath+keyStr, err)
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
			fmt.Printf("Failed to read secret %s: %v (invalid path or maybe a folder)", arguments.SecretPath, err)
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
			outputPath = strings.TrimSuffix(outputPath, "/")
			if fileName == "" {
				fileName = strings.TrimSuffix(arguments.SecretPath, "/")
			}
			fileName = strings.TrimPrefix(fileName, "/")
		}
		writeOutput(secrets, arguments.OutputMode, arguments.OutputFormat, outputPath, fileName)
	}
}

func restoreSecrets(client *vault.Client, arguments Arguments) {
	// Check if input path exists
	info, err := os.Stat(arguments.InputPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to access input path %s: %v", arguments.InputPath, err))
	}

	if info.IsDir() {
		// Restore from directory - walk through all files
		err := filepath.WalkDir(arguments.InputPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if !d.IsDir() {
				err := restoreFromFile(client, arguments, path)
				if err != nil {
					fmt.Printf("Failed to restore from %s: %v\n", path, err)
				}
			}
			return nil
		})
		if err != nil {
			panic(fmt.Sprintf("Failed to walk directory %s: %v", arguments.InputPath, err))
		}
	} else {
		// Restore from single file
		err := restoreFromFile(client, arguments, arguments.InputPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to restore from file %s: %v", arguments.InputPath, err))
		}
	}
}

func restoreFromFile(client *vault.Client, arguments Arguments, filePath string) error {
	// Read file content
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Determine file format from extension
	ext := filepath.Ext(filePath)
	var secretData map[string]interface{}

	switch strings.ToLower(ext) {
	case ".json":
		err = json.Unmarshal(fileContent, &secretData)
		if err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	case ".yaml", ".yml":
		err = yaml.Unmarshal(fileContent, &secretData)
		if err != nil {
			return fmt.Errorf("failed to parse YAML: %w", err)
		}
	case ".ini", ".env":
		secretData, err = parseKeyValueFile(string(fileContent))
		if err != nil {
			return fmt.Errorf("failed to parse key-value file: %w", err)
		}
	default:
		// Try JSON first, then YAML
		err = json.Unmarshal(fileContent, &secretData)
		if err != nil {
			err = yaml.Unmarshal(fileContent, &secretData)
			if err != nil {
				return fmt.Errorf("failed to parse file as JSON or YAML: %w", err)
			}
		}
	}

	// Determine the secret path
	var secretPath string
	if arguments.SecretPath != "" {
		// Use provided secret path
		secretPath = arguments.SecretPath
	} else {
		// Derive secret path from file path relative to input path
		relPath, err := filepath.Rel(arguments.InputPath, filePath)
		if err != nil {
			relPath = filepath.Base(filePath)
		}
		// Remove file extension and use as secret path
		secretPath = strings.TrimSuffix(relPath, filepath.Ext(relPath))
		secretPath = strings.ReplaceAll(secretPath, "\\", "/") // Convert Windows paths to Unix-style
	}

	// Write secret to Vault
	fullPath := arguments.SecretName + "/data/" + secretPath
	vaultData := map[string]interface{}{
		"data": secretData,
	}

	_, err = client.Logical().Write(fullPath, vaultData)
	if err != nil {
		return fmt.Errorf("failed to write secret to Vault at %s: %w", fullPath, err)
	}

	fmt.Printf("Successfully restored secret to %s from %s\n", fullPath, filePath)
	return nil
}

func parseKeyValueFile(content string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}

		result[key] = value
	}

	return result, nil
}
