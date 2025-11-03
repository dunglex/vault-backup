package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	vault "github.com/hashicorp/vault/api"
	yaml "gopkg.in/yaml.v3"
)

func sortMapKeys(data map[string]any) []string {
	// Extract keys from the map
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}

	// Sort the keys alphabetically
	sort.Strings(keys)

	return keys
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
			sortedKeys := sortMapKeys(d)
			sortedData := make(map[string]any)
			for _, key := range sortedKeys {
				sortedData[key] = d[key]
			}
			outputData = getFormatted(sortedData)
		} else {
			panic("Expected 'data' key in secret map")
		}
		fmt.Println(outputData)
		return
	case "file":
		if d, ok := data["data"].(map[string]any); ok {
			sortedKeys := sortMapKeys(d)
			sortedData := make(map[string]any)
			for _, key := range sortedKeys {
				sortedData[key] = d[key]
			}
			outputData = getFormatted(sortedData)
		} else {
			panic("Expected 'data' key in secret map")
		}
		filePath := outputPath + "/" + fileName
		if err := os.MkdirAll(outputPath, 0755); err != nil {
			panic(fmt.Sprintf("Failed to create output directory: %v", err))
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
			panic(fmt.Sprintf("Failed to write to file: %v", err))
		}
		fmt.Printf("Secrets written to %s\n", filePath)
		return
	default:
		panic(fmt.Sprintf("Unknown output mode: %s", outputMode))
	}
}

func toINI(data map[string]any) string {
	var sb strings.Builder
	// Extract and sort keys alphabetically
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	// Write each key and its value in sorted order
	for _, k := range keys {
		value := fmt.Sprintf("%v", data[k])
		// Quote the value if it contains spaces
		if strings.Contains(value, " ") {
			value = fmt.Sprintf("\"%s\"", value)
		}
		sb.WriteString(fmt.Sprintf("%s=%s\r\n", k, value))
	}
	return sb.String()
}

func toENV(data map[string]any) string {
	var sb strings.Builder
	// Extract and sort keys alphabetically
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	// Write each key and its value in sorted order
	for _, k := range keys {
		value := fmt.Sprintf("%v", data[k])
		// Quote the value if it contains spaces
		if strings.Contains(value, " ") {
			value = fmt.Sprintf("\"%s\"", value)
		}
		sb.WriteString(fmt.Sprintf("%s=%s\r\n", strings.ToUpper(k), value))
	}
	return sb.String()
}

func toJSON(data map[string]any) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("{\r\n")
	for i, k := range keys {
		valBytes, err := json.MarshalIndent(data[k], "  ", "  ")
		if err != nil {
			panic(fmt.Sprintf("Failed to marshal key %q: %v", k, err))
		}
		sb.WriteString(fmt.Sprintf("  %q: %s", k, valBytes))
		if i < len(keys)-1 {
			sb.WriteString(",\r\n")
		} else {
			sb.WriteString("\r\n")
		}
	}
	sb.WriteString("}")
	return sb.String()
}

func toYAML(data map[string]any) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("{\r\n")
	for i, k := range keys {
		valBytes, err := yaml.Marshal(data[k])
		if err != nil {
			panic(fmt.Sprintf("Failed to marshal key %q: %v", k, err))
		}
		sb.WriteString(fmt.Sprintf("  %q: %s", k, valBytes))
		if i < len(keys)-1 {
			sb.WriteString(",\r\n")
		} else {
			sb.WriteString("\r\n")
		}
	}
	sb.WriteString("}")
	return sb.String()
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
			fmt.Printf("Failed to list secrets in folder %s: %v (maybe no item)\n", arguments.SecretPath, err)
			return
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
			if keyStr == "" || strings.Contains(keyStr, "example-secret") {
				fmt.Println("Skip secret " + arguments.SecretPath)
				continue
			}
			fullPath := arguments.SecretName + "/data/" + arguments.SecretPath + keyStr
			secretData, err := client.Logical().Read(fullPath)
			if err != nil || secretData == nil || secretData.Data == nil {
				fmt.Printf("Failed to read secret %s: %v (maybe a folder)\n", arguments.SecretPath+keyStr, err)
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
		if arguments.SecretPath == "" || strings.Contains(arguments.SecretPath, "example-secret") {
			fmt.Println("Skip secret " + arguments.SecretPath)
			return
		}
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
	// Skip example-secret
	if strings.Contains(filePath, "example-secret") {
		fmt.Printf("Skipping example-secret file: %s\n", filePath)
		return nil
	}
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
	inputInfo, _ := os.Stat(arguments.InputPath)

	if arguments.SecretPath != "" {
		// Use provided secret path
		if inputInfo != nil && inputInfo.IsDir() {
			// If restoring from directory, derive relative path and append to secret path
			relPath, err := filepath.Rel(arguments.InputPath, filePath)
			if err != nil {
				relPath = filepath.Base(filePath)
			}
			// Remove file extension and append to provided secret path
			fileName := strings.TrimSuffix(relPath, filepath.Ext(relPath))
			fileName = strings.ReplaceAll(fileName, "\\", "/") // Convert Windows paths to Unix-style
			secretPath = strings.TrimSuffix(arguments.SecretPath, "/") + "/" + fileName
		} else {
			// Single file restore, use provided path as-is
			secretPath = arguments.SecretPath
		}
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
