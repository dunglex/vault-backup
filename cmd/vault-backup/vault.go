package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
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
func writeOutput(data map[string]any, outputMode, outputFormat, outputPath, fileName string) error {
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
		return nil
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
		return nil
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
		if err := os.MkdirAll(outputPath, 0700); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
		if !strings.HasSuffix(fileName, ".ini") &&
			!strings.HasSuffix(fileName, ".env") &&
			!strings.HasSuffix(fileName, ".json") &&
			!strings.HasSuffix(fileName, ".yml") &&
			!strings.HasSuffix(fileName, ".yaml") {
			filePath = filePath + "." + strings.Replace(outputFormat, ".", "", -1)
		}
		if err := writeSecretFile(filePath, []byte(outputData)); err != nil {
			return err
		}
		fmt.Printf("Secrets written to %s\n", filePath)
		return nil
	default:
		return fmt.Errorf("unknown output mode %q", outputMode)
	}
}

func writeSecretFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Truncate(0); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
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

	tlsConfig := &vault.TLSConfig{
		CACert:        arguments.CACert,
		ClientCert:    arguments.ClientCert,
		ClientKey:     arguments.ClientKey,
		TLSServerName: arguments.TLSServerName,
		Insecure:      arguments.Insecure,
	}
	if arguments.Insecure && (arguments.CACert != "" || arguments.ClientCert != "" || arguments.ClientKey != "") {
		panic("VAULT_INSECURE cannot be combined with mTLS or custom CA configuration")
	}
	if arguments.ClientCert != "" || arguments.ClientKey != "" {
		if arguments.ClientCert == "" || arguments.ClientKey == "" {
			panic("Both VAULT_CLIENT_CERT and VAULT_CLIENT_KEY are required for mutual TLS")
		}
	}
	if tlsConfig.CACert != "" || tlsConfig.ClientCert != "" || tlsConfig.ClientKey != "" || tlsConfig.TLSServerName != "" || arguments.Insecure {
		if err := config.ConfigureTLS(tlsConfig); err != nil {
			panic(fmt.Sprintf("Failed to configure Vault TLS: %v", err))
		}
	}

	client, err := vault.NewClient(config)
	if err != nil {
		panic(fmt.Sprintf("Failed to create Vault client: %v", err))
	}
	client.SetHeaders(http.Header{"X-Vault-Backup-Protocol": []string{"client-cert-v1"}})
	if arguments.Token != "" {
		client.SetToken(arguments.Token)
		return client
	}

	// Authenticate with LDAP username/password
	data := map[string]any{
		"password": arguments.Pass,
	}
	loginPath := fmt.Sprintf("auth/ldap/login/%s", arguments.User)
	secret, err := client.Logical().Write(loginPath, data)
	if err != nil || secret == nil || secret.Auth == nil {
		panic(fmt.Sprintf("Failed to authenticate with LDAP: %s", formatVaultError(err)))
	}
	client.SetToken(secret.Auth.ClientToken)
	return client
}

func backupSecrets(client *vault.Client, arguments Arguments) error {
	if strings.HasSuffix(arguments.SecretPath, "/") {
		return backupSecretFolder(client, arguments)
	}
	return backupSingleSecret(client, arguments)
}

func backupSecretFolder(client *vault.Client, arguments Arguments) error {
	metadataPath := arguments.SecretName + "/metadata/" + arguments.SecretPath
	list, err := client.Logical().List(metadataPath)
	if err != nil {
		return fmt.Errorf("list folder %s: %s", arguments.SecretPath, formatVaultAPIError(err))
	}
	if list == nil || list.Data == nil {
		return fmt.Errorf("list folder %s: empty response", arguments.SecretPath)
	}
	keys, ok := list.Data["keys"].([]any)
	if !ok {
		return fmt.Errorf("list folder %s: unexpected keys format %T", arguments.SecretPath, list.Data["keys"])
	}

	var failures []error
	for _, key := range keys {
		keyStr, ok := key.(string)
		if !ok {
			failures = append(failures, fmt.Errorf("list folder %s: unexpected key type %T", arguments.SecretPath, key))
			continue
		}
		keyStr = strings.TrimPrefix(keyStr, "/")
		if keyStr == "" || strings.Contains(keyStr, "example-secret") {
			fmt.Println("Skip secret " + arguments.SecretPath + keyStr)
			continue
		}

		childArguments := arguments
		childArguments.SecretPath = arguments.SecretPath + keyStr
		if strings.HasSuffix(keyStr, "/") {
			if err := backupSecretFolder(client, childArguments); err != nil {
				failures = append(failures, err)
			}
			continue
		}
		childArguments.OutputPath = arguments.OutputPath
		if !strings.HasSuffix(childArguments.OutputPath, "/") {
			childArguments.OutputPath += "/"
		}
		childArguments.OutputPath += strings.TrimSuffix(arguments.SecretPath, "/") + "/"
		if err := backupSingleSecret(client, childArguments); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func backupSingleSecret(client *vault.Client, arguments Arguments) error {
	if arguments.SecretPath == "" || strings.Contains(arguments.SecretPath, "example-secret") {
		fmt.Println("Skip secret " + arguments.SecretPath)
		return nil
	}

	fullPath := arguments.SecretName + "/data/" + arguments.SecretPath
	secretData, err := client.Logical().Read(fullPath)
	if err != nil {
		return fmt.Errorf("read secret %s: %s", arguments.SecretPath, formatVaultAPIError(err))
	}
	if secretData == nil || secretData.Data == nil {
		return fmt.Errorf("read secret %s: empty response", arguments.SecretPath)
	}
	data, ok := secretData.Data["data"]
	if !ok {
		return fmt.Errorf("read secret %s: response missing data", arguments.SecretPath)
	}
	secrets := map[string]any{
		"key":  fullPath,
		"data": data,
	}

	var outputPath, fileName string
	if strings.HasSuffix(arguments.OutputPath, "/") {
		outputPath = strings.TrimSuffix(arguments.OutputPath, "/")
		pathParts := strings.Split(arguments.SecretPath, "/")
		fileName = pathParts[len(pathParts)-1]
	} else {
		outputPath, fileName = filepath.Split(arguments.OutputPath)
		if outputPath == "" {
			outputPath = "."
		}
		outputPath = strings.TrimSuffix(outputPath, "/")
		if fileName == "" {
			fileName = filepath.Base(arguments.SecretPath)
		}
		fileName = strings.TrimPrefix(fileName, "/")
	}
	if err := writeOutput(secrets, arguments.OutputMode, arguments.OutputFormat, outputPath, fileName); err != nil {
		return fmt.Errorf("write backup for %s: %w", arguments.SecretPath, err)
	}
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

func restoreSecrets(client *vault.Client, arguments Arguments) error {
	// Check if input path exists
	info, err := os.Stat(arguments.InputPath)
	if err != nil {
		return fmt.Errorf("access input path %s: %w", arguments.InputPath, err)
	}

	if info.IsDir() {
		var failures []error
		// Restore from directory - walk through all files
		err := filepath.WalkDir(arguments.InputPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", path, err))
				return nil
			}

			if !d.IsDir() {
				if err := restoreFromFile(client, arguments, path); err != nil {
					failures = append(failures, fmt.Errorf("%s: %w", path, err))
				}
			}
			return nil
		})
		if err != nil {
			failures = append(failures, fmt.Errorf("walk directory %s: %w", arguments.InputPath, err))
		}
		return errors.Join(failures...)
	}

	// Restore from single file
	if err := restoreFromFile(client, arguments, arguments.InputPath); err != nil {
		return fmt.Errorf("restore from file %s: %w", arguments.InputPath, err)
	}
	return nil
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
		return fmt.Errorf("failed to write secret to Vault at %s: %s", fullPath, formatVaultAPIError(err))
	}

	fmt.Printf("Successfully restored secret to %s from %s\n", fullPath, filePath)
	return nil
}

func formatVaultError(err error) string {
	if err == nil {
		return "unknown error"
	}
	if isClientCertificateHandshakeError(err) {
		return "Vault rejected the client certificate during the TLS handshake. Check that the certificate is valid, matches the private key, and is trusted by the Vault server's client CA."
	}
	var responseErr *vault.ResponseError
	if errors.As(err, &responseErr) {
		details := strings.TrimSpace(strings.Join(responseErr.Errors, "; "))
		switch responseErr.StatusCode {
		case http.StatusLocked:
			if details == "" {
				details = "initial setup window expired"
			}
			return "Vault setup is locked (423): " + details
		case http.StatusUnauthorized:
			return formatVaultResponseMessage("Vault rejected the supplied credentials (401 Unauthorized).", details)
		case http.StatusForbidden:
			return formatVaultResponseMessage("Vault denied the request (403 Forbidden).", details)
		case http.StatusUpgradeRequired:
			return formatVaultResponseMessage("Vault requires a newer client (426 Upgrade Required).", details)
		}
		status := vaultHTTPStatus(responseErr.StatusCode)
		if details == "" {
			return status + " with no error details."
		}
		return status + ": " + details
	}
	return err.Error()
}

func isClientCertificateHandshakeError(err error) bool {
	var networkErr *net.OpError
	if !errors.As(err, &networkErr) || networkErr.Op != "remote error" {
		return false
	}
	switch networkErr.Err.Error() {
	case "tls: bad certificate",
		"tls: unsupported certificate",
		"tls: revoked certificate",
		"tls: expired certificate",
		"tls: unknown certificate",
		"tls: unknown certificate authority",
		"tls: certificate required":
		return true
	default:
		return false
	}
}

func formatVaultAPIError(err error) string {
	var responseErr *vault.ResponseError
	if !errors.As(err, &responseErr) {
		return formatVaultError(err)
	}
	details := strings.TrimSpace(strings.Join(responseErr.Errors, "; "))
	switch responseErr.StatusCode {
	case http.StatusUnauthorized:
		message := "Vault rejected the API token or client certificate (401 Unauthorized). Use a current managed API token (it may be invalid, expired, or revoked); if mTLS is enforced, check that the client certificate matches the token and is current."
		return formatVaultResponseMessage(message, details)
	case http.StatusForbidden:
		message := "Vault denied this request (403 Forbidden). The authenticated token does not have permission to access this resource."
		return formatVaultResponseMessage(message, details)
	case http.StatusUpgradeRequired:
		message := "Vault requires a newer vault-backup client (426 Upgrade Required). Upgrade to a version that supports the server's required API protocol."
		return formatVaultResponseMessage(message, details)
	default:
		return formatVaultError(err)
	}
}

func formatVaultResponseMessage(message, details string) string {
	if details == "" {
		return message
	}
	return message + " Server detail: " + details
}

func vaultHTTPStatus(statusCode int) string {
	status := fmt.Sprintf("Vault returned HTTP %d", statusCode)
	if statusText := http.StatusText(statusCode); statusText != "" {
		status += " " + statusText
	}
	return status
}
