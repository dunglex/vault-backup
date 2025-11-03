package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

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
