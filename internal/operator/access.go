package operator

import (
	"encoding/json"
	"fmt"
	"strings"
)

const MaxSecretPrefixes = 100

type SecretAccess struct {
	Unrestricted bool
	Prefixes     []string
	Encoded      string
}

func NormalizeSecretPrefixes(prefixes []string, validPath func(string) bool) ([]string, error) {
	if len(prefixes) == 0 || len(prefixes) > MaxSecretPrefixes {
		return nil, fmt.Errorf("provide between 1 and %d secret path prefixes", MaxSecretPrefixes)
	}
	normalized := make([]string, 0, len(prefixes))
	seen := make(map[string]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if !validPath(prefix) {
			return nil, fmt.Errorf("secret path prefixes must use valid secret paths")
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("provide at least one secret path prefix")
	}
	return normalized, nil
}

func EncodeSecretPrefixes(prefixes []string) (string, error) {
	encoded, err := json.Marshal(prefixes)
	if err != nil {
		return "", fmt.Errorf("encode secret path prefixes: %w", err)
	}
	return string(encoded), nil
}

func DecodeSecretPrefixes(encoded string, validPath func(string) bool) ([]string, error) {
	var prefixes []string
	if err := json.Unmarshal([]byte(encoded), &prefixes); err != nil {
		return nil, fmt.Errorf("decode secret path prefixes: %w", err)
	}
	if prefixes == nil {
		return nil, fmt.Errorf("secret path prefixes must be an array")
	}
	if len(prefixes) > MaxSecretPrefixes {
		return nil, fmt.Errorf("too many secret path prefixes")
	}
	normalized := make([]string, 0, len(prefixes))
	seen := make(map[string]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if !validPath(prefix) {
			return nil, fmt.Errorf("invalid stored secret path prefix")
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
	}
	return normalized, nil
}

func (access SecretAccess) Allows(path string) bool {
	if access.Unrestricted {
		return true
	}
	for _, prefix := range access.Prefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func (access SecretAccess) Intersects(path string) bool {
	if access.Unrestricted {
		return true
	}
	for _, prefix := range access.Prefixes {
		if path == prefix ||
			strings.HasPrefix(path, prefix+"/") ||
			strings.HasPrefix(prefix, path+"/") {
			return true
		}
	}
	return false
}

func (access SecretAccess) Contains(candidate string) bool {
	if access.Unrestricted {
		return true
	}
	for _, prefix := range access.Prefixes {
		if candidate == prefix || strings.HasPrefix(candidate, prefix+"/") {
			return true
		}
	}
	return false
}

func (access SecretAccess) Intersect(other SecretAccess) SecretAccess {
	if access.Unrestricted {
		return other
	}
	if other.Unrestricted {
		return access
	}
	intersection := SecretAccess{Prefixes: make([]string, 0)}
	seen := make(map[string]struct{})
	for _, left := range access.Prefixes {
		for _, right := range other.Prefixes {
			switch {
			case left == right || strings.HasPrefix(left, right+"/"):
				if _, exists := seen[left]; !exists {
					intersection.Prefixes = append(intersection.Prefixes, left)
					seen[left] = struct{}{}
				}
			case strings.HasPrefix(right, left+"/"):
				if _, exists := seen[right]; !exists {
					intersection.Prefixes = append(intersection.Prefixes, right)
					seen[right] = struct{}{}
				}
			}
		}
	}
	encoded, _ := json.Marshal(intersection.Prefixes)
	intersection.Encoded = string(encoded)
	return intersection
}
