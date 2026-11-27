package operator

import (
	"encoding/json"
	"fmt"
	"strings"
)

const MaxSecretMounts = 100

type MountAccess struct {
	Unrestricted bool
	Mounts       []string
	Encoded      string
}

func NormalizeSecretMounts(mounts []string, validMount func(string) bool) ([]string, error) {
	if len(mounts) == 0 || len(mounts) > MaxSecretMounts {
		return nil, fmt.Errorf("provide between 1 and %d secret mounts", MaxSecretMounts)
	}
	normalized := make([]string, 0, len(mounts))
	seen := make(map[string]struct{}, len(mounts))
	for _, mount := range mounts {
		mount = strings.TrimSpace(mount)
		if !validMount(mount) {
			return nil, fmt.Errorf("secret mounts must use valid mount names")
		}
		if _, exists := seen[mount]; exists {
			continue
		}
		seen[mount] = struct{}{}
		normalized = append(normalized, mount)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("provide at least one secret mount")
	}
	return normalized, nil
}

func EncodeSecretMounts(mounts []string) (string, error) {
	encoded, err := json.Marshal(mounts)
	if err != nil {
		return "", fmt.Errorf("encode secret mounts: %w", err)
	}
	return string(encoded), nil
}

func DecodeSecretMounts(encoded string, validMount func(string) bool) ([]string, error) {
	var mounts []string
	if err := json.Unmarshal([]byte(encoded), &mounts); err != nil {
		return nil, fmt.Errorf("decode secret mounts: %w", err)
	}
	if mounts == nil {
		return nil, fmt.Errorf("secret mounts must be an array")
	}
	if len(mounts) > MaxSecretMounts {
		return nil, fmt.Errorf("too many secret mounts")
	}
	normalized := make([]string, 0, len(mounts))
	seen := make(map[string]struct{}, len(mounts))
	for _, mount := range mounts {
		if !validMount(mount) {
			return nil, fmt.Errorf("invalid stored secret mount")
		}
		if _, exists := seen[mount]; exists {
			continue
		}
		seen[mount] = struct{}{}
		normalized = append(normalized, mount)
	}
	return normalized, nil
}

func (access MountAccess) Allows(mount string) bool {
	if access.Unrestricted {
		return true
	}
	for _, allowed := range access.Mounts {
		if mount == allowed {
			return true
		}
	}
	return false
}

func (access MountAccess) Intersect(other MountAccess) MountAccess {
	if access.Unrestricted {
		return other
	}
	if other.Unrestricted {
		return access
	}
	allowed := make(map[string]struct{}, len(other.Mounts))
	for _, mount := range other.Mounts {
		allowed[mount] = struct{}{}
	}
	intersection := MountAccess{Mounts: make([]string, 0)}
	for _, mount := range access.Mounts {
		if _, ok := allowed[mount]; ok {
			intersection.Mounts = append(intersection.Mounts, mount)
		}
	}
	intersection.Encoded, _ = EncodeSecretMounts(intersection.Mounts)
	return intersection
}
