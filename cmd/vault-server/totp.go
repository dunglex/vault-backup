package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	totpPeriod            = 30 * time.Second
	totpDigits            = 6
	totpRecoveryCodeCount = 10
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func generateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return totpBase32.EncodeToString(secret), nil
}

func verifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	key, err := totpBase32.DecodeString(strings.ToUpper(secret))
	if err != nil || len(key) == 0 {
		return false
	}
	currentStep := now.Unix() / int64(totpPeriod/time.Second)
	for offset := int64(-1); offset <= 1; offset++ {
		step := currentStep + offset
		if step < 0 {
			continue
		}
		expected := totpCodeAt(key, uint64(step))
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

func totpCodeAt(key []byte, counter uint64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1_000_000)
	return fmt.Sprintf("%06d", value%modulus)
}

func generateRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, 0, totpRecoveryCodeCount)
	hashes := make([]string, 0, totpRecoveryCodeCount)
	for range totpRecoveryCodeCount {
		random := make([]byte, 10)
		if _, err := rand.Read(random); err != nil {
			return nil, nil, fmt.Errorf("generate TOTP recovery code: %w", err)
		}
		encoded := totpBase32.EncodeToString(random)
		code := strings.Join([]string{encoded[:4], encoded[4:8], encoded[8:12], encoded[12:]}, "-")
		codes = append(codes, code)
		hashes = append(hashes, hashRecoveryCode(code))
	}
	return codes, hashes, nil
}

func hashRecoveryCode(code string) string {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.Join(strings.Fields(normalized), "")
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
