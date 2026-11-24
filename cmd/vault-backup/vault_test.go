package main

import (
	"net/http"
	"strings"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

func TestFormatVaultErrorForLockedSetup(t *testing.T) {
	err := &vault.ResponseError{
		StatusCode: http.StatusLocked,
		Errors:     []string{"setup window expired"},
	}

	got := formatVaultError(err)
	if got != "Vault setup is locked (423): setup window expired" {
		t.Fatalf("formatVaultError() = %q", got)
	}
}

func TestFormatVaultErrorPreservesOtherErrors(t *testing.T) {
	err := &vault.ResponseError{
		StatusCode: http.StatusForbidden,
		Errors:     []string{"permission denied"},
	}

	got := formatVaultError(err)
	if !strings.Contains(got, "permission denied") {
		t.Fatalf("formatVaultError() = %q", got)
	}
}
