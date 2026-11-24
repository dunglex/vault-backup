package main

import (
	"strings"
	"testing"
)

func validArguments() Arguments {
	return Arguments{
		Url:          "https://vault.example/api",
		Token:        "managed-token",
		SecretName:   "kv",
		SecretPath:   "app/database",
		OutputMode:   "file",
		OutputFormat: "env",
		OutputPath:   "backup.env",
	}
}

func TestValidateArgumentsAcceptsValidTokenBackup(t *testing.T) {
	if err := validateArguments(validArguments()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateArgumentsRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Arguments)
		want   string
	}{
		{"missing URL", func(a *Arguments) { a.Url = "" }, "url is required"},
		{"relative URL", func(a *Arguments) { a.Url = "vault.example/api" }, "absolute http or https URL"},
		{"unsupported URL scheme", func(a *Arguments) { a.Url = "ftp://vault.example" }, "absolute http or https URL"},
		{"missing authentication", func(a *Arguments) { a.Token = "" }, "either token or user/pass is required"},
		{"partial user authentication", func(a *Arguments) { a.Token = ""; a.User = "admin" }, "user and pass must be provided together"},
		{"mixed authentication", func(a *Arguments) { a.User = "admin"; a.Pass = "password" }, "token cannot be combined"},
		{"missing certificate", func(a *Arguments) { a.ClientCert = "client.pem" }, "client_cert and client_key"},
		{"insecure custom CA", func(a *Arguments) { a.Insecure = true; a.CACert = "ca.pem" }, "insecure cannot be combined"},
		{"missing mount", func(a *Arguments) { a.SecretName = "" }, "secret_name is required"},
		{"missing secret path", func(a *Arguments) { a.SecretPath = "" }, "secret_path is required"},
		{"invalid output mode", func(a *Arguments) { a.OutputMode = "tar" }, "output_mode must be one of"},
		{"invalid output format", func(a *Arguments) { a.OutputFormat = "toml" }, "output_format must be one of"},
		{"missing output path", func(a *Arguments) { a.OutputPath = "" }, "output_path is required"},
		{"missing restore input", func(a *Arguments) {
			a.RestoreMode = true
			a.InputPath = ""
		}, "input_path is required"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := validArguments()
			test.change(&arguments)
			err := validateArguments(arguments)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateArguments() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateArgumentsAcceptsUserPassword(t *testing.T) {
	arguments := validArguments()
	arguments.Token = ""
	arguments.User = "admin"
	arguments.Pass = "password"
	if err := validateArguments(arguments); err != nil {
		t.Fatal(err)
	}
}
