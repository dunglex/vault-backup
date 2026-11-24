package main

import (
	"fmt"
	"os"
)

func main() {
	// Get arguments from command line or environment variables
	arguments := parseArguments()

	// Connect to Vault
	client := connectToVault(arguments)

	var err error
	if arguments.RestoreMode {
		// Restore secrets from backup files to Vault
		err = restoreSecrets(client, arguments)
	} else {
		// Backup secrets from Vault
		err = backupSecrets(client, arguments)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault-backup failed: %v\n", err)
		os.Exit(1)
	}
}
