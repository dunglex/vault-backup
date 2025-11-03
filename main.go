package main

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
