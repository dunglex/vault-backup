#!/bin/bash

# Read user credentials and backup folder from .env file
source .env2
export TOKEN
export BACKUP_FOLDER

# Clean up environment variables (remove carriage returns and whitespace)
echo "Sanitizing environment variables..."
VAULT_TOKEN=$(echo -n "${TOKEN}" | tr -d '\r' | xargs)
BACKUP_FOLDER=$(echo -n "${BACKUP_FOLDER}" | tr -d '\r' | xargs)
# echo "Environment variables sanitized."
# echo "VAULT_TOKEN: ${VAULT_TOKEN}"
# echo "BACKUP_FOLDER: ${BACKUP_FOLDER}"

# Restore nonprod vaults
cd "${BACKUP_FOLDER}/nonprod/"
echo "Restore nonprod vaults..."
vault-backup --url=https://vault-erec.apps-country-k8s-pdc-nonprod-green.hcnet.vn/api -n=apps -s=cma/ --restore --input_path=./cma/ -k --token "${VAULT_TOKEN}"
vault-backup --url=https://vault-erec.apps-country-k8s-pdc-nonprod-green.hcnet.vn/api -n=apps -s=erec/ --restore --input_path=./erec/ -k --token "${VAULT_TOKEN}"
vault-backup --url=https://vault-erec.apps-country-k8s-pdc-nonprod-green.hcnet.vn/api -n=apps -s=aspire/ --restore --input_path=./aspire/ -k --token "${VAULT_TOKEN}"
