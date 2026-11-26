# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git build-base bash

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN bash scripts/build.sh


# Final stage: runtime binaries

FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl && addgroup -S -g 1000 vault && adduser -S -u 1000 -G vault vault

# Copy the built binaries from the builder stage to the final image
RUN mkdir -p /app/bin && chown -R vault:vault /app/bin
COPY --from=builder --chown=vault:vault /app/bin/vault-backup /usr/local/bin/vault-backup
COPY --from=builder --chown=vault:vault /app/bin/vault-server /usr/local/bin/vault-server
COPY --from=builder --chown=vault:vault /app/bin/mkcert /usr/local/bin/mkcert

# Create a directory for Vault server data and set ownership
RUN mkdir -p /data /backups && chown -R vault:vault /data /backups
VOLUME ["/data", "/backups"]

# Set default environment variables for Vault server
ENV VAULT_SERVER_DB=/data/vault.db
ENV VAULT_SERVER_SECRETS_DB=/data/vault-secrets.db
ENV VAULT_SERVER_DATA_DIR=/data
ENV VAULT_SERVER_BACKUP_DIR=/backups
ENV VAULT_SERVER_HEALTHCHECK_URL=https://127.0.0.1:8200/health

USER vault

WORKDIR /app

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD curl --fail --silent --show-error --insecure "$VAULT_SERVER_HEALTHCHECK_URL" >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/vault-server"]
