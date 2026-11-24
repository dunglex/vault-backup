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

RUN apk add --no-cache ca-certificates && addgroup -S vault && adduser -S -G vault vault

COPY --from=builder --chown=vault:vault /app/bin/vault-backup /usr/local/bin/vault-backup
COPY --from=builder --chown=vault:vault /app/bin/vault-server /usr/local/bin/vault-server
COPY --from=builder --chown=vault:vault /app/bin/mkcert /usr/local/bin/mkcert

RUN mkdir -p /data && chown -R vault:vault /data

VOLUME /data
ENV VAULT_SERVER_DB=/data/vault.db

USER vault
WORKDIR /app
ENTRYPOINT ["/usr/local/bin/vault-server"]