# Build stage
ARG APP=vault-backup

FROM golang:1.26-alpine AS builder
ARG APP

WORKDIR /app
RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN mkdir -p /out && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "/out/${APP}" "./cmd/${APP}"

# Final stage: just the binary
FROM alpine:3.19
ARG APP

RUN apk add --no-cache ca-certificates && addgroup -S vault && adduser -S -G vault vault

COPY --from=builder --chown=vault:vault "/out/${APP}" "/usr/local/bin/${APP}"
RUN ln -s "/usr/local/bin/${APP}" /usr/local/bin/app \
    && mkdir -p /data \
    && chown -R vault:vault /data

VOLUME /data
ENV VAULT_SERVER_DB=/data/vault.db

USER vault
WORKDIR /app
ENTRYPOINT ["/usr/local/bin/app"]