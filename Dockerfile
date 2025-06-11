# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git for go modules if needed
RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the binary for Linux
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o vault-backup .

# Final stage: just the binary
FROM alpine:3.19

WORKDIR /app

COPY --from=builder /app/vault-backup /usr/local/bin/vault-backup

ENTRYPOINT ["vault-backup"]