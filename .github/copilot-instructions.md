# UI & Dashboard Rules
- Output a single self-contained `index.html` file with embedded `<style>` and `<script>`.
- Do NOT use React, Vue, npm, or external build steps.
- Use semantic HTML5 (`<aside>`, `<main>`, `<header>`, `<section>`, `<table>`) and CSS custom properties (`:root`) for colors and spacing.
- Keep JavaScript minimal and vanilla (`document.getElementById`, `addEventListener`).
- When modifying existing code, return the complete updated block without placeholders like `// ... existing code ...`.

# Backend Rules
- The backend consists of two Go applications: `cmd/vault-server` and `cmd/vault-backup`. Follow each command's README and existing package patterns; keep changes scoped to the requested behavior.
- Preserve type safety and return/report errors explicitly. Backup and restore operations can partially succeed: aggregate item failures and make the command exit non-zero rather than reporting overall success.
- The server's main database is SQLCipher-encrypted. Keep its key file protected (`0600`); the separate audit database is plaintext SQLite and must contain metadata only, never secret values or raw tokens. Do not silently enable or migrate plaintext main databases.
- `/api/...` endpoints accept only admin-created managed API tokens (`X-Vault-Token` or Bearer). Web session cookies and username/password login tokens are not API credentials.
- Validate secret paths consistently in web and API handlers: slash-separated segments, each 1–127 ASCII letters, digits, or hyphens. Invalid API paths must return HTTP 400 with a useful message.
- Keep secrets out of logs, audit records, error messages, and test output. Record audit metadata for relevant successful and failed operations; preserve token fingerprinting rather than storing raw tokens.
- Preserve security defaults: HTTPS by default, HTTP only when explicitly configured, proxy forwarding headers trusted only from configured proxies, shared login throttling, restricted file permissions, database-aware health checks, and graceful shutdown.
- When changing configuration, API routes, persistence, authentication, or validation, update directly related docs and focused tests. Keep web and API behavior consistent where they share functionality.
- Python integration tests in `tests/` use the standard library and exercise the Go binaries. Run focused tests where possible; the main suites are `python3 tests/test_vault_server.py`, `python3 tests/test_vault_backup.py`, and `go test ./...`.
- Keep test scripts in Python; `tests/generate_dummy_secrets.py` is a data-generation utility, not a server or backup test suite.