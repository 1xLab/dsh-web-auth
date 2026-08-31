# DSH Web Auth

`DSH Web Auth` is a light, security-focused [DeepSeek Harness (DSH)](https://github.com/deepseek-ai/deepseek-harness) host plugin that adds a password-protected login page and persistent session cookies for the DSH Web UI.

## Features

- **HTML Login Page (`/login`):** Modern, dark-themed login screen for unauthenticated visitors.
- **Unauthenticated Root Redirect:** Direct visits to `/` without a valid session cookie automatically redirect to `/login`.
- **HMAC Signed Cookie Integration:** Uses the exact HMAC-SHA256 signature format and credential store (`client-connection/browser-session`) as native DSH `BrowserAuth`, ensuring 100% compatibility with DSH Connection RPC authentication.
- **Persistent Sessions:** Configurable 30-day (or custom) `HttpOnly; SameSite=Strict` cookie so users stay logged in across process restarts without needing `?token=...` launch links in URLs.
- **Logout Route (`/logout`):** Clears the authority-bound session cookie and redirects to `/login`.

## Environment Configuration

Configure the access password via environment variable in your DSH home `.env` or deployment environment:

```env
DSH_WEB_PASSWORD=YourSecurePasswordHere
```

If `DSH_WEB_PASSWORD` is omitted, the password defaults to the configured plugin option or `coder2026`.

## Usage

1. Open `https://your-domain.com/` in your browser.
2. If unauthenticated, you will be redirected to `https://your-domain.com/login`.
3. Enter your password and submit.
4. Your browser receives the signed session cookie and redirects back to `/`.

## Architecture and Integration

The host plugin registers exact WebServer routes:

- `GET /login`: Renders the HTML login page (or redirects to `/` if already authenticated).
- `POST /login`: Validates the password and sets the signed `dsh-auth-<authorityHash>` cookie.
- `GET /logout`: Clears the session cookie.
- `GET /`: Intercepts unauthenticated root requests, redirecting them to `/login` while passing authenticated requests (and launch token exchanges) to the webserver SPA fallback.

## Model Experience

This plugin is a pure host infrastructure component that manages HTTP web server authentication. It does not register LLM tools, alter prompts, or modify model context.

## Known Limitations and Deferred Work

- Single shared password authentication; multi-user RBAC or OAuth2 OIDC workflows are deferred.
- Rate limiting / IP brute-force lockouts are handled by external reverse proxies or firewall layers.
