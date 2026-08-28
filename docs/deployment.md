# Deployment Guide

## Production Readiness

ClickSafe runs untrusted websites in Playwright. Deploy the API as an isolated scanning service,
not as a general-purpose web application.

- Run it in a dedicated container or VM with a non-root service account.
- Allow browser egress only to public HTTP/HTTPS destinations and required API providers.
- Block egress to loopback, RFC 1918, link-local, metadata, and internal network ranges at the
  network boundary. The application also rejects these targets, but network policy is the final
  enforcement point.
- Persist screenshots, HTML artifacts, and the SQLite database on controlled volumes. Encrypt
  backups and define an artifact-retention policy.
- Keep all provider keys in a managed secret store. Never expose them to the frontend or commit
  `.env` files.

## Required Configuration

Start from the root `.env.example`, then set production values outside source control.

```dotenv
APP_ENV=production
LOG_LEVEL=INFO
DATABASE_URL=sqlite+aiosqlite:////var/lib/clicksafe/clicksafe.db
SCREENSHOT_DIR=/var/lib/clicksafe/screenshots
HTML_DIR=/var/lib/clicksafe/html
BLOCK_PRIVATE_NETWORKS=true
MAX_REQUEST_BODY_BYTES=8192
ANALYSIS_RATE_LIMIT_ENABLED=true
ANALYSIS_RATE_LIMIT_REQUESTS=5
ANALYSIS_RATE_LIMIT_WINDOW_SECONDS=60
CORS_ORIGINS=https://clicksafe.example.com
OPENAI_API_KEY=replace-with-managed-secret
VIRUSTOTAL_API_KEY=replace-with-managed-secret
GOOGLE_SAFE_BROWSING_API_KEY=replace-with-managed-secret
```

Use a production CORS allowlist. Do not use `*` while credentials are enabled.

## Backend Startup

Install the service and Chromium in the deployment environment:

```bash
cd backend
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install .
.venv/bin/python -m playwright install --with-deps chromium
```

Run the API behind a TLS-terminating reverse proxy:

```bash
.venv/bin/uvicorn clicksafe.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Use one worker per SQLite database unless write access is coordinated externally. For multiple
workers or replicas, migrate job storage to a server database and use a shared rate limiter such
as Redis or enforce limits at the reverse proxy/API gateway.

## Frontend Build

```bash
cd frontend
npm ci
npm run build
```

Deploy `frontend/dist` through a static web server. Set `VITE_API_BASE_URL` before the build to
the public HTTPS API origin.

## Reverse Proxy Requirements

- Terminate TLS and redirect HTTP to HTTPS.
- Limit request body size to the same or smaller value as `MAX_REQUEST_BODY_BYTES`.
- Add a second rate limit at the edge for `POST /api/v1/analyze`.
- Forward the real client address only from known proxies; ClickSafe otherwise uses the direct
  connection peer for its built-in per-process rate limit.
- Do not cache analysis responses, screenshots, or HTML artifacts.

## Observability

ClickSafe emits JSON application logs. Each response includes an `X-Request-ID` header, and log
records include the same request ID, event name, HTTP method, path without query parameters,
status code, and duration. Analysis logs use the analysis ID rather than the submitted URL.

Monitor at least:

- `429` responses, which indicate scan throttling.
- `413` responses, which indicate oversized requests.
- `unsafe_destination` browser failures, which indicate blocked private-network targets or
  redirects.
- Browser timeout, setup, and navigation failures.
- Provider-specific reputation and AI fallback states.

## Verification Before Release

```bash
cd backend
.venv/bin/python -m pytest
.venv/bin/python -m ruff check src tests
.venv/bin/python -m mypy src

cd ../frontend
npm ci
npm run test
npm run build
npx playwright install chromium
npm run test:e2e
```

Review the provider licensing and artifact-retention policy before enabling scans for external
users. Google Safe Browsing v4 is not licensed for commercial use; use Google Web Risk or another
commercially appropriate provider when needed.
