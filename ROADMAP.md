# ClickSafe Development Roadmap

## Phase 1 - Foundation

Status: complete in this scaffold.

- Create backend and frontend project structure.
- Configure Python and npm dependencies.
- Establish clean architecture module boundaries.
- Add FastAPI health route and placeholder analysis route.
- Add responsive React/Tailwind dashboard shell.
- Add test harnesses for backend and frontend.
- Document setup, architecture, and phase plan.

## Phase 2 - Backend Core

Status: complete.

- Implemented URL validation and normalization.
- Added database models and async SQLite persistence.
- Created analysis job lifecycle: requested, running, completed, failed.
- Implemented service orchestration for the current Phase 2 pipeline.
- Added unit tests for validation, service flow, and error cases.

## Phase 3 - Browser Isolation

Status: complete.

- Implemented Playwright browser lifecycle.
- Follow redirects and capture the final URL chain.
- Save screenshot artifacts.
- Extract HTML with size limits and timeout handling.
- Add tests around browser-client error mapping.

## Phase 4 - Technical Analyzers

Status: complete.

- Implemented SSL certificate inspection.
- Implemented DNS resolution analyzer.
- Implemented WHOIS/domain age analyzer.
- Implemented HTML structure analyzer.
- Implemented HTML metadata analyzer.
- Implemented forms and credential-field analyzer.
- Implemented suspicious JavaScript analyzer.
- Implemented redirect-chain analyzer.

## Phase 5 - Reputation Integrations

Status: complete.

- Added VirusTotal API v3 URL report client using `VIRUSTOTAL_API_KEY`.
- Added Google Safe Browsing v4 lookup client using `GOOGLE_SAFE_BROWSING_API_KEY`.
- Added configurable timeout, HTTP error, malformed-response, and missing-key behavior.
- Added mocked request-contract tests and provider-failure isolation coverage.

## Phase 6 - AI Verdict

Status: complete.

- Built an OpenAI Responses API client.
- Defined a strict JSON schema for AI output.
- Send normalized evidence to the model.
- Return verdict, risk score, explanation, recommendation, confidence, and evidence weighting.
- Added tests for structured-output request assembly, fallback behavior, and schema handling.

## Phase 7 - Dashboard Experience

- Wire frontend to backend analysis endpoint.
- Display verdict, score, screenshot, redirect trail, and evidence groups.
- Add loading, failure, and retry states.
- Polish mobile layout and dark mode.
- Add frontend component tests.

## Phase 8 - Hardening

- Add rate limiting and request size controls.
- Add SSRF protections and private network blocking.
- Add structured JSON logging.
- Add end-to-end tests.
- Add deployment documentation.
