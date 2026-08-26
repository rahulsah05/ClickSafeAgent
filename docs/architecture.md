# Architecture

ClickSafe follows a clean architecture layout. The dependency direction should point inward: API and infrastructure depend on application services, application services depend on domain models, and domain models do not depend on frameworks.

## Backend Layers

- `domain`: framework-free entities, enums, and evidence contracts.
- `application`: orchestration services and use cases.
- `analyzers`: focused phishing evidence analyzers, one concern per file.
- `infrastructure`: Playwright, database, OpenAI, and reputation-service adapters.
- `api`: FastAPI routes, schemas, and dependency wiring.
- `core`: configuration, logging, and shared runtime settings.

## Frontend Layers

- `components`: reusable dashboard UI modules.
- `lib`: API clients and utility code.
- `types`: shared TypeScript contracts.

## Planned Analysis Flow

1. Validate and normalize the submitted URL.
2. Create an analysis record in SQLite.
3. Visit the URL through an isolated Playwright browser context.
4. Capture redirects, final URL, screenshot, and HTML.
5. Run technical analyzers concurrently where safe.
6. Query reputation services when API keys are present.
7. Send the evidence bundle to the OpenAI Responses API.
8. Persist and return the final verdict payload.

## Implemented Phase 6 Flow

1. Accept a submitted URL string.
2. Persist a requested analysis job.
3. Normalize HTTP/HTTPS URLs, remove fragments, lowercase hostnames, remove default ports, and add HTTPS to bare domains.
4. Mark the job running with initial lifecycle evidence.
5. Visit the normalized URL in a fresh Playwright Chromium browser context.
6. Observe redirects and record the final page URL and response status.
7. Save a full-page screenshot artifact.
8. Save an HTML artifact with configured byte limits and truncation metadata.
9. Run technical analyzers for redirects, HTML structure, metadata, forms, JavaScript, DNS, SSL, and WHOIS.
10. Run reputation checks against VirusTotal and Google Safe Browsing when API keys are configured.
11. Send the normalized evidence bundle to the OpenAI Responses API using a strict structured-output schema when `OPENAI_API_KEY` is configured.
12. Persist the AI verdict, risk score, explanation, confidence, recommendation, and evidence weights. If OpenAI is unavailable, persist a labeled local heuristic fallback.
13. Mark the job completed with validation, browser, technical, reputation, and AI evidence, or failed when URL policy validation or browser navigation rejects the URL.
14. Return and persist the job payload for later retrieval.

## Implemented Phase 7 Dashboard

1. The React dashboard submits URLs to `POST /api/v1/analyze` and renders the returned job payload.
2. It presents verdict, risk score, validation, browser, AI, technical, and reputation evidence in responsive light and dark layouts.
3. Browser redirect responses are displayed in order, along with the final destination.
4. Captured screenshots are loaded through the analysis-scoped screenshot API rather than exposing a filesystem path.
5. Network failures and failed analysis jobs offer a retry using the previously submitted URL.

## AI Verdict Source

- OpenAI Responses API requests use `responses.create`.
- Structured output is requested with `text.format` using `type: json_schema`, `strict: true`, and a ClickSafe verdict schema.

## Reputation Sources

- VirusTotal uses API v3 `GET /api/v3/urls/{id}`, where `{id}` is the URL-safe base64 representation of the URL without padding.
- Google Safe Browsing uses the v4 `POST /v4/threatMatches:find` lookup endpoint. It is intended for non-commercial use; commercial deployments should use Google Web Risk.
- Each provider uses `REPUTATION_TIMEOUT_SECONDS`; provider failures and malformed responses are preserved as provider-specific evidence so one unavailable service does not discard the other result.
- Enabled providers receive the browser's final URL. URLs containing sensitive query tokens should be treated as a third-party disclosure.
