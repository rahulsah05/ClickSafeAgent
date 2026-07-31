# ClickSafe

ClickSafe is an AI-powered phishing detection application. The finished product will inspect a submitted URL in an isolated browser session, collect technical and visual evidence, enrich it with reputation services, and use the OpenAI Responses API to return a Safe, Suspicious, or Malicious verdict with a risk score.

This repository is currently at Phase 5: backend URL validation, SQLite persistence, isolated Playwright browser capture, technical analyzers, and reputation-service integration are implemented.

## Stack

- Backend: Python, FastAPI, async service boundaries, SQLite
- Browser automation: Playwright
- AI reasoning: OpenAI Responses API
- Frontend: React, TypeScript, Tailwind CSS, Vite
- Testing: pytest for backend, Vitest for frontend

## Local Setup

Backend:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m playwright install chromium
uvicorn clicksafe.main:app --reload
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

Environment:

```powershell
Copy-Item .env.example .env
```

Set `VIRUSTOTAL_API_KEY` and `GOOGLE_SAFE_BROWSING_API_KEY` to enable reputation checks. Use
`REPUTATION_TIMEOUT_SECONDS` to set the per-provider request timeout. `OPENAI_API_KEY` is used
by the planned Phase 6 verdict integration.

Google Safe Browsing is licensed for non-commercial use. A commercial deployment should use
[Google Web Risk](https://cloud.google.com/web-risk) instead.

## Current Endpoints

- `GET /api/v1/health` returns service health metadata.
- `POST /api/v1/analyze` validates and normalizes a URL, persists an analysis job, runs browser capture and technical/reputation checks, and returns the current Phase 5 job payload.
- The analysis payload includes browser evidence, technical analyzer findings, and reputation-service findings when API keys are configured.
- `GET /api/v1/analyses` returns recent persisted analysis jobs.
- `GET /api/v1/analyses/{analysis_id}` returns a persisted analysis job by ID.

## Phase Gate

Per the requested workflow, implementation stops after each phase until approval is given.
