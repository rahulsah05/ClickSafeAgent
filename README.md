# ClickSafe

ClickSafe is an AI-powered phishing detection application. The finished product will inspect a submitted URL in an isolated browser session, collect technical and visual evidence, enrich it with reputation services, and use the OpenAI Responses API to return a Safe, Suspicious, or Malicious verdict with a risk score.

This repository is currently at Phase 7: the responsive dashboard submits scans to the backend and
renders verdicts, evidence groups, redirect trails, captured screenshots, loading/failure states,
and retries. The backend URL validation, SQLite persistence, isolated Playwright browser capture,
technical analyzers, reputation-service integration, and AI verdict generation are also implemented.

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

Set `OPENAI_API_KEY` to enable OpenAI Responses API verdict generation. Without it, ClickSafe
returns a clearly labeled local heuristic fallback so development scans still complete. Set
`VIRUSTOTAL_API_KEY` and `GOOGLE_SAFE_BROWSING_API_KEY` to enable reputation checks. Use
`REPUTATION_TIMEOUT_SECONDS` to set the per-provider request timeout.

Google Safe Browsing is licensed for non-commercial use. A commercial deployment should use
[Google Web Risk](https://cloud.google.com/web-risk) instead.

## Current Endpoints

- `GET /api/v1/health` returns service health metadata.
- `POST /api/v1/analyze` validates and normalizes a URL, persists an analysis job, runs browser capture, technical/reputation checks, AI verdict generation, and returns the current Phase 7 job payload.
- The analysis payload includes browser evidence, technical analyzer findings, reputation-service findings when API keys are configured, and an `ai` verdict block.
- `GET /api/v1/analyses` returns recent persisted analysis jobs.
- `GET /api/v1/analyses/{analysis_id}` returns a persisted analysis job by ID.
- `GET /api/v1/analyses/{analysis_id}/screenshot` returns the captured PNG for that analysis when the expected artifact is available.

## Phase Gate

Per the requested workflow, implementation stops after each phase until approval is given.
