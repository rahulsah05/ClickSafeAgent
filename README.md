# ClickSafe

ClickSafe is an AI-powered phishing detection application. The finished product will inspect a submitted URL in an isolated browser session, collect technical and visual evidence, enrich it with reputation services, and use the OpenAI Responses API to return a Safe, Suspicious, or Malicious verdict with a risk score.

This repository is currently at Phase 8: the complete URL-analysis pipeline and dashboard are
implemented, with request throttling, body-size limits, structured JSON logs, SSRF protections,
browser-level dashboard coverage, and deployment guidance added for hardening. Two later checks,
a local URL pre-scan and a structured URL classifier, now run before that pipeline as evidence
only. The classifier does not set the Safe, Suspicious, or Malicious verdict. A beginner-friendly
snapshot of what is finished is in [PROGRESS.md](PROGRESS.md). Dataset and model notes are in
[DATASET_DOCUMENTATION.md](DATASET_DOCUMENTATION.md) and [MODEL_EVALUATION.md](MODEL_EVALUATION.md).

## Stack

- Backend: Python, FastAPI, async service boundaries, SQLite
- Browser automation: Playwright
- AI reasoning: OpenAI Responses API
- Frontend: React, TypeScript, Tailwind CSS, Vite
- Testing: pytest for backend, Vitest and Playwright for frontend

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
npm run test:e2e
```

Environment:

```powershell
Copy-Item .env.example .env
```

Set `OPENAI_API_KEY` to enable OpenAI Responses API verdict generation. Without it, ClickSafe
returns a clearly labeled local heuristic fallback so development scans still complete. Set
`VIRUSTOTAL_API_KEY` and `GOOGLE_SAFE_BROWSING_API_KEY` to enable reputation checks. Use
`REPUTATION_TIMEOUT_SECONDS` to set the per-provider request timeout.

Keep `BLOCK_PRIVATE_NETWORKS=true` in deployed environments. It blocks loopback, private,
link-local, reserved, and unresolved navigation targets before browser access, including redirects.
Configure the rate and body controls with `ANALYSIS_RATE_LIMIT_*` and `MAX_REQUEST_BODY_BYTES`.

Google Safe Browsing is licensed for non-commercial use. A commercial deployment should use
[Google Web Risk](https://cloud.google.com/web-risk) instead.

## Structured URL model

The scan loads `backend/src/clicksafe/infrastructure/ml/models/structured_url_model.joblib`.
Training output is `models/structured_url_model.joblib`. The previous TF-IDF file
`backend/src/clicksafe/infrastructure/ml/models/model.joblib` stays in place and is not the
active prediction call.

Regenerate the synthetic dataset, train, and replay the saved test labels from the repository
root with the backend interpreter:

```powershell
backend\venv\Scripts\python.exe scripts\generate_synthetic_dataset.py --rows 10000 --seed 20261015
backend\venv\Scripts\python.exe scripts\train_structured_model.py --seed 20261015
backend\venv\Scripts\python.exe scripts\evaluate_structured_model.py
```

Run the API from `backend`. Settings load `backend/.env` from that file's path, and the SQLite URL is still relative to the working directory:

```powershell
.\venv\Scripts\uvicorn.exe clicksafe.main:app --reload --host 127.0.0.1 --port 8000 --app-dir src
```

## Current Endpoints

- `GET /api/v1/health` returns service health metadata.
- `POST /api/v1/analyze` validates and normalizes a URL, applies destination and rate-limit policy, persists an analysis job, runs the URL pre-scan and structured URL classifier as evidence, then browser capture, technical/reputation checks, and AI verdict generation. It returns the current Phase 8 job payload. The classifier does not set the verdict.
- The analysis payload includes browser evidence, technical analyzer findings, reputation-service findings when API keys are configured, and an `ai` verdict block.
- `GET /api/v1/analyses` returns recent persisted analysis jobs.
- `GET /api/v1/analyses/{analysis_id}` returns a persisted analysis job by ID.
- `GET /api/v1/analyses/{analysis_id}/screenshot` returns the captured PNG for that analysis when the expected artifact is available.

## Deployment

Read [the deployment guide](docs/deployment.md) before exposing ClickSafe outside a local
development environment.

## Phase Gate

Per the requested workflow, implementation stops after each phase until approval is given.
