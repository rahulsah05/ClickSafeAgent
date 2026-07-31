# ClickSafe Backend

FastAPI service for URL analysis, evidence collection, and AI-assisted phishing verdicts.

## Commands

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m playwright install chromium
uvicorn clicksafe.main:app --reload
```

## Tests

```powershell
pytest
```

