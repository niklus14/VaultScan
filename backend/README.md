# VaultScan API

FastAPI service for the VaultScan dashboard.

## Features

- AWS AssumeRole / direct keys / demo scan
- Misconfig checks (S3, IAM, EC2, RDS)
- Settings UI credential storage (`data/connection.json`)
- Cloud Assistant summaries, chat, and rich PDF/DOCX reports
- Persisted scans (`data/scans.json`) so reports reopen without a new scan

## Run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

API docs: http://localhost:8000/docs

## Main routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan` | Run scan (uses Settings) |
| GET | `/api/scans/latest` | Last saved scan |
| GET/PUT | `/api/settings/connection` | Cloud connection settings |
| POST | `/api/ai/report` | Report package for UI |
| GET | `/api/report/export/pdf` | Download PDF |
| GET | `/api/report/export/docx` | Download Word |
| POST | `/api/ai/chat` | Cloud Assistant chat |

Secrets and `data/*` are gitignored.
