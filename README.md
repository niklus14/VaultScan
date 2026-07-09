# VaultScan

**Cloud Security Posture Management (CSPM)** — scan AWS for misconfigurations, map compliance risk, and generate clear reports with **Cloud Assistant**.

```
AWS (AssumeRole) → Findings + score → Dashboard → AI report → PDF / Word
```

## Layout

| Path | Purpose |
|------|---------|
| `frontend/` | Next.js CSPM dashboard |
| `backend/` | FastAPI — scans, Settings, Cloud Assistant, PDF/DOCX export |
| `docs/` | Security checks & connection notes |
| `scripts/start-stack.sh` | Start API + UI together |

## Quick start

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional: GROK_API_KEY for Cloud Assistant
python app.py          # http://localhost:8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev            # http://localhost:3000
```

Or from repo root: `./scripts/start-stack.sh`

### Use the product

1. **Settings** → connect AWS (Role assumption recommended) or **Demo mode**
2. **Launch active scan**
3. Review Overview / findings / compliance / remediation
4. **Generate Report** → **PDF** or **Word**
5. Top-right **Cloud Assistant** for questions on findings

You can reopen the last report and export PDF/Word without scanning again (saved under `backend/data/`, gitignored).

## AWS connection

Configure in **Settings** (not only `.env`):

1. Access keys for a connector IAM user (can call `sts:AssumeRole`)
2. Target **Role ARN** with read-only policies (`SecurityAudit` / `ViewOnlyAccess`)

Never commit secrets. Prefer AssumeRole over admin long-lived keys.

## Environment

See `backend/.env.example`. UI Settings overrides AWS defaults at runtime.

## License

Academic / portfolio CSPM project (2026).
