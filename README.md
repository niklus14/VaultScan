# VaultScan

**Cloud Security Posture Management (CSPM)** — detect AWS misconfigurations, map them to compliance frameworks, and generate clear reports with **Cloud Assistant**.

```
Scan AWS (AssumeRole) → Findings + score → Dashboard → AI report → PDF / Word
```

## Repository layout

| Path | Purpose |
|------|---------|
| `frontend/` | Next.js CSPM dashboard (UI) |
| `backend/` | FastAPI API — scan engine, settings, Cloud Assistant, PDF/DOCX export |
| `scanner.py` | Standalone CLI scanner (LocalStack / Moto / AWS) |
| `demo_with_moto.py` | One-command demo scan (no AWS account) |
| `docs/` | Connection guide, security checks, project notes |
| `scripts/` | Local helpers (LocalStack bootstrap, start stack) |
| `webapp/` | Legacy Flask UI (optional) |
| `Cloud-Misconfig-Scanner/` | Multi-cloud S3-focused library (used by legacy webapp) |

## Quick start (product stack)

### 1. Backend API

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env — set GROK_API_KEY for Cloud Assistant (optional for scan-only)
# Prefer configuring AWS in the UI: Settings → Cloud Connection

python app.py
# → http://localhost:8000
# → docs: http://localhost:8000/docs
```

### 2. Frontend dashboard

```bash
cd frontend
npm install
npm run dev
# → http://localhost:3000
```

The Next.js app proxies `/api/*` to `http://127.0.0.1:8000`.

### 3. Use the product

1. Open **Settings** → connect AWS (**IAM Role assumption** recommended) or **Demo mode**
2. **Launch active scan**
3. Browse Overview / Vulnerability Feed / Compliance / Remediation
4. **Generate Report** → download **PDF** or **Word**
5. Use the top-right **Cloud Assistant** for Q&A on findings

You can reopen the last report and export PDF/Word **without** running a new scan (results are saved under `backend/data/`, gitignored).

## AWS connection model

Industry-standard CSPM pattern:

1. IAM user access keys (operator identity) — only need `sts:AssumeRole`
2. Target **Role ARN** with read-only policies (`SecurityAudit` / `ViewOnlyAccess`)
3. VaultScan assumes the role and scans S3, IAM, EC2, RDS, etc.

Configure this in the **Settings** UI — do not commit secrets.

## CLI demos (no UI)

```bash
# In-memory vulnerable cloud (Moto)
python demo_with_moto.py
# or
python scanner.py --simulate

# Real AWS (profile / env credentials)
python scanner.py --aws --region us-east-1
```

## Environment variables (backend)

See `backend/.env.example`:

- `GROK_API_KEY` — Cloud Assistant (xAI-compatible API)
- `AWS_ROLE_ARN` — default role (overridden by Settings UI)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` — optional; Settings UI is preferred

## Security notes

- Never commit `.env` or `backend/data/`
- Prefer short-lived AssumeRole over long-lived admin keys
- Access keys stored via Settings stay on the server and are never returned in full

## License / academic use

Built as a cybersecurity / CSPM portfolio project (2026).
