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

See `backend/.env.example` and `frontend/.env.example`. UI Settings overrides AWS defaults at runtime.

## Deploy on Vercel (Services)

This repo is set up as a **Vercel Services** project: Next.js UI + FastAPI API in one deployment (see root `vercel.json`).

```
Browser → your-app.vercel.app
            ├─ /api/*  →  backend (FastAPI, entrypoint app:app)
            └─ /*      →  frontend (Next.js)
```

### 1. Import the repo

1. [vercel.com/new](https://vercel.com/new) → import the Git repository  
2. **Application Preset** → **Services** (not a single Next.js-only preset)  
3. Leave **Root Directory** as `/`  
4. In **Build and Output Settings**, **turn OFF** any custom overrides  
   - Build / Install must **not** be `npm run dev`  
   - Vercel reads install/build from each service (`frontend/`, `backend/`)

### 2. Confirm `vercel.json` (already in repo)

Root `vercel.json` must include a complete `services` block. Incomplete JSON (missing braces) will show a red error in the Vercel UI:

```json
{
  "services": {
    "frontend": { "root": "frontend/", "framework": "nextjs", ... },
    "backend":  { "root": "backend/", "entrypoint": "app:app" }
  },
  "rewrites": [
    { "source": "/api/(.*)", "destination": { "service": "backend" } },
    { "source": "/(.*)",     "destination": { "service": "frontend" } }
  ]
}
```

If the UI still says *“vercel.json required…”*, click **Refresh** after this file is on the default branch, or paste the full file into the editor (valid JSON only).

### 3. Environment variables

| Name | Where | Notes |
|------|--------|--------|
| `GROK_API_KEY` | backend / project env | Optional; Cloud Assistant |
| `NEXT_PUBLIC_SITE_URL` | frontend | e.g. `https://vault-scan.vercel.app` |
| AWS keys / role | backend | Prefer Settings UI at runtime for demos |

`VAULTSCAN_API_ORIGIN` is injected automatically via the **service binding** when using Services mode.

Leave `NEXT_PUBLIC_API_BASE` empty so the browser uses same-origin `/api/*`.

### 4. Deploy

Push to `main`, or from the repo root:

```bash
npx vercel
npx vercel --prod
```

### Frontend-only alternative

If you only want the Next.js app on Vercel and host FastAPI elsewhere:

1. Preset → **Next.js** (not Services)  
2. Root Directory → `frontend`  
3. Set `VAULTSCAN_API_ORIGIN` to your external API URL  

### Local production smoke-test

```bash
cd frontend
cp .env.example .env.local
npm install && npm run build && npm start
```

**Caveats:** serverless timeouts can affect long AWS scans; `backend/data/` is ephemeral on Vercel (scans/settings may not persist across cold starts unless you add external storage).

## License

Academic / portfolio CSPM project (2026).
