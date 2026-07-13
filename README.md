# VaultScan

Cloud Security Posture Management (CSPM) — scan AWS for misconfigurations (lab Steps 1–10), map attack paths, and export reports with Cloud Assistant.

```
AWS (AssumeRole) → Findings + score → Dashboard → AI report → PDF / Word
```

## Layout

| Path | Purpose |
|------|---------|
| `frontend/` | Next.js CSPM dashboard |
| `backend/` | FastAPI — scans, Settings, Cloud Assistant, PDF/DOCX |
| `docs/` | Security checks & connection notes |
| `scripts/start-stack.sh` | Start API + UI together |

## Local quick start

### Backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional GROK_API_KEY
python app.py          # http://localhost:8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev            # http://localhost:3000
```

Or: `./scripts/start-stack.sh`

1. **Settings** → Demo mode **or** real AWS Access Key + Role ARN  
2. **Launch active scan**  
3. Review Overview / Findings / Attack Paths  
4. **Generate Report** → PDF / Word  

## Deploy on Vercel (GitHub)

Root `vercel.json` uses **Vercel Services**:

- `/api/*` → FastAPI (`backend/app:app`)
- `/*` → Next.js (`frontend/`)

1. Import `niklus14/VaultScan` in Vercel  
2. Application Preset: **Services**, Root Directory `/`  
3. Turn OFF custom Build/Install overrides  
4. Optional env: `GROK_API_KEY`  
5. Deploy  

Settings secrets on Vercel use `/tmp` (ephemeral). Demo mode always works.

## License

Academic / portfolio CSPM project (2026).
