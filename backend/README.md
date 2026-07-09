# VaultScan Backend (CSPM API)

FastAPI service that:

1. **Assumes** an IAM role in the target AWS account (`sts:AssumeRole`)
2. **Scans** for real misconfigurations (S3, IAM, EC2 SG, RDS)
3. **Summarizes / chats** via the xAI **Grok** API

## Quick start

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# also: pip install 'moto[s3,iam,ec2,rds]' for simulate mode

# Edit .env — GROK_API_KEY is already set; add base AWS keys that can AssumeRole:
#   AWS_ACCESS_KEY_ID=...
#   AWS_SECRET_ACCESS_KEY=...
# Role is pre-filled:
#   AWS_ROLE_ARN=arn:aws:iam::850919910218:role/demo-test-vulnerable-ec2-role

python app.py
# → http://localhost:8000
# → docs: http://localhost:8000/docs
```

## Auth model (industry standard)

```
Your laptop / VaultScan server
   │  (base keys or SSO / instance profile)
   │  sts:AssumeRole
   ▼
arn:aws:iam::850919910218:role/demo-test-vulnerable-ec2-role
   │  short-lived credentials
   ▼
Read-only APIs: s3:*, iam:List*, ec2:Describe*, rds:Describe*
```

The target role’s **trust policy** must allow your base principal to assume it.
Recommended managed policies on the role: `SecurityAudit` + `ViewOnlyAccess`.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health + Grok key status |
| GET | `/api/connection` | Probe AssumeRole |
| POST | `/api/scan` | Run scan (`assume_role` / `direct` / `simulate`) |
| GET | `/api/scans` | History |
| GET | `/api/scans/latest` | Latest full result |
| POST | `/api/ai/summarize` | Grok executive summary |
| POST | `/api/ai/chat` | Grok security assistant |

### Example — simulate (no AWS)

```bash
curl -s -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"mode":"simulate","region":"us-east-1"}' | jq '.score,.summary'
```

### Example — real AWS via role

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
# or put them in .env

curl -s -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "mode":"assume_role",
    "role_arn":"arn:aws:iam::850919910218:role/demo-test-vulnerable-ec2-role",
    "region":"us-east-1"
  }' | jq '.score,.total_findings,.vulnerabilities[:3]'
```

## Frontend

The Next app in `../frontend` proxies `/api/*` → `http://127.0.0.1:8000`.

```bash
cd ../frontend
pnpm install   # or npm install
pnpm dev       # http://localhost:3000
```

Use the sidebar: pick **AssumeRole** or **Simulate**, then **LAUNCH ACTIVE SCAN**.
Open **GROK ASSIST** for summaries and Q&A.
