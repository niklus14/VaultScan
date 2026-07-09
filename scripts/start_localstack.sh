#!/usr/bin/env bash
# Start a reliable community LocalStack for VaultScan development/demo
set -e

CONTAINER="vaultscan-localstack"

echo "==> Stopping old container (if any)"
docker rm -f "$CONTAINER" 2>/dev/null || true

echo "==> Starting LocalStack community (S3 + IAM + common services)"
docker run -d --name "$CONTAINER" \
  -p 4566:4566 \
  -e SERVICES=s3,iam,ec2,rds,lambda,kms \
  -e LOCALSTACK_AUTH_TOKEN="" \
  -e DISABLE_PRO=1 \
  localstack/localstack:3.8

echo "==> Waiting for readiness..."
for i in {1..25}; do
  if curl -sf http://localhost:4566/_localstack/health >/dev/null 2>&1; then
    echo "✅ LocalStack is up"
    curl -s http://localhost:4566/_localstack/health | python3 -c '
import sys, json
h = json.load(sys.stdin)
print("Edition:", h.get("edition"))
print("Available:", [k for k,v in h.get("services",{}).items() if v == "available"])
'
    exit 0
  fi
  sleep 1.2
  echo -n "."
done

echo "Timed out. Check: docker logs $CONTAINER"
exit 1
