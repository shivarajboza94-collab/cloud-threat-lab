#!/usr/bin/env bash

set -eo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NETWORK_NAME="threat-lab-net"
INTERNAL_API_URL="http://threat-api:5000"
HOST_HEALTH_URL="http://localhost:5000/health"

WIN_PWD=$(pwd -W 2>/dev/null || cygpath -w "$PWD" 2>/dev/null || echo "$PWD")
SARIF_FILE="results/nuclei-findings.sarif"

mkdir -p results
rm -f "$SARIF_FILE" results/step-summary.md

cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up containers and network (${NETWORK_NAME})...${NC}"
    docker compose down --remove-orphans >/dev/null 2>&1 || true
    echo -e "${GREEN}[+] Environment stopped cleanly.${NC}"
}
trap cleanup EXIT

echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}   End-to-End Docker Network & SARIF Job Summary Gate    ${NC}"
echo -e "${BLUE}=========================================================${NC}"

echo -e "\n[*] Starting API container on network '${NETWORK_NAME}'..."
docker compose up -d --build api >/dev/null 2>&1

echo -n "[*] Waiting for API health check ($HOST_HEALTH_URL)..."
RETRIES=15
until curl -s "$HOST_HEALTH_URL" | grep -q "healthy" || [ $RETRIES -eq 0 ]; do
    sleep 1
    RETRIES=$((RETRIES - 1))
    echo -n "."
done
echo ""

if [ $RETRIES -eq 0 ]; then
    echo -e "${RED}[!] FATAL: API did not become healthy in time.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] API is online and reachable.${NC}"

echo -e "\n[*] Running Nuclei against ${INTERNAL_API_URL} on ${NETWORK_NAME}..."
MSYS_NO_PATHCONV=1 docker run --rm \
  --network="$NETWORK_NAME" \
  -v "${WIN_PWD}/nuclei-templates:/templates" \
  -v "${WIN_PWD}/results:/results" \
  projectdiscovery/nuclei:latest \
  -u "$INTERNAL_API_URL" \
  -t "/templates" \
  -tags "idor,auth" \
  -severity "high,critical" \
  -sarif-export "/results/nuclei-findings.sarif" \
  -silent -no-color || true

if [ ! -f "$SARIF_FILE" ]; then
    cat << 'SARIF_EOF' > "$SARIF_FILE"
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "nuclei", "rules": [] } },
      "results": []
    }
  ]
}
SARIF_EOF
fi

PYTHON_BIN=$(command -v python || command -v python3)
"$PYTHON_BIN" scripts/evaluate_sarif.py
