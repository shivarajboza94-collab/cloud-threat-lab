#!/usr/bin/env bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== Running Threat Modeling Lab Verifications ===${NC}"

# 1. Test BOLA / IDOR on API
echo -e "\n[*] Testing IDOR Vulnerability (Tenant B accessing Tenant A record):"
echo -n "Vulnerable Endpoint (v1): "
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5000/api/v1/invoices/inv-101

echo -n "Hardened Endpoint (v2 with Tenant B header): "
RESPONSE=$(curl -s -H "X-Tenant-ID: tenant-b" http://localhost:5000/api/v2/invoices/inv-101)
echo "$RESPONSE"

# 2. Verify Non-Root User Execution in Worker
echo -e "\n[*] Checking Worker User ID and Privilege Escalation:"
docker exec threat-worker whoami
docker exec threat-worker id

# 3. Test Read-Only Root Filesystem (Tampering Prevention)
echo -e "\n[*] Testing Write Access on Worker Root Filesystem:"
if docker exec threat-worker touch /root_test.txt 2>/dev/null; then
    echo -e "${RED}[!] FAIL: Container root filesystem is writable!${NC}"
else
    echo -e "${GREEN}[+] PASS: Root filesystem is read-only. Modification blocked.${NC}"
fi

# 4. Verify Ephemeral Memory Buffer (/tmp)
echo -e "\n[*] Testing Ephemeral Sandboxed Scratchpad (/tmp):"
if docker exec threat-worker touch /tmp/scratch.pdf 2>/dev/null; then
    echo -e "${GREEN}[+] PASS: Sandboxed /tmp volume is writable for processing.${NC}"
fi
