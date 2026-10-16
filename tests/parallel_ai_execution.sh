#!/bin/bash

# Parallel AI Execution Test with Encrypted Secrets
# Tests that multiple workers can handle concurrent AI tasks with long execution times
# Usage: ./parallel_ai_execution.sh [NUM_TASKS]

set -e

# Configuration
NUM_TASKS=${1:-3}  # Default: 3 parallel tasks (AI is expensive)
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
USER_ACCOUNT="${USER_ACCOUNT:-zavodil.testnet}"

# ai-example (NEAR.ai API, free, no API key needed), published on FastFS
WASM_URL="https://wasmhub.testnet.fastfs.io/fastfs.testnet/cbf80ed0080dd62f2041745cdc958ec0fbd192f33aeaa756f7873d742204b2f8.wasm"
WASM_HASH="41c1c7b3528565f3fd139943f439d61c0768e9abdb9b579bd0921ecbfcabeded"
BUILD_TARGET="wasm32-wasip2"

# AI prompts for variety
AI_PROMPTS=(
    "Explain what NEAR Protocol is in one sentence"
    "What are the benefits of blockchain technology?"
    "Describe Web3 in simple terms"
    "What is decentralized computation?"
    "How does off-chain execution help blockchain scalability?"
    "What makes smart contracts secure?"
    "Explain gas fees in blockchain"
    "What is the difference between Layer 1 and Layer 2?"
    "How do oracles work in blockchain?"
    "What is the future of decentralized applications?"
)

SENDERS=(
    "zavodil.testnet"
    "zavodil2.testnet"
    "zavodil3.testnet"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Parallel AI Execution Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${YELLOW}Number of parallel AI tasks: ${NUM_TASKS}${NC}"
echo -e "${YELLOW}Contract: ${CONTRACT_ID}${NC}"
echo -e "${YELLOW}User: ${USER_ACCOUNT}${NC}"
echo -e "${YELLOW}Using NEAR.ai API (free, no key needed)${NC}"
echo ""

# Function to submit a single AI execution request
submit_ai_task() {
    local task_num=$1

    # Select prompt (cycle through available prompts)
    local prompt_index=$(( (task_num - 1) % ${#AI_PROMPTS[@]} ))
    local prompt="${AI_PROMPTS[$prompt_index]}"

    local sender="${SENDERS[$prompt_index]}"

    # Build input_data JSON
    local input_data="{\"prompt\":\"${prompt}\",\"history\":[{\"role\":\"user\",\"content\":\"Hello\"},{\"role\":\"assistant\",\"content\":\"Hi! I'm here to help.\"}],\"model_name\":\"fireworks::accounts/fireworks/models/gpt-oss-120b\",\"openai_endpoint\":\"https://api.near.ai/v1/chat/completions\",\"max_tokens\":16384}"

    echo -e "${BLUE}[AI Task ${task_num}] Submitting execution request...${NC}"
    echo -e "${BLUE}[AI Task ${task_num}] Prompt: ${prompt}${NC}"

    set +e  # Don't exit on error

    # Build JSON payload with escaped prompt
    local json_payload="{
    \"source\": {
      \"WasmUrl\": {
        \"url\": \"$WASM_URL\",
        \"hash\": \"$WASM_HASH\",
        \"build_target\": \"$BUILD_TARGET\"
      }
    },
    \"resource_limits\": {
      \"max_instructions\": 10000000000,
      \"max_memory_mb\": 128,
      \"max_execution_seconds\": 60
    },
    \"input_data\": \"{\\\"prompt\\\":\\\"${prompt} Be short\\\",\\\"history\\\":[],\\\"model_name\\\":\\\"fireworks::accounts/fireworks/models/gpt-oss-120b\\\",\\\"openai_endpoint\\\":\\\"https://api.near.ai/v1/chat/completions\\\",\\\"max_tokens\\\":16384}\",
    \"secrets_ref\": {
        \"profile\": \"default\",
        \"account_id\": \"zavodil2.testnet\"
    }    
  }"

    # Call contract with encrypted secrets
    local output=$(near contract call-function as-transaction "$CONTRACT_ID" request_execution json-args "$json_payload" prepaid-gas '300.0 Tgas' attached-deposit '0.1 NEAR' sign-as "$sender" network-config testnet sign-with-keychain send 2>&1)
    
    local exit_code=$?
    set -e

    # Extract transaction hash (check both hash formats)
    local tx_hash=$(echo "$output" | grep -oE '[A-Za-z0-9]{40,}' | head -1)

    # If we have a transaction hash, submission was successful
    # (exit_code may be non-zero due to contract panic with result)
    if [ -n "$tx_hash" ]; then
        echo -e "${GREEN}[AI Task ${task_num}] ✓ Submitted successfully${NC}"
        echo -e "${GREEN}[AI Task ${task_num}] TX: ${tx_hash}${NC}"
        echo "$tx_hash" > "/tmp/offchainvm_ai_task_${task_num}.tx"
    else
        echo -e "${RED}[AI Task ${task_num}] ✗ Failed to submit${NC}"
        echo "$output" | head -10
        return 1
    fi
}

# Submit all AI tasks in parallel
echo -e "${YELLOW}Submitting ${NUM_TASKS} AI tasks in parallel...${NC}"
echo -e "${YELLOW}Each task will call NEAR.ai API and take ~5-30 seconds${NC}"
echo ""

pids=()
start_time=$(date +%s)

for i in $(seq 1 $NUM_TASKS); do
    submit_ai_task $i &
    pids+=($!)
    sleep 1  # Small delay to avoid overwhelming the system
done

# Wait for all submissions to complete
echo ""
echo -e "${YELLOW}Waiting for all AI task submissions to complete...${NC}"
for pid in "${pids[@]}"; do
    wait $pid || true  # Continue even if some tasks fail
done

submit_time=$(($(date +%s) - start_time))

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All ${NUM_TASKS} AI tasks submitted in ${submit_time}s!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Monitor execution progress
echo -e "${YELLOW}Monitoring AI task execution...${NC}"
echo -e "${YELLOW}This may take 30-60 seconds per task${NC}"
echo ""

sleep 10

# Check worker distribution
echo -e "${BLUE}Checking coordinator for worker distribution:${NC}"
curl -s "http://localhost:8080/public/jobs?limit=50" | python3 -c "
import sys
import json
from collections import Counter
from datetime import datetime, timedelta

try:
    data = json.load(sys.stdin)
except:
    print('Failed to fetch jobs data')
    sys.exit(1)

# Filter recent jobs (last 5 minutes)
now = datetime.now()
recent_jobs = []
for job in data:
    try:
        created_at = job.get('created_at', '')
        if created_at:
            # Parse timestamp
            job_time = datetime.fromisoformat(created_at.replace('Z', '').replace('+00:00', ''))
            if (now - job_time).total_seconds() < 300:
                recent_jobs.append(job)
    except:
        continue

workers = Counter(job['worker_id'] for job in recent_jobs if job.get('worker_id'))
statuses = Counter(job['success'] for job in recent_jobs)

print(f'\nRecent jobs (last 5 min): {len(recent_jobs)}')
print('\nWorker distribution:')
for worker, count in workers.most_common():
    print(f'  {worker}: {count} jobs')

print(f'\nStatus:')
print(f'  Success: {statuses.get(True, 0)}')
print(f'  Failed: {statuses.get(False, 0)}')
print(f'  Pending: {len(recent_jobs) - statuses.get(True, 0) - statuses.get(False, 0)}')

if len(workers) > 1:
    print(f'\n✓ Tasks distributed across {len(workers)} workers')
elif len(workers) == 1:
    print(f'\n⚠ All tasks handled by 1 worker (start more workers for distribution test)')
else:
    print(f'\n⚠ No workers found yet')
" 2>/dev/null || echo "Failed to analyze jobs"

echo ""
echo -e "${BLUE}Transaction hashes:${NC}"
for i in $(seq 1 $NUM_TASKS); do
    if [ -f "/tmp/offchainvm_ai_task_${i}.tx" ]; then
        tx=$(cat "/tmp/offchainvm_ai_task_${i}.tx")
        echo -e "  AI Task ${i}: https://testnet.nearblocks.io/txns/${tx}"
        rm "/tmp/offchainvm_ai_task_${i}.tx"
    fi
done

echo ""
echo -e "${GREEN}✓ Parallel AI execution test completed${NC}"
echo -e "${YELLOW}Note:${NC}"
echo -e "${YELLOW}  - Check worker logs to verify different workers processed AI tasks${NC}"
echo -e "${YELLOW}  - Each AI task should take 5-30 seconds due to NEAR.ai API calls${NC}"
echo -e "${YELLOW}  - Monitor coordinator logs to see job distribution${NC}"
echo -e "${YELLOW}  - Used prompts:${NC}"
for i in $(seq 1 ${#AI_PROMPTS[@]}); do
    echo -e "${YELLOW}    ${i}. ${AI_PROMPTS[$((i-1))]}${NC}"
done
