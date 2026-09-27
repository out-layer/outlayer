#!/bin/bash

# Parallel Execution Test
# Tests that multiple workers can handle concurrent AI tasks
# Usage: ./parallel_execution.sh [NUM_TASKS]

set -e

# Configuration
NUM_TASKS=${1:-5}  # Default: 5 parallel tasks
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
USER_ACCOUNT="${USER_ACCOUNT:-zavodil.testnet}"
GITHUB_REPO="https://github.com/out-layer/echo-example"
GITHUB_COMMIT="main"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Parallel Execution Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${YELLOW}Number of parallel tasks: ${NUM_TASKS}${NC}"
echo -e "${YELLOW}Contract: ${CONTRACT_ID}${NC}"
echo -e "${YELLOW}User: ${USER_ACCOUNT}${NC}"
echo ""

# Function to submit a single execution request
submit_task() {
    local task_num=$1
    local input_data="{\\\"message\\\":\\\"Task ${task_num} - $(date +%s)\\\"}"

    echo -e "${BLUE}[Task ${task_num}] Submitting execution request...${NC}"

    # Call contract
    local output=$(near contract call-function as-transaction "$CONTRACT_ID" request_execution json-args "{
        \"source\": {
            \"GitHub\": {
                \"repo\": \"$GITHUB_REPO\",
                \"commit\": \"$GITHUB_COMMIT\",
                \"build_target\": \"wasm32-wasip1\"
            }
        },
        \"resource_limits\": {
            \"max_instructions\": 1000000000,
            \"max_memory_mb\": 128,
            \"max_execution_seconds\": 60
        },
        \"input_data\": \"$input_data\"
    }" prepaid-gas '300.0 Tgas' attached-deposit '0.1 NEAR' sign-as "$USER_ACCOUNT" network-config testnet sign-with-keychain send 2>&1)

    echo $output

    # Extract transaction hash
    local tx_hash=$(echo "$output" | grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{43,44}' | awk '{print $NF}' | head -1)

    if [ -n "$tx_hash" ]; then
        echo -e "${GREEN}[Task ${task_num}] ✓ Submitted successfully${NC}"
        echo -e "${GREEN}[Task ${task_num}] TX: ${tx_hash}${NC}"
        echo "$tx_hash" > "/tmp/offchainvm_task_${task_num}.tx"
    else
        echo -e "${RED}[Task ${task_num}] ✗ Failed to submit${NC}"
        return 1
    fi
}

# Submit all tasks in parallel
echo -e "${YELLOW}Submitting ${NUM_TASKS} tasks in parallel...${NC}"
echo ""

pids=()
for i in $(seq 1 $NUM_TASKS); do
    submit_task $i &
    pids+=($!)
    sleep 0.5  # Small delay to avoid rate limiting
done

# Wait for all submissions to complete
echo ""
echo -e "${YELLOW}Waiting for all submissions to complete...${NC}"
for pid in "${pids[@]}"; do
    wait $pid
done

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All ${NUM_TASKS} tasks submitted!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Monitor job distribution across workers
echo -e "${YELLOW}Monitoring job distribution...${NC}"
echo ""

sleep 5  # Give workers time to pick up tasks

echo -e "${BLUE}Checking coordinator for job distribution:${NC}"
curl -s "${COORDINATOR_URL:-http://localhost:8080}/public/jobs?limit=50" | python3 -c "
import sys
import json
from collections import Counter

data = json.load(sys.stdin)
workers = Counter(job['worker_id'] for job in data if job.get('worker_id'))

print('\nWorker distribution:')
for worker, count in workers.most_common():
    print(f'  {worker}: {count} jobs')

if len(workers) > 1:
    print(f'\n✓ Tasks distributed across {len(workers)} workers')
else:
    print(f'\n⚠ All tasks handled by {len(workers)} worker(s)')
"

echo ""
echo -e "${BLUE}Transaction hashes:${NC}"
for i in $(seq 1 $NUM_TASKS); do
    if [ -f "/tmp/offchainvm_task_${i}.tx" ]; then
        tx=$(cat "/tmp/offchainvm_task_${i}.tx")
        echo -e "  Task ${i}: https://testnet.nearblocks.io/txns/${tx}"
        rm "/tmp/offchainvm_task_${i}.tx"
    fi
done

echo ""
echo -e "${GREEN}✓ Parallel execution test completed${NC}"
echo -e "${YELLOW}Note: Check worker logs to verify different workers processed the tasks${NC}"
