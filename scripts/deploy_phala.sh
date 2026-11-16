#!/usr/bin/env bash
#
# Automated deployment to Phala Cloud with TEE measurements whitelisting and DAO voting
#
# Usage:
#   ./scripts/deploy_phala.sh keystore [testnet|mainnet] [instance-name] --version vX.Y.Z
#   ./scripts/deploy_phala.sh worker [testnet|mainnet] [instance-name] --version vX.Y.Z
#
# Options:
#   --version     REQUIRED. Version to deploy; the digest is fetched from the GitHub
#                 release and is Sigstore-attested.
#   --no-build    Skip local Docker build (use image from docker-compose)
#   --dry-run     Only show digest and verification command, don't deploy
#   --region      Deploy to specific region (e.g., us-west, eu-central)
#
# Examples:
#   ./scripts/deploy_phala.sh worker testnet --version v0.1.1              # deploy specific version
#   ./scripts/deploy_phala.sh worker testnet --version v0.1.1 --dry-run    # show digest only
#   ./scripts/deploy_phala.sh worker mainnet worker3 --version v1.0.0
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Docker Hub org
DOCKERHUB_ORG="outlayer"

# Parse arguments
SKIP_BUILD=false
DEPLOY_VERSION=""
DRY_RUN=false
REGION=""
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-build)
            SKIP_BUILD=true
            shift
            ;;
        --version)
            DEPLOY_VERSION="$2"
            SKIP_BUILD=true
            shift 2
            ;;
        --dry-run|--info)
            DRY_RUN=true
            shift
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Check positional arguments
if [ "${#POSITIONAL_ARGS[@]}" -lt 1 ] || [ "${#POSITIONAL_ARGS[@]}" -gt 3 ]; then
    echo -e "${RED}Usage: $0 <keystore|worker> [testnet|mainnet] [instance-name] [--version vX.Y.Z]${NC}"
    exit 1
fi

COMPONENT="${POSITIONAL_ARGS[0]}"
NETWORK="${POSITIONAL_ARGS[1]:-testnet}"
INSTANCE_NAME="${POSITIONAL_ARGS[2]:-}"

# Set account suffix based on network
if [ "$NETWORK" = "mainnet" ]; then
    ACCOUNT_SUFFIX="near"
else
    ACCOUNT_SUFFIX="testnet"
fi

# Validate component
if [[ "$COMPONENT" != "keystore" && "$COMPONENT" != "worker" ]]; then
    echo -e "${RED}Error: Component must be 'keystore' or 'worker'${NC}"
    exit 1
fi

# --version is required.
#
# Without it the script used to fall through to building and pushing an image locally, or to
# whatever the compose file happened to reference. Both paths deploy something that was never
# resolved from a release and never Sigstore-attested — and the resulting measurement is what
# the DAO is then asked to approve. Passing a version is what makes the deployed image
# verifiable, so it is not optional.
if [ -z "$DEPLOY_VERSION" ]; then
    echo -e "${RED}Error: --version is required (e.g. --version 0.1.42)${NC}"
    echo "  The digest is resolved from the GitHub release and verified via Sigstore."
    echo "  Verify independently with:"
    echo "    gh attestation verify oci://docker.io/${DOCKERHUB_ORG}/near-outlayer-${COMPONENT}@<digest> -R out-layer/outlayer   (releases <= v0.1.58: --owner fastnear)"
    exit 1
fi

# Configuration based on component and network
case "$COMPONENT" in
    keystore)
        KEYSTORE_SUFFIX="${INSTANCE_NAME:-keystore}"
        CVM_NAME="outlayer-${NETWORK}-${KEYSTORE_SUFFIX}"
        COMPOSE_FILE="docker-compose.keystore-phala.yml"
        ENV_FILE=".env.${NETWORK}-keystore-phala"
        DAO_CONTRACT="dao.outlayer.${ACCOUNT_SUFFIX}"
        SIGNER_ACCOUNT="owner.outlayer.${ACCOUNT_SUFFIX}"
        VOTER_ACCOUNT="zavodil.${ACCOUNT_SUFFIX}"
        BUILD_SCRIPT="./scripts/build_and_push_keystore_tee.sh"
        BUILD_ARGS="zavodil latest"
        ;;
    worker)
        WORKER_SUFFIX="${INSTANCE_NAME:-worker}"
        CVM_NAME="outlayer-${NETWORK}-${WORKER_SUFFIX}"
        COMPOSE_FILE="docker-compose.phala.yml"
        ENV_FILE=".env.${NETWORK}-worker-phala"
        DAO_CONTRACT="worker.outlayer.${ACCOUNT_SUFFIX}"
        SIGNER_ACCOUNT="owner.outlayer.${ACCOUNT_SUFFIX}"
        VOTER_ACCOUNT="zavodil.${ACCOUNT_SUFFIX}"
        BUILD_SCRIPT="./scripts/build_and_push_phala.sh"
        BUILD_ARGS="zavodil latest worker"
        ;;
esac


cd "$(dirname "$0")/.."

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}🚀 Phala Deployment: ${COMPONENT} (${NETWORK})${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Step 1: Prepare Docker image
COMPOSE_MODIFIED=false
ORIGINAL_IMAGE_LINE=""

# Cleanup function to restore docker-compose (must be set BEFORE any modifications)
cleanup() {
    if [ "$COMPOSE_MODIFIED" = true ] && [ -f "docker/${COMPOSE_FILE}.bak" ]; then
        mv "docker/${COMPOSE_FILE}.bak" "docker/$COMPOSE_FILE"
        echo -e "${GREEN}✓ Restored original $COMPOSE_FILE${NC}"
    fi
}
trap cleanup EXIT INT TERM

if [ -n "$DEPLOY_VERSION" ]; then
    # Fetch digest from GitHub Release (verified by Sigstore)
    echo -e "${YELLOW}[1/7] Fetching digest for version $DEPLOY_VERSION from GitHub...${NC}"

    if [ "$COMPONENT" = "worker" ]; then
        IMAGE_NAME="${DOCKERHUB_ORG}/near-outlayer-worker"
    else
        IMAGE_NAME="${DOCKERHUB_ORG}/near-outlayer-keystore"
    fi

    # Normalize version (add 'v' prefix if missing)
    VERSION_TAG="$DEPLOY_VERSION"
    if [[ ! "$VERSION_TAG" =~ ^v ]]; then
        VERSION_TAG="v${VERSION_TAG}"
    fi

    # Get digest from GitHub release body (format: "| worker | `sha256:...` |" or "| keystore | `sha256:...` |")
    RELEASE_BODY=$(gh release view "$VERSION_TAG" --repo out-layer/outlayer --json body -q '.body' 2>/dev/null || echo "")

    if [ -z "$RELEASE_BODY" ]; then
        echo -e "${RED}Error: Could not fetch GitHub release $VERSION_TAG${NC}"
        echo "Make sure the release exists: https://github.com/out-layer/outlayer/releases/tag/$VERSION_TAG"
        exit 1
    fi

    # Extract digest for this component from release body
    DIGEST=$(echo "$RELEASE_BODY" | grep -i "| $COMPONENT " | grep -oE 'sha256:[a-f0-9]{64}' | head -1 || echo "")

    if [ -z "$DIGEST" ]; then
        echo -e "${RED}Error: Could not find digest for '$COMPONENT' in release $VERSION_TAG${NC}"
        echo "Release body:"
        echo "$RELEASE_BODY" | head -20
        exit 1
    fi

    echo -e "${GREEN}✓ Found digest: ${DIGEST}${NC}"

    # Show attestation verification command
    echo ""
    echo -e "${BLUE}Verify attestation with:${NC}"
    echo "  gh attestation verify oci://docker.io/${IMAGE_NAME}@${DIGEST} -R out-layer/outlayer   (releases <= v0.1.58: --owner fastnear)"
    echo ""
    echo -e "${BLUE}Docker image reference:${NC}"
    echo "  docker.io/${IMAGE_NAME}@${DIGEST}"
    echo ""

    # Exit early if dry-run
    if [ "$DRY_RUN" = true ]; then
        echo -e "${GREEN}Dry run complete. No deployment performed.${NC}"
        exit 0
    fi

    # Backup original image line and update docker-compose temporarily
    COMPOSE_PATH="docker/$COMPOSE_FILE"
    ORIGINAL_IMAGE_LINE=$(grep "image:" "$COMPOSE_PATH" | head -1)
    NEW_IMAGE="docker.io/${IMAGE_NAME}@${DIGEST}"

    # Update docker-compose with digest
    sed -i.bak "s|image:.*|image: ${NEW_IMAGE}|" "$COMPOSE_PATH"
    COMPOSE_MODIFIED=true

    echo -e "${GREEN}✓ Updated $COMPOSE_FILE with verified image${NC}"

elif [ "$SKIP_BUILD" = false ] && grep -q "@sha256:" "docker/$COMPOSE_FILE" 2>/dev/null; then
    echo -e "${YELLOW}[1/7] Skipping build (docker-compose uses @sha256: digest)${NC}"
    echo -e "${GREEN}✓ Using verified image from $COMPOSE_FILE${NC}"
elif [ "$SKIP_BUILD" = true ]; then
    echo -e "${YELLOW}[1/7] Skipping build (--no-build flag)${NC}"
    echo -e "${GREEN}✓ Using pre-built image${NC}"
else
    echo -e "${YELLOW}[1/7] Building and pushing Docker image...${NC}"
    $BUILD_SCRIPT $BUILD_ARGS
fi

# Step 2: Clear phala config (required for new deployments)
echo -e "${YELLOW}[2/7] Clearing Phala config...${NC}"
PHALA_CONFIG="docker/.phala/config"
if [ -f "$PHALA_CONFIG" ]; then
    echo "{}" > "$PHALA_CONFIG"
    echo -e "${GREEN}✓ Cleared $PHALA_CONFIG${NC}"
else
    mkdir -p docker/.phala
    echo "{}" > "$PHALA_CONFIG"
    echo -e "${GREEN}✓ Created empty $PHALA_CONFIG${NC}"
fi

# Step 3: Check if CVM already exists
echo -e "${YELLOW}[3/7] Checking existing CVM...${NC}"
if phala cvms get "$CVM_NAME" --json 2>/dev/null | jq -e '.success' > /dev/null 2>&1; then
    echo -e "${RED}Error: CVM '$CVM_NAME' already exists${NC}"
    echo ""
    echo "To update an existing CVM, delete it first:"
    echo "  phala cvms delete $CVM_NAME --yes"
    echo ""
    echo "Or use a different instance name:"
    echo "  $0 $COMPONENT $NETWORK <new-instance-name> ${DEPLOY_VERSION:+--version $DEPLOY_VERSION}"
    exit 1
else
    echo -e "${GREEN}✓ No existing CVM found${NC}"
fi

# Step 4: Deploy to Phala
echo -e "${YELLOW}[4/7] Deploying to Phala Cloud...${NC}"
cd docker

DEPLOY_CMD=(phala deploy \
    --name "$CVM_NAME" \
    --compose "$COMPOSE_FILE" \
    -e "$ENV_FILE" \
    --vcpu 2 \
    --memory 2G \
    --disk-size 1G \
    --image dstack-0.5.4 \
    --kms-id phala-prod10)

if [ -n "$REGION" ]; then
    DEPLOY_CMD+=(--region "$REGION")
fi

"${DEPLOY_CMD[@]}"

cd ..
echo -e "${GREEN}✓ Deployment initiated${NC}"

# Step 5: Wait for CVM to be running and get TEE measurements
echo -e "${YELLOW}[5/7] Waiting for CVM to start and getting TEE measurements...${NC}"

MAX_ATTEMPTS=60
ATTEMPT=0
MRTD=""
RTMR0=""
RTMR1=""
RTMR2=""
RTMR3=""

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    ATTEMPT=$((ATTEMPT + 1))
    echo -n "."

    # Check if CVM is running
    STATUS=$(phala cvms get "$CVM_NAME" --json 2>/dev/null | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")

    if [ "$STATUS" = "running" ]; then
        echo ""
        echo -e "${GREEN}✓ CVM is running${NC}"

        # Get attestation with all measurements
        sleep 10  # Wait for attestation to be ready
        # Write to temp file: attestation JSON is ~55KB with embedded docker-compose,
        # echo "$VAR" | jq corrupts escape sequences in app_compose field
        ATTESTATION_TMP=$(mktemp)
        phala cvms attestation "$CVM_NAME" --json > "$ATTESTATION_TMP" 2>/dev/null || true

        if [ -s "$ATTESTATION_TMP" ]; then
            MRTD=$(jq -r '.tcb_info.mrtd // empty' "$ATTESTATION_TMP" 2>/dev/null || echo "")
            RTMR0=$(jq -r '.tcb_info.rtmr0 // empty' "$ATTESTATION_TMP" 2>/dev/null || echo "")
            RTMR1=$(jq -r '.tcb_info.rtmr1 // empty' "$ATTESTATION_TMP" 2>/dev/null || echo "")
            RTMR2=$(jq -r '.tcb_info.rtmr2 // empty' "$ATTESTATION_TMP" 2>/dev/null || echo "")
            RTMR3=$(jq -r '.tcb_info.rtmr3 // empty' "$ATTESTATION_TMP" 2>/dev/null || echo "")
        fi
        rm -f "$ATTESTATION_TMP"

        if [ -n "$MRTD" ] && [ -n "$RTMR3" ]; then
            echo -e "${GREEN}✓ Got TEE measurements:${NC}"
            echo -e "   MRTD:  ${MRTD}"
            echo -e "   RTMR0: ${RTMR0}"
            echo -e "   RTMR1: ${RTMR1}"
            echo -e "   RTMR2: ${RTMR2}"
            echo -e "   RTMR3: ${RTMR3}"
            break
        fi
    fi

    sleep 5
done

if [ -z "$RTMR3" ]; then
    echo ""
    echo -e "${RED}Error: Failed to get TEE measurements after $MAX_ATTEMPTS attempts${NC}"
    exit 1
fi

# Step 6: Add TEE measurements to contract (if not already approved)
echo -e "${YELLOW}[6/7] Checking if TEE measurements are already approved...${NC}"

MEASUREMENTS_APPROVED=$(near contract call-function as-read-only "$DAO_CONTRACT" is_measurements_approved \
    json-args "{\"measurements\": {\"mrtd\": \"$MRTD\", \"rtmr0\": \"$RTMR0\", \"rtmr1\": \"$RTMR1\", \"rtmr2\": \"$RTMR2\", \"rtmr3\": \"$RTMR3\"}}" \
    network-config "$NETWORK" now 2>/dev/null | grep -o 'true\|false' | head -1 || echo "false")

if [ "$MEASUREMENTS_APPROVED" = "true" ]; then
    echo -e "${GREEN}✓ Measurements already approved, skipping${NC}"
else
    echo -e "${YELLOW}Measurements not approved, adding to contract...${NC}"

    # If this is an additional instance (has INSTANCE_NAME), don't clear others
    if [ -n "$INSTANCE_NAME" ]; then
        CLEAR_OTHERS="false"
    else
        CLEAR_OTHERS="true"
    fi

    near contract call-function as-transaction "$DAO_CONTRACT" add_approved_measurements \
        json-args "{\"measurements\": {\"mrtd\": \"$MRTD\", \"rtmr0\": \"$RTMR0\", \"rtmr1\": \"$RTMR1\", \"rtmr2\": \"$RTMR2\", \"rtmr3\": \"$RTMR3\"}, \"clear_others\": $CLEAR_OTHERS}" \
        prepaid-gas '30.0 Tgas' \
        attached-deposit '0 NEAR' \
        sign-as "$SIGNER_ACCOUNT" \
        network-config "$NETWORK" \
        sign-with-keychain send

    echo -e "${GREEN}✓ Measurements added to contract${NC}"
fi

# Step 7: Restart CVM (and wait for proposal if keystore)
echo -e "${YELLOW}[7/7] Restarting CVM...${NC}"

phala cvms restart "$CVM_NAME"

# For keystore: wait for proposal and vote
if [ "$COMPONENT" = "keystore" ]; then
    echo "Waiting for CVM to restart and create proposal..."
    sleep 30

    # Get proposal ID from logs
    MAX_LOG_ATTEMPTS=30
    LOG_ATTEMPT=0
    PROPOSAL_ID=""

    while [ $LOG_ATTEMPT -lt $MAX_LOG_ATTEMPTS ]; do
        LOG_ATTEMPT=$((LOG_ATTEMPT + 1))
        echo -n "."

        RAW_LOGS=$(phala cvms logs "$CVM_NAME" --tail 200 2>/dev/null || echo "")

        # Try plain text first (logs may come as plain text with timestamps)
        PROPOSAL_ID=$(echo "$RAW_LOGS" | grep -o 'Proposal ID: [0-9]*' | sed 's/Proposal ID: //' | tail -1 || echo "")

        # Fallback: try JSON with base64-encoded messages
        if [ -z "$PROPOSAL_ID" ]; then
            PROPOSAL_ID=$(echo "$RAW_LOGS" | jq -r '.message // empty' 2>/dev/null | \
                base64 -d 2>/dev/null | \
                grep -o 'Proposal ID: [0-9]*' | sed 's/Proposal ID: //' | tail -1 || echo "")
        fi

        # The key this boot registered: a vote for the registration names it.
        LIVE_KEY=$(echo "$RAW_LOGS" | grep -oE 'Using keystore public key: [a-z0-9-]+:[A-Za-z0-9]+' | tail -1 | sed 's/.*: //' || echo "")
        if [ -z "$LIVE_KEY" ]; then
            LIVE_KEY=$(echo "$RAW_LOGS" | jq -r '.message // empty' 2>/dev/null | base64 -d 2>/dev/null | \
                grep -oE 'Using keystore public key: [a-z0-9-]+:[A-Za-z0-9]+' | tail -1 | sed 's/.*: //' || echo "")
        fi

        if [ -n "$PROPOSAL_ID" ] && [ -n "$LIVE_KEY" ]; then
            echo ""
            echo -e "${GREEN}✓ Found Proposal ID: ${PROPOSAL_ID} (key ${LIVE_KEY})${NC}"
            break
        fi

        sleep 5
    done

    if [ -z "$PROPOSAL_ID" ] || [ -z "${LIVE_KEY:-}" ]; then
        echo ""
        echo -e "${RED}Error: Could not find the proposal ID and the keystore's public key in logs${NC}"
        echo -e "${YELLOW}Check logs manually: phala cvms logs $CVM_NAME${NC}"
        exit 1
    fi

    # Auto-vote on testnet, manual vote on mainnet
    if [ "$NETWORK" = "mainnet" ]; then
        echo -e "${YELLOW}Mainnet deployment - manual vote required${NC}"
        echo -e "Run this to approve proposal #${PROPOSAL_ID}:"
        echo ""
        echo "  near contract call-function as-transaction $DAO_CONTRACT vote \\"
        echo "    json-args '{\"proposal_id\": $PROPOSAL_ID, \"approve\": true, \"public_key\": \"$LIVE_KEY\"}' \\"
        echo "    prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \\"
        echo "    sign-as $VOTER_ACCOUNT network-config $NETWORK sign-with-keychain send"
        echo ""
    else
        echo -e "${YELLOW}Voting on proposal #${PROPOSAL_ID}...${NC}"

        near contract call-function as-transaction "$DAO_CONTRACT" vote \
            json-args "{\"proposal_id\": $PROPOSAL_ID, \"approve\": true, \"public_key\": \"$LIVE_KEY\"}" \
            prepaid-gas '100.0 Tgas' \
            attached-deposit '0 NEAR' \
            sign-as "$VOTER_ACCOUNT" \
            network-config "$NETWORK" \
            sign-with-keychain send

        echo -e "${GREEN}✓ Voted on proposal #${PROPOSAL_ID}${NC}"
    fi
else
    echo -e "${GREEN}✓ CVM restarted (no proposal needed for worker)${NC}"
fi

# Wait for CVM to come back to "running" after restart, then fetch identifiers.
# instance_id is empty while the CVM is restarting, so we poll for up to ~60s.
APP_ID=""
INSTANCE_ID=""
GATEWAY_DOMAIN=""
DAPP_URL=""
for _ in $(seq 1 30); do
    CVM_DETAILS=$(phala cvms get "$CVM_NAME" --json 2>/dev/null || echo "{}")
    POST_STATUS=$(echo "$CVM_DETAILS" | jq -r '.status // empty')
    APP_ID=$(echo "$CVM_DETAILS" | jq -r '.app_id // empty')
    INSTANCE_ID=$(echo "$CVM_DETAILS" | jq -r '.instance_id // empty')
    GATEWAY_DOMAIN=$(echo "$CVM_DETAILS" | jq -r '.gateway_domain // empty')
    DAPP_URL=$(echo "$CVM_DETAILS" | jq -r '.dapp_dashboard_url // empty')
    if [ "$POST_STATUS" = "running" ] && [ -n "$INSTANCE_ID" ]; then
        break
    fi
    sleep 2
done
# Extract cluster (e.g. dstack-pha-prod5) by stripping trailing .phala.network
CLUSTER="${GATEWAY_DOMAIN%.phala.network}"

# Done
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}✅ Deployment Complete!${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo -e "CVM Name:    ${GREEN}${CVM_NAME}${NC}"
echo -e "App ID:      ${GREEN}${APP_ID}${NC}"
echo -e "Instance ID: ${GREEN}${INSTANCE_ID}${NC}"
echo -e "Cluster:     ${GREEN}${CLUSTER}${NC}"
echo -e "Worker URL:  ${GREEN}${DAPP_URL}${NC}"
echo -e "MRTD:     ${GREEN}${MRTD}${NC}"
echo -e "RTMR0:    ${GREEN}${RTMR0}${NC}"
echo -e "RTMR1:    ${GREEN}${RTMR1}${NC}"
echo -e "RTMR2:    ${GREEN}${RTMR2}${NC}"
echo -e "RTMR3:    ${GREEN}${RTMR3}${NC}"
if [ "$COMPONENT" = "keystore" ]; then
    echo -e "Proposal: ${GREEN}${PROPOSAL_ID}${NC}"
fi
echo ""
echo "Monitor logs:"
echo "  phala cvms logs $CVM_NAME --follow"
echo ""
echo "Get CVM details:"
echo "  phala cvms get $CVM_NAME"
echo ""
