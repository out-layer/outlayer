#!/usr/bin/env bash
#
# Build and push NEAR OutLayer Keystore Docker image for TEE/Phala deployment
#
# Usage:
#   ./scripts/build_and_push_keystore_tee.sh [dockerhub-username] [version]
#
# Examples:
#   ./scripts/build_and_push_keystore_tee.sh                # Uses defaults from env
#   ./scripts/build_and_push_keystore_tee.sh outlayer            # Company org, default version
#   ./scripts/build_and_push_keystore_tee.sh outlayer v0.1.42    # Company org and version
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration with defaults
DOCKERHUB_USER="${1:-${DOCKERHUB_USER:-zavodil}}"
VERSION="${2:-${VERSION:-latest}}"
IMAGE_NAME="near-outlayer-keystore"
FULL_IMAGE="${DOCKERHUB_USER}/${IMAGE_NAME}:${VERSION}"
LATEST_IMAGE="${DOCKERHUB_USER}/${IMAGE_NAME}:latest"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}🔐 Keystore TEE Build & Push${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo -e "  User:    ${GREEN}${DOCKERHUB_USER}${NC}"
echo -e "  Version: ${GREEN}${VERSION}${NC}"
echo -e "  Image:   ${GREEN}${FULL_IMAGE}${NC}"
echo ""

# Navigate to project root
cd "$(dirname "$0")/.."

# Step 1: Check Dockerfile exists
echo -e "${YELLOW}[1/5] Checking Dockerfile...${NC}"
DOCKERFILE="docker/Dockerfile.keystore-phala"

if [ ! -f "$DOCKERFILE" ]; then
    echo -e "${RED}Error: Dockerfile not found at $DOCKERFILE${NC}"
    echo "Please ensure docker/Dockerfile.keystore-phala exists"
    exit 1
fi
echo -e "${GREEN}✓ Using existing Dockerfile: $DOCKERFILE${NC}"

# Check if keystore-worker source exists
if [ ! -d "keystore-worker/src" ]; then
    echo -e "${RED}Error: keystore-worker/src directory not found${NC}"
    exit 1
fi

# Step 2: Build Docker image
echo -e "${YELLOW}[2/5] Building Docker image for TEE (linux/amd64)...${NC}"

# Enable BuildKit
export DOCKER_BUILDKIT=1

# Build with platform specified for Phala (amd64)
docker buildx build \
    --platform linux/amd64 \
    -f "$DOCKERFILE" \
    -t "${FULL_IMAGE}" \
    -t "${LATEST_IMAGE}" \
    --load \
    .

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Docker build failed${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ Build successful!${NC}"
echo ""

# Step 3: Quick startup test (non-TEE mode for local testing)
echo -e "${YELLOW}[3/5] Testing image locally (quick check)...${NC}"

# Create temporary test env file
TEST_ENV=$(mktemp)
cat > "$TEST_ENV" <<EOF
SERVER_HOST=0.0.0.0
SERVER_PORT=8081
NEAR_NETWORK=testnet
NEAR_RPC_URL=https://rpc.testnet.near.org
NEAR_CONTRACT_ID=outlayer.testnet
ALLOWED_WORKER_TOKEN_HASHES=54bf7eee4e92735c477cba4ea0004715d345613be1038b827b0447525afd7f6a
TEE_MODE=none
USE_TEE_REGISTRATION=false
KEYSTORE_MASTER_SECRET=test1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd
RUST_LOG=info
EOF

# Run container for 5 seconds to check it starts
timeout 5 docker run --rm --env-file "$TEST_ENV" "${FULL_IMAGE}" || true

# Check if container started successfully (exit code 124 = timeout, which is good)
if [ $? -eq 124 ]; then
    echo -e "${GREEN}✅ Container started successfully (stopped after 5s test)${NC}"
else
    echo -e "${YELLOW}Warning: Container may have crashed during startup${NC}"
    echo "Check logs above for errors"
fi

# Cleanup
rm -f "$TEST_ENV"
echo ""

# Step 4: Push to Docker Hub
echo -e "${YELLOW}[4/5] Pushing to Docker Hub...${NC}"
echo "This may take a few minutes..."

# Check if logged in to Docker Hub
if ! docker info | grep -q "Username"; then
    echo -e "${YELLOW}Not logged in to Docker Hub. Please login:${NC}"
    docker login
fi

# Push versioned tag
echo "Pushing ${FULL_IMAGE}..."
docker push "${FULL_IMAGE}"

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to push ${FULL_IMAGE}${NC}"
    exit 1
fi

# Also push as latest if version is not already "latest"
if [ "${VERSION}" != "latest" ]; then
    echo "Pushing ${LATEST_IMAGE}..."
    docker push "${LATEST_IMAGE}"

    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to push ${LATEST_IMAGE}${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}✅ Successfully pushed image to Docker Hub!${NC}"
echo ""

# Step 5: Generate deployment instructions
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}✅ Build & Push Complete!${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo "Image tags:"
echo "  - ${GREEN}${FULL_IMAGE}${NC}"
if [ "${VERSION}" != "latest" ]; then
    echo "  - ${GREEN}${LATEST_IMAGE}${NC}"
fi
echo ""
echo "Next steps:"
echo "1. Update docker/.env.testnet-keystore-phala:"
echo "   DOCKER_IMAGE_KEYSTORE=${FULL_IMAGE}"
echo ""
echo "2. Deploy to Phala Cloud:"
echo "   cd docker"
echo "   phala deploy --name outlayer-testnet-keystore \\"
echo "     --compose docker-compose.keystore-phala.yml \\"
echo "     --env-file .env.testnet-keystore-phala \\"
echo "     --vcpu 2 --memory 2G --disk-size 20G \\"
echo "     --kms-id phala-prod10"
echo ""
echo "3. Monitor deployment:"
echo "   phala logs outlayer-testnet-keystore --follow"
echo ""
echo "4. The DAO approves the build by vote (ApproveOsImage, ApproveCompose) and the members vote"
echo "   for the keystore's key: keystore-dao-contract/README.md, \"The build is approved once;"
echo "   every instance takes a vote\". scripts/deploy_tdx.sh does both on a TDX node."
echo ""