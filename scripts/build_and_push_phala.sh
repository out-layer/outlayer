#!/usr/bin/env bash
set -e

# Build and push NEAR OutLayer worker Docker image for Phala Cloud
#
# Usage:
#   ./scripts/build_and_push_phala.sh <dockerhub-username> <tag> [dockerfile]
#
# Examples:
#   ./scripts/build_and_push_phala.sh outlayer v0.1.42                   # Build worker-compiler (default)
#   ./scripts/build_and_push_phala.sh outlayer v0.1.42 worker-compiler   # Build worker-compiler explicitly
#   ./scripts/build_and_push_phala.sh outlayer v0.1.42 worker            # Build execution-only worker
#
# Push to the company org, and use a real version rather than `latest`: deploys resolve the
# digest from the matching GitHub release, and a floating tag has no release to resolve from.

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check arguments
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo -e "${RED}Error: Invalid arguments${NC}"
    echo "Usage: $0 <dockerhub-username> <tag> [dockerfile]"
    echo ""
    echo "Examples:"
    echo "  $0 zavodil latest                     # Build worker-compiler (default)"
    echo "  $0 zavodil v1.0.0 worker-compiler     # Build worker-compiler explicitly"
    echo "  $0 zavodil v1.0.0 worker              # Build execution-only worker"
    exit 1
fi

DOCKER_USERNAME=$1
TAG=$2
DOCKERFILE_TYPE="${3:-worker-compiler}"  # Default to worker-compiler

# Determine Docker file and image name
case "$DOCKERFILE_TYPE" in
    "worker-compiler")
        DOCKERFILE="docker/Dockerfile.compiler-worker"
        IMAGE_NAME="$DOCKER_USERNAME/near-outlayer-worker-compiler"
        ;;
    "worker")
        DOCKERFILE="docker/Dockerfile.worker-phala"
        IMAGE_NAME="$DOCKER_USERNAME/near-outlayer-worker"
        ;;
    *)
        echo -e "${RED}Error: Invalid dockerfile type: $DOCKERFILE_TYPE${NC}"
        echo "Valid types: worker-compiler, worker"
        exit 1
        ;;
esac

FULL_TAG="$IMAGE_NAME:$TAG"
LATEST_TAG="$IMAGE_NAME:latest"

echo -e "${GREEN}Building NEAR OutLayer Worker for Phala Cloud${NC}"
echo "Image: $FULL_TAG"
echo ""

# Navigate to project root
cd "$(dirname "$0")/.."

# Check if Dockerfile exists
if [ ! -f "$DOCKERFILE" ]; then
    echo -e "${RED}Error: $DOCKERFILE not found${NC}"
    exit 1
fi

echo -e "${GREEN}Building: $DOCKERFILE_TYPE${NC}"
echo "Dockerfile: $DOCKERFILE"
echo "Image: $FULL_TAG"
echo ""

# Check if worker source exists
if [ ! -d "worker/src" ]; then
    echo -e "${RED}Error: worker/src directory not found${NC}"
    exit 1
fi

# Build Docker image for AMD64 (Phala Cloud)
echo -e "${YELLOW}Step 1/3: Building Docker image for linux/amd64...${NC}"

# Enable BuildKit
export DOCKER_BUILDKIT=1

docker buildx build \
    --platform linux/amd64 \
    -f "$DOCKERFILE" \
    -t "$FULL_TAG" \
    -t "$LATEST_TAG" \
    --load \
    .

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Docker build failed${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ Build successful!${NC}"
echo ""

# Test image locally (optional)
echo -e "${YELLOW}Step 2/3: Testing image locally (quick check)...${NC}"

# Create temporary test env file
TEST_ENV=$(mktemp)
cat > "$TEST_ENV" << EOF
API_BASE_URL=http://test-coordinator.com
API_AUTH_TOKEN=test-token
NEAR_RPC_URL=https://rpc.testnet.near.org
OFFCHAINVM_CONTRACT_ID=outlayer.testnet
OPERATOR_ACCOUNT_ID=worker.outlayer.testnet
OPERATOR_PRIVATE_KEY=ed25519:3D4YudUahN1HNj8EFaP7M9zQcL6oBXCVbFzQbZBdQPdx7qfpj1QbP8J6X6qH8F9RqZQF8vN9hKm5PxDqV1PxJ4R8
TEE_MODE=none
COMPILATION_ENABLED=false
EXECUTION_ENABLED=true
RUST_LOG=info
ENABLE_EVENT_MONITOR=false
EOF

# Run container for 5 seconds to check it starts
timeout 5 docker run --rm --env-file "$TEST_ENV" "$FULL_TAG" || true

# Check if container started successfully (exit code 124 = timeout, which is good)
if [ $? -eq 124 ]; then
    echo -e "${GREEN}✅ Container started successfully (stopped after 5s test)${NC}"
else
    echo -e "${RED}Warning: Container may have crashed during startup${NC}"
    echo "Check logs above for errors"
fi

# Cleanup
rm -f "$TEST_ENV"
echo ""

# Push to Docker Hub
echo -e "${YELLOW}Step 3/3: Pushing to Docker Hub...${NC}"
echo "This may take a few minutes..."

# Check if logged in to Docker Hub
if ! docker info | grep -q "Username"; then
    echo -e "${YELLOW}Not logged in to Docker Hub. Please login:${NC}"
    docker login
fi

# Push versioned tag
echo "Pushing $FULL_TAG..."
docker push "$FULL_TAG"

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to push $FULL_TAG${NC}"
    exit 1
fi

# Push latest tag
echo "Pushing $LATEST_TAG..."
docker push "$LATEST_TAG"

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to push $LATEST_TAG${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ Successfully pushed image to Docker Hub!${NC}"
echo ""
echo "Image tags:"
echo "  - $FULL_TAG"
echo "  - $LATEST_TAG"
echo ""
echo "Next steps:"
echo "1. Update docker/.env.phala:"
echo "   DOCKER_IMAGE_WORKER=$FULL_TAG"
echo ""
echo "2. Deploy to Phala Cloud:"
echo "   cd docker"
echo "   phala cvms create --name near-outlayer-worker \\"
echo "     --compose ./docker-compose.phala.yml \\"
echo "     --env-file ./.env.phala \\"
echo "     --vcpu 2 --memory 4096 --disk-size 60"
echo ""
echo "3. Monitor deployment:"
echo "   phala cvms status near-outlayer-worker"
echo "   phala cvms logs near-outlayer-worker --follow"
echo ""
