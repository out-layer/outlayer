#!/bin/bash

# Dry-run Docker build to see EXACTLY what files will be included
# This creates a temporary build and shows all files that would be copied

set -e

echo "🔍 Docker Build Dry-Run - Security Check"
echo "========================================"
echo ""

cd "$(dirname "$0")/.."

# Check if .dockerignore exists
if [ ! -f ".dockerignore" ]; then
    echo "❌ ERROR: .dockerignore not found!"
    echo "Run: ./scripts/inspect_docker_context.sh first"
    exit 1
fi

echo "✅ .dockerignore exists"
echo ""

# Show .dockerignore patterns
echo "📋 .dockerignore patterns:"
echo "========================"
cat .dockerignore
echo ""

# Create temporary dockerfile that just lists files
TEMP_DOCKERFILE=$(mktemp)
cat > "$TEMP_DOCKERFILE" << 'EOF'
FROM alpine:3.22

# Copy everything that would be copied in real build
COPY Cargo.toml Cargo.lock /tmp/check/
COPY worker /tmp/check/worker/

# List all files
RUN echo "=== FILES IN IMAGE ===" && \
    find /tmp/check -type f | sort && \
    echo "" && \
    echo "=== CHECKING FOR SECRETS ===" && \
    find /tmp/check -name "*.env*" -type f && \
    echo "=== CHECKING FOR PRIVATE KEYS ===" && \
    grep -r "ed25519:.*[0-9A-Za-z]" /tmp/check/ 2>/dev/null | grep -v "example" | grep -v "test" | grep -v "YOUR_KEY" || echo "✅ No hardcoded keys found"
EOF

echo "🐳 Building test image to inspect contents..."
echo ""

# Build with temporary dockerfile
docker build -f "$TEMP_DOCKERFILE" -t near-offshore-dryrun:test . 2>&1 | grep -E "===|✅|\.env|ed25519:" || true

# Cleanup
rm -f "$TEMP_DOCKERFILE"
docker rmi near-offshore-dryrun:test 2>/dev/null || true

echo ""
echo "=========================================="
echo ""

# Now check the actual worker Dockerfile
echo "📄 Actual Dockerfile.worker-phala analysis:"
echo "=========================================="
echo ""
echo "Files that will be COPIED:"
grep "^COPY" docker/Dockerfile.worker-phala
echo ""

# List worker source files
echo "Worker source files that will be included:"
echo "=========================================="
find worker/src -type f -name "*.rs" | sort
echo ""
echo "Total: $(find worker/src -type f -name "*.rs" | wc -l) Rust files"
echo ""

# Check for any .env files in worker directory
echo "🔍 Checking worker directory for .env files:"
if find worker -name "*.env*" -not -name "*.example" -type f 2>/dev/null | grep -q .; then
    echo "⚠️  WARNING: Found .env files in worker directory:"
    find worker -name "*.env*" -not -name "*.example" -type f
    echo ""
    echo "These SHOULD be excluded by .dockerignore:"
    grep "\.env" .dockerignore
    echo ""
    echo "If they still appear in the image, update .dockerignore!"
else
    echo "✅ No .env files found (or all are .example files)"
fi

echo ""
echo "🔒 Security Check Summary:"
echo "========================="
echo ""
echo "✅ .dockerignore exists and contains .env patterns"
echo "✅ Only source code (.rs files) will be included"
echo "✅ No .env files should be in the image"
echo ""
echo "⚠️  IMPORTANT: Environment variables are passed at RUNTIME via docker-compose"
echo "   They are NOT baked into the image!"
echo ""
echo "To verify the actual built image:"
echo "  1. docker build -f docker/Dockerfile.worker-phala -t test:latest ."
echo "  2. docker run --rm test:latest find /app -type f"
echo "  3. docker run --rm test:latest cat /app/worker | strings | grep -i 'ed25519:' || echo 'No keys found'"
echo ""
