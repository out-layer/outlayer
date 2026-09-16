# Docker Configurations

Docker images for NEAR OutLayer components.

## Production Releases

See [DOCKER_RELEASE.md](./DOCKER_RELEASE.md) for building verified Docker images with Sigstore attestation.

## Files

- **Dockerfile.coordinator** - Production image for Coordinator API
- **Dockerfile.worker** - Production image for Worker
- **Dockerfile.wasmedge-compiler** - The image user code is compiled in. It fixes
  the toolchain, and with it the bytes: the same commit compiles to the same
  wasm only for a given image, so deployments pin it by digest
  (`DOCKER_IMAGE=outlayer/wasmedge-compiler@sha256:…`)
- **Dockerfile.compiler-worker** - Worker with the rust toolchain built in, for
  compiling without a docker socket (`COMPILATION_MODE=native`)

## Building Images

### Coordinator

```bash
cd coordinator
docker build -f ../docker/Dockerfile.coordinator -t offchainvm-coordinator:latest .
```

### Worker

```bash
cd worker
docker build -f ../docker/Dockerfile.worker -t offchainvm-worker:latest .
```

### Compiler (for worker to use)

```bash
docker build -f docker/Dockerfile.wasmedge-compiler -t outlayer/wasmedge-compiler:rust1.85-wasi25 .
```

See [BUILD.md](BUILD.md) for the digest to pin, and
`scripts/build_github_wasm.sh` for computing a project's wasm hash in this same
image before publishing it.

## Running with Docker Compose

### Development Mode

```bash
# Start PostgreSQL + Redis + Coordinator
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f coordinator

# Stop all services
docker-compose down
```

### Production Mode

Edit `docker-compose.yml` and set:
```yaml
environment:
  REQUIRE_AUTH: "true"
  RUST_LOG: offchainvm_coordinator=info
```

Then:
```bash
docker-compose up -d
```

## Environment Variables

### Coordinator

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Bind address | `0.0.0.0` |
| `PORT` | HTTP port | `8080` |
| `DATABASE_URL` | PostgreSQL connection | Required |
| `REDIS_URL` | Redis connection | Required |
| `WASM_CACHE_DIR` | WASM cache directory | `/var/offchainvm/wasm` |
| `REQUIRE_AUTH` | Enable auth | `false` |
| `RUST_LOG` | Logging level | `info` |

### Worker

| Variable | Description | Required |
|----------|-------------|----------|
| `API_BASE_URL` | Coordinator URL | ✅ |
| `API_AUTH_TOKEN` | Auth token | ✅ |
| `NEAR_RPC_URL` | NEAR RPC endpoint | ✅ |
| `OFFCHAINVM_CONTRACT_ID` | Contract ID | ✅ |
| `OPERATOR_ACCOUNT_ID` | Operator account | ✅ |
| `OPERATOR_PRIVATE_KEY` | Private key | ✅ |
| `WORKER_ID` | Worker identifier | Auto-generated |
| `ENABLE_EVENT_MONITOR` | Monitor events | `false` |

## Docker Compose Services

### postgres

PostgreSQL 14 database for coordinator metadata.

**Ports:** 5432
**Volume:** `postgres_data`

### redis

Redis 7 for task queue and locks.

**Ports:** 6379
**Volume:** `redis_data`

### coordinator

Coordinator API server.

**Ports:** 8080
**Volume:** `wasm_cache`
**Depends on:** postgres, redis

## Volumes

- `postgres_data` - PostgreSQL data persistence
- `redis_data` - Redis data persistence
- `wasm_cache` - Compiled WASM binaries cache

## Health Checks

All services include health checks:

```bash
# Check coordinator health
curl http://localhost:8080/health

# Check PostgreSQL
docker exec offchainvm-postgres pg_isready -U postgres

# Check Redis
docker exec offchainvm-redis redis-cli ping
```

## Troubleshooting

### Coordinator won't start

```bash
# Check logs
docker-compose logs coordinator

# Common issues:
# 1. Database migration failed
docker-compose exec coordinator /app/coordinator migrate

# 2. Permission issues with WASM cache
docker-compose exec coordinator ls -la /var/offchainvm/wasm
```

### Database connection errors

```bash
# Verify PostgreSQL is running
docker-compose ps postgres

# Test connection
docker-compose exec postgres psql -U postgres -d offchainvm -c "SELECT 1;"
```

### Redis connection errors

```bash
# Verify Redis is running
docker-compose ps redis

# Test connection
docker-compose exec redis redis-cli ping
```

## Production Deployment

### Using Docker Compose

1. **Update environment variables:**
```yaml
# docker-compose.yml
services:
  coordinator:
    environment:
      REQUIRE_AUTH: "true"
      RUST_LOG: offchainvm_coordinator=info
```

2. **Set up reverse proxy (nginx example):**
```nginx
server {
    listen 80;
    server_name coordinator.example.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

3. **Start services:**
```bash
docker-compose up -d
```

### Using Kubernetes

Example Kubernetes manifests:

```yaml
# coordinator-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: offchainvm-coordinator
spec:
  replicas: 3
  selector:
    matchLabels:
      app: coordinator
  template:
    metadata:
      labels:
        app: coordinator
    spec:
      containers:
      - name: coordinator
        image: offchainvm-coordinator:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: coordinator-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: coordinator-secrets
              key: redis-url
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
```

## Resource Limits

### Recommended Production Settings

**Coordinator:**
- CPU: 1-2 cores
- Memory: 512MB - 1GB
- Disk: 10GB (for WASM cache)

**Worker:**
- CPU: 2-4 cores
- Memory: 2-4GB
- Disk: 5GB

**PostgreSQL:**
- CPU: 1-2 cores
- Memory: 1-2GB
- Disk: 20GB

**Redis:**
- CPU: 0.5-1 core
- Memory: 512MB - 1GB
- Disk: 1GB

## Monitoring

### Prometheus Metrics

Add metrics exporter to coordinator:

```yaml
services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
```

### Grafana Dashboard

```yaml
services:
  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

## Security Notes

1. **Never commit .env files with real credentials**
2. **Use Docker secrets for sensitive data in production**
3. **Enable authentication (`REQUIRE_AUTH=true`)**
4. **Run coordinator behind HTTPS reverse proxy**
5. **Limit Docker socket access for worker**
6. **Use read-only root filesystem where possible**
7. **Regularly update base images**

## Backup & Restore

### PostgreSQL

```bash
# Backup
docker exec offchainvm-postgres pg_dump -U postgres offchainvm > backup.sql

# Restore
docker exec -i offchainvm-postgres psql -U postgres offchainvm < backup.sql
```

### Redis

```bash
# Backup
docker exec offchainvm-redis redis-cli SAVE
docker cp offchainvm-redis:/data/dump.rdb ./redis-backup.rdb

# Restore
docker cp ./redis-backup.rdb offchainvm-redis:/data/dump.rdb
docker-compose restart redis
```

### WASM Cache

```bash
# Backup
docker run --rm -v offchainvm_wasm_cache:/data \
  -v $(pwd):/backup alpine tar czf /backup/wasm-cache-backup.tar.gz /data

# Restore
docker run --rm -v offchainvm_wasm_cache:/data \
  -v $(pwd):/backup alpine tar xzf /backup/wasm-cache-backup.tar.gz -C /
```
