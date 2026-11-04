# Docker Images

Dockerfiles for the worker, the keystore and the compiler image. The
coordinator's images and compose files live in the coordinator repository.
Workers and keystores run in Intel TDX CVMs on our own hosts; their compose
files and deploy scripts are in [`deploy/self-hosted-tdx`](../deploy/self-hosted-tdx/README.md).

## Files

| File | What it is | Used by |
|---|---|---|
| `Dockerfile.worker-phala` | Execution worker image (`outlayer/near-outlayer-worker`); alpine, built from the repository root | `.github/workflows/release-docker.yml`, `scripts/build_and_push_phala.sh … worker`, `scripts/build_local_fast.sh` |
| `Dockerfile.keystore-phala` | Keystore image (`outlayer/near-outlayer-keystore`) | `.github/workflows/release-docker.yml`, `scripts/build_and_push_keystore*.sh`, `scripts/build_local_fast.sh` |
| `Dockerfile.compiler-worker` | Worker with a Rust toolchain and WASI SDK built in, for `COMPILATION_MODE=native` (no docker socket) | `scripts/build_and_push_phala.sh … worker-compiler` |
| `Dockerfile.wasmedge-compiler` | The image GitHub builds run in (`DOCKER_IMAGE` on a docker-mode builder); fixes the toolchain and with it the wasm bytes | [BUILD.md](BUILD.md) |
| `Dockerfile.worker` | Standalone worker image built from `worker/` | nothing; it does not copy `worker/wit`, which the build needs |
| `docker-compose.phala.yml`, `docker-compose.keystore-phala.yml` | Phala Cloud CVM compose files | `scripts/deploy_phala.sh` only; production does not run on Phala Cloud |

The `-phala` suffix of the two release Dockerfiles is a file name only: the
images they build are the ones the self-hosted TDX CVMs run.

## Building

Release images are built and attested by CI on a `v*` tag:
[DOCKER_RELEASE.md](DOCKER_RELEASE.md). Locally, from the repository root:

```bash
docker build -f docker/Dockerfile.worker-phala   -t near-outlayer-worker:dev .
docker build -f docker/Dockerfile.keystore-phala -t near-outlayer-keystore:dev .
```

A local build is not attested and has a different digest from the release; it
cannot be deployed as a measured CVM.

The compiler image: [BUILD.md](BUILD.md).
