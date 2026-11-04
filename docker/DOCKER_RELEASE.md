# Docker Image Release Guide

Production worker and keystore images are built by GitHub Actions
(`.github/workflows/release-docker.yml`) and carry a Sigstore build-provenance
attestation, which ties each image digest to a commit of this public
repository. The digest is what a TDX CVM's compose names, so the measured
application can be traced back to source.

## Building a release

Push a tag starting with `v`, from any commit:

```bash
git tag v<X.Y.Z>
git push origin v<X.Y.Z>
```

Suffixes such as `-rc1`, `-beta` or `-defuse.1` mark pre-releases; the
workflow treats every `v*` tag the same.

## What happens on tag push

1. GitHub Actions builds `docker/Dockerfile.worker-phala` and
   `docker/Dockerfile.keystore-phala` for linux/amd64
2. Pushes them to Docker Hub as `outlayer/near-outlayer-worker` and
   `outlayer/near-outlayer-keystore`, tagged with the git tag and `latest`
3. Creates a Sigstore attestation for each digest and pushes it to the registry
4. Creates a GitHub Release whose body lists both digests and the verify command

One run per tag: a duplicate delivery of the same tag push cancels the earlier
run, so a release never names a digest it did not build.

## Verifying images

```bash
gh attestation verify oci://docker.io/outlayer/near-outlayer-worker@sha256:<digest> -R out-layer/outlayer
```

Images up to and including `v0.1.58` are attested under the `fastnear`
GitHub organization, so `-R out-layer/outlayer` finds no attestation for them:

```bash
gh attestation verify oci://docker.io/outlayer/near-outlayer-worker:v0.1.58 --owner fastnear
# or without the GitHub API, from the attestation pushed to the registry:
gh attestation verify oci://docker.io/outlayer/near-outlayer-worker:v0.1.58 --bundle-from-oci --owner fastnear
```

Or search the digest on https://search.sigstore.dev/.

## Deploying a release

Deploy by digest, never by tag: a tag can be moved, a digest cannot.
`scripts/deploy_tdx.sh <worker|keystore> <net> --version <ver> --node <host>`
reads the digest from the GitHub release of `v<ver>` (`--digest` overrides
the lookup), checks its attestation (`-R out-layer/outlayer`, then `--owner
fastnear`) and deploys the CVM with that digest in its compose
(`deploy/self-hosted-tdx/<component>/docker-compose.yaml`,
`image: docker.io/outlayer/near-outlayer-<component>@sha256:…`). An
attestation that does not verify is printed as `NOT verified` and the deploy
continues: read that line before approving the measurements.

## Unattested builds

For iteration only, never for a measured deployment:

```bash
./scripts/build_and_push_phala.sh outlayer v0.1.42 worker
./scripts/build_and_push_keystore_tee.sh outlayer v0.1.42
```

These push an image without a Sigstore attestation; `deploy_tdx.sh` resolves
digests from GitHub releases and will not find them.

## GitHub repository setup

**Variables** (Settings > Variables > Actions):
- `DOCKERHUB_USERNAME`: Docker Hub user or organization (`outlayer`)

**Secrets** (Settings > Secrets > Actions):
- `DOCKERHUB_TOKEN`: Docker Hub access token with Read & Write permissions
