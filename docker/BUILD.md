# Compiler Image Build

`docker/Dockerfile.wasmedge-compiler` is the image GitHub builds run in
(`DOCKER_IMAGE` on a builder worker) and the one `scripts/build_github_wasm.sh`
uses to compute a project's wasm hash before publishing. It fixes every input
that decides the bytes: the rust base by digest, `wasm-tools` and
`cargo-component` by version, binaryen (`wasm-opt`) by exact package.

## Build and push (amd64 only)

The architecture changes the bytes: the same commit, image digest and recipe
compile to different wasm on amd64 and arm64. The image is therefore built
for `linux/amd64` only, and anyone checking a hash on another machine runs it
emulated.

```bash
docker buildx build \
  --platform linux/amd64 \
  -t outlayer/wasmedge-compiler:<tag> \
  -f docker/Dockerfile.wasmedge-compiler \
  --push \
  .
```

Tag names carry the toolchain so a human can read them
(`rust1.97-wasi25-b120`: rust 1.97, WASI SDK 25, binaryen 120).

## No `latest` tag; deployments pin the digest

`ensure_image` pulls on **every** compile job, so a floating tag would let
anything pushed to this repository enter production compilation with no
deploy and no review, and would make the measured wasm hash irreproducible.

```bash
docker buildx imagetools inspect outlayer/wasmedge-compiler:<tag>
# -> Digest: sha256:...
```

Put the digest in the builder worker's env (`DOCKER_IMAGE=outlayer/wasmedge-compiler@sha256:…`)
and in `DEFAULT_IMAGE` of `scripts/build_github_wasm.sh`; the two must name the
same image, or a hash computed locally will not match the server's.

## Bumping the image

A new image gives every GitHub-built project a new hash. The coordinator's
wasm cache is keyed by `repo:commit:build_target` and says nothing about the
compiler, so clear it when `DOCKER_IMAGE` changes; otherwise a cached commit
keeps serving its old bytes while a fresh build of it gives the new hash.
