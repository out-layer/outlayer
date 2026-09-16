#!/usr/bin/env bash
#
# Compile a project the way the platform compiles it, and print the sha256 of
# the wasm.
#
# That number is what an OutLayer enclave measures before it runs your code, and
# what a secret locked to a build is judged against. Running this before you
# publish lets you store the secret against the build first, so the very first
# run is already allowed to read it — instead of publishing, running once to
# discover the number, and storing the secret afterwards.
#
# The build runs inside the same image the platform's compiler runs in, pinned
# by digest, and follows the same recipe as
# worker/src/compiler/wasm32_wasip{1,2}.rs: cargo build --release, then wasm-opt
# for P1 or wasm-tools strip for P2. Building with your own toolchain gives a
# different, equally valid binary — and a different hash.
#
# Usage:
#   scripts/build_github_wasm.sh --repo https://github.com/you/proj --commit main
#   scripts/build_github_wasm.sh --dir ./my-project --target wasm32-wasip2
#   scripts/build_github_wasm.sh --repo … --commit … --twice   # check it reproduces
#
# Options:
#   --repo URL        GitHub repository to clone (with --commit)
#   --commit REF      branch, tag or commit to build
#   --dir PATH        build a local directory instead of cloning
#   --target TRIPLE   wasm32-wasip1 (default) or wasm32-wasip2
#   --image REF       compiler image; defaults to the digest below, which is
#                     what the deployed compiling worker uses
#                     (worker/.env.testnet.worker1). Override to match a
#                     different worker, and pin by digest — a floating tag lets
#                     a registry push change the toolchain under you.
#   --twice           build twice from scratch and report whether the bytes match
#   --keep            leave the build output on disk and say where
#
set -euo pipefail

# The compiler the deployed worker runs, on linux/amd64 — the architecture the
# compiling worker runs on, and not a detail.
#
# Measured, because the opposite seemed obvious: out-layer/env-test-example at
# 74fb4db6 compiles to f4712d4f… on amd64 and to c11e2a1b… on arm64, same image
# digest, same recipe. (out-layer/echo-example happens to agree across both,
# which is how the assumption survived a first test.) A hash computed on an
# Apple laptop against the arm64 variant is therefore a number the platform will
# never produce, and a secret locked to it would never open.
# outlayer/wasmedge-compiler:rust1.97-wasi25-b120, amd64 — the same image the
# compiling worker is pinned to (worker/.env.testnet.worker1). Every input that
# decides the bytes is fixed in it: the rust base by digest, wasm-tools and
# cargo-component by version, and binaryen — whose wasm-opt rewrites every
# wasip1 module — by exact package.
#
# amd64 is named, not merely preferred: the architecture changes the bytes.
# out-layer/env-test-example at 74fb4db6 compiled to f4712d4f… on amd64 and to
# c11e2a1b… on arm64 under the previous image, same digest and same recipe. A
# hash worked out against an arm64 variant is one the platform will never
# produce, and a secret locked to it would never open.
DEFAULT_IMAGE="outlayer/wasmedge-compiler@sha256:d9eb7bd9bab6c46b77f309ec33e94ca112883268a848dd1929289fade799cd27"

REPO=""; COMMIT=""; DIR=""; TARGET="wasm32-wasip1"
IMAGE="${OUTLAYER_COMPILER_IMAGE:-$DEFAULT_IMAGE}"
TWICE=0; KEEP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)   REPO="${2:?--repo needs a URL}"; shift 2 ;;
    --commit) COMMIT="${2:?--commit needs a ref}"; shift 2 ;;
    --dir)    DIR="${2:?--dir needs a path}"; shift 2 ;;
    --target) TARGET="${2:?--target needs a triple}"; shift 2 ;;
    --image)  IMAGE="${2:?--image needs a reference}"; shift 2 ;;
    --twice)  TWICE=1; shift ;;
    --keep)   KEEP=1; shift ;;
    -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$TARGET" in
  wasm32-wasip1|wasm32-wasip2|wasm32-wasi) ;;
  *) echo "unsupported target: $TARGET (use wasm32-wasip1 or wasm32-wasip2)" >&2; exit 2 ;;
esac

if [ -n "$DIR" ]; then
  [ -n "$REPO$COMMIT" ] && { echo "--dir cannot be combined with --repo/--commit" >&2; exit 2; }
  [ -d "$DIR" ] || { echo "no such directory: $DIR" >&2; exit 2; }
  [ -f "$DIR/Cargo.toml" ] || { echo "no Cargo.toml in $DIR" >&2; exit 2; }
elif [ -n "$REPO" ] && [ -n "$COMMIT" ]; then
  :
else
  echo "give either --repo URL --commit REF, or --dir PATH. --help for the rest." >&2
  exit 2
fi

command -v docker >/dev/null || { echo "docker is required: the build runs in the platform's compiler image" >&2; exit 2; }

# Fix the architecture by naming an amd64 image, then check it. `--platform`
# cannot rescue a multi-arch reference here: docker stores one image per
# reference, so a digest already pulled as arm64 stays arm64 and the flag is
# refused beside a digest anyway.
docker pull -q "$IMAGE" >/dev/null 2>&1 || docker pull -q --platform linux/amd64 "$IMAGE" >/dev/null 2>&1 || true
ARCH=$(docker image inspect "$IMAGE" --format '{{.Architecture}}' 2>/dev/null || echo unknown)
if [ "$ARCH" != "amd64" ]; then
  echo "the compiler image resolved to '$ARCH', not amd64." >&2
  echo "The platform compiles on amd64 and the bytes differ, so a hash from any" >&2
  echo "other architecture is one the platform will never produce. Name the amd64" >&2
  echo "image rather than a multi-arch one: a reference already pulled for this" >&2
  echo "host keeps that architecture, and --platform will not move it." >&2
  exit 1
fi

# The recipe, run inside the container. It mirrors
# worker/src/compiler/wasm32_wasip1.rs and wasm32_wasip2.rs: the sources at
# /workspace/repo, the image's own CARGO_HOME, --locked when the project pinned
# its dependencies, the first wasm by name when a project builds several, and
# the same post-processing — which is part of the bytes, not a detail.
read -r -d '' RECIPE <<'INNER' || true
set -eu
cd /workspace
if [ -f /usr/local/cargo/env ]; then . /usr/local/cargo/env; fi

TARGET_TO_ADD="$BUILD_TARGET"
if [ "$BUILD_TARGET" = "wasm32-wasi" ] && rustup target list | grep -q wasm32-wasip1; then
  TARGET_TO_ADD="wasm32-wasip1"
fi
rustup target add "$TARGET_TO_ADD" >/dev/null 2>&1

if [ -n "${SRC_REPO:-}" ]; then
  git clone -q -- "$SRC_REPO" repo
  cd repo
  git checkout -q "$SRC_COMMIT"
else
  mkdir -p repo
  cp -a /outlayer/src/. repo/
  cd repo
  rm -rf target
fi

# The platform refuses build scripts and git dependencies. Warn here rather than
# letting the build run and the publish fail later. Comments are stripped first:
# repositories leave the rejected forms in a comment as a note to the reader,
# and one of OutLayer's own examples does.
CODE=$(sed 's/#.*//' Cargo.toml)
if printf '%s' "$CODE" | grep -Eq '^[[:space:]]*build[[:space:]]*='; then
  echo "warning: Cargo.toml declares a build script; the platform refuses those" >&2
fi
if printf '%s' "$CODE" | grep -Eq 'git[[:space:]]*=[[:space:]]*["'"'"']https?://'; then
  echo "warning: Cargo.toml has a git dependency; the platform refuses those" >&2
fi

LOCKED=""
if [ -f Cargo.lock ]; then
  LOCKED="--locked"
else
  echo "note: no Cargo.lock — dependency versions are picked at build time, so this hash will not hold once a dependency publishes. Commit a lock file." >&2
fi

cargo build --release --target "$TARGET_TO_ADD" $LOCKED >&2

WASM=$(find "target/$TARGET_TO_ADD/release" -maxdepth 1 -name '*.wasm' -type f | sort | head -1)
[ -n "$WASM" ] || { echo "the build produced no wasm in target/$TARGET_TO_ADD/release" >&2; exit 1; }
COUNT=$(find "target/$TARGET_TO_ADD/release" -maxdepth 1 -name '*.wasm' -type f | wc -l | tr -d ' ')
[ "$COUNT" = 1 ] || echo "note: $COUNT wasm binaries built; the platform runs the first by name, $(basename "$WASM")" >&2

mkdir -p /workspace/output
cp "$WASM" /workspace/output/output.wasm

# Post-processing is part of the bytes. A build that skipped it is a different
# binary with a different hash, so a missing tool is an error, never a skip.
if [ "$TARGET_TO_ADD" = "wasm32-wasip2" ]; then
  command -v wasm-tools >/dev/null || { echo "wasm-tools missing from the compiler image" >&2; exit 1; }
  wasm-tools strip /workspace/output/output.wasm -o /workspace/output/stripped.wasm
  mv /workspace/output/stripped.wasm /workspace/output/output.wasm
else
  command -v wasm-opt >/dev/null || { echo "wasm-opt missing from the compiler image" >&2; exit 1; }
  wasm-opt -Oz --strip-dwarf --strip-producers --enable-sign-ext --enable-bulk-memory \
    /workspace/output/output.wasm -o /workspace/output/opt.wasm
  mv /workspace/output/opt.wasm /workspace/output/output.wasm
fi

cp /workspace/output/output.wasm /outlayer/out/module.wasm
sha256sum /workspace/output/output.wasm | cut -d' ' -f1
echo "toolchain $(rustc -V 2>/dev/null || echo unknown)" >&2
INNER

OUT_DIR=$(mktemp -d)
trap '[ "$KEEP" = 1 ] || rm -rf "$OUT_DIR"' EXIT

run_build() {
  local out="$1"
  mkdir -p "$out"
  local args=(run --rm -i
    -e "SRC_REPO=$REPO" -e "SRC_COMMIT=$COMMIT" -e "BUILD_TARGET=$TARGET"
    -v "$out:/outlayer/out")
  [ -n "$DIR" ] && args+=(-v "$(cd "$DIR" && pwd):/outlayer/src:ro")
  docker "${args[@]}" "$IMAGE" sh -c "$RECIPE"
}

echo "compiler image: $IMAGE (amd64)" >&2
echo "target:         $TARGET" >&2
[ -n "$REPO" ] && echo "source:         $REPO @ $COMMIT" >&2
[ -n "$DIR" ]  && echo "source:         $DIR (local)" >&2
echo >&2

FIRST=$(run_build "$OUT_DIR/a")

if [ "$TWICE" = 1 ]; then
  echo >&2
  echo "building a second time, from scratch…" >&2
  SECOND=$(run_build "$OUT_DIR/b")
  echo >&2
  if [ "$FIRST" = "$SECOND" ]; then
    echo "reproducible: both builds produced $FIRST" >&2
  else
    echo "NOT reproducible: $FIRST vs $SECOND" >&2
    echo "The same source compiled to different bytes twice in a row. A secret" >&2
    echo "locked to either hash will stop opening when the project is rebuilt." >&2
    exit 1
  fi
fi

[ "$KEEP" = 1 ] && echo "wasm kept at: $OUT_DIR/a/module.wasm" >&2

echo >&2
echo "Lock a secret to this build with:" >&2
echo "  outlayer secrets set <KEY> <value> --build $FIRST" >&2
echo >&2

echo "$FIRST"
