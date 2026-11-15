#!/usr/bin/env bash
# Run a command inside the pinned Q-EVM container, e.g.
#   scripts/dev.sh cargo test --workspace
#   scripts/dev.sh cargo run --release -p qevm-cli -- experiment --repeats 30
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=qevm-dev:1
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" "$ROOT"
fi
# CARGO_BUILD_JOBS defaults to 2: Docker Desktop on the 8 GB dev laptop gives
# the VM ~2 GB, and a parallel release build of revm/arkworks runs out of memory.
# MSYS_NO_PATHCONV stops Git Bash on Windows from rewriting /work paths.
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$ROOT":/work \
  -v qevm-target:/target \
  -v qevm-cargo-registry:/usr/local/cargo/registry \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
  -w /work "$IMAGE" "$@"
