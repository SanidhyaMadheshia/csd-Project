#!/usr/bin/env bash
# Executable native ML-DSA-44 baseline (supervisor point 5): compile the ZKNox
# ETHDILITHIUM NIST verifier and run it on the same revm chain as Q-EVM.
#
# Requirements: git, docker (scripts/dev.sh), python3 with eth_abi, pycryptodome, numpy.
# Third-party code is fetched into $WORK (outside the repository) at a pinned commit.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-$ROOT/../qevm-third-party}"
PY="${PYTHON:-python3}"
COMMIT=f9f4fe1d84e68304b425e054c273c276fe44ba11   # ZKNoxHQ/ETHDILITHIUM main, 2026-09-16
SOLC_VERSION=0.8.30                                # as in the repo's foundry.toml
OUT="$ROOT/results/native-baseline"
COUNT="${COUNT:-100}"

mkdir -p "$WORK" "$OUT"
if [ ! -d "$WORK/ETHDILITHIUM" ]; then
  git clone https://github.com/ZKNoxHQ/ETHDILITHIUM.git "$WORK/ETHDILITHIUM"
fi
git -C "$WORK/ETHDILITHIUM" checkout -q "$COMMIT"
git -C "$WORK/ETHDILITHIUM" submodule update --init --depth 1 lib/sstore2 lib/InterfaceVerifier
# polyntt (imported by the Python reference); its requirements.txt URL is broken, so install from a checkout
NTT_COMMIT=3ac5f5dc0b204e91df4f68e347ade2bd4a82bb37
[ -d "$WORK/NTT" ] || git clone https://github.com/ZKNoxHQ/NTT.git "$WORK/NTT"
git -C "$WORK/NTT" checkout -q "$NTT_COMMIT"
"$PY" -m pip install -q eth_abi pycryptodome==3.23.0 numpy "$WORK/NTT/assets/pythonref"

# 1. vectors (our FIPS 204 implementation)
"$ROOT/scripts/dev.sh" /target/release/qevm-cli export-mldsa-vectors --count "$COUNT" --out results/native-baseline/vectors.json

# 2. expand public keys with the verifier's own Python reference
"$PY" "$ROOT/scripts/zknox_expand_pk.py" "$WORK/ETHDILITHIUM/pythonref" "$OUT/vectors.json" "$OUT/expanded.json"

# 3. compile (Cancun: revm 14 has no Osaka rules; the repo's default profile uses
#    optimizer runs = 10000 without via-IR, which we keep)
MSYS_NO_PATHCONV=1 docker run --rm -v "$WORK/ETHDILITHIUM":/src -v "$OUT":/out -w /src qevm-dev:1 bash -c "
  set -e
  [ -x /out/.solc ] || curl -sSL -o /out/.solc https://github.com/ethereum/solidity/releases/download/v$SOLC_VERSION/solc-static-linux
  chmod +x /out/.solc
  /out/.solc --version | tail -1 > /out/solc-version.txt
  /out/.solc --optimize --optimize-runs 10000 --evm-version cancun \
    sstore2/=lib/sstore2/contracts/ InterfaceVerifier/=lib/InterfaceVerifier/src/ \
    --bin src/ZKNOX_dilithium.sol -o /out/.build --overwrite
  cp /out/.build/ZKNOX_dilithium.bin /out/ZKNOX_dilithium.bin
"

# 4. execute on revm
"$ROOT/scripts/dev.sh" /target/release/qevm-cli native-baseline \
  --bin results/native-baseline/ZKNOX_dilithium.bin \
  --source "ZKNoxHQ/ETHDILITHIUM@$COMMIT src/ZKNOX_dilithium.sol (NIST ML-DSA-44), solc $SOLC_VERSION --optimize-runs 10000 --evm-version cancun"

# 5. Optimised experimental verifier (branch exp/packed-verifier): same key blob
#    and signature format; needs the Keccak-f[1600] helper contract deployed first.
PACKED_COMMIT=f85ca80c446c2d59fcd68b5efe565275599bb1f9   # 2026-09-09
OUTP="$ROOT/results/native-baseline-packed"
mkdir -p "$OUTP"
if [ ! -d "$WORK/ETHDILITHIUM-packed" ]; then
  git clone --branch exp/packed-verifier https://github.com/ZKNoxHQ/ETHDILITHIUM.git "$WORK/ETHDILITHIUM-packed"
fi
git -C "$WORK/ETHDILITHIUM-packed" checkout -q "$PACKED_COMMIT"
git -C "$WORK/ETHDILITHIUM-packed" submodule update --init --depth 1 lib/sstore2 lib/InterfaceVerifier
cp "$OUT/vectors.json" "$OUT/expanded.json" "$OUTP/"
cp "$WORK/ETHDILITHIUM-packed/test/f1600_170.hex" "$OUTP/f1600_170.hex"
MSYS_NO_PATHCONV=1 docker run --rm -v "$WORK/ETHDILITHIUM-packed":/src -v "$OUTP":/out -v "$OUT":/solc -w /src qevm-dev:1 bash -c "
  set -e
  /solc/.solc --via-ir --optimize --optimize-runs 1000000 --evm-version cancun \
    sstore2/=lib/sstore2/contracts/ InterfaceVerifier/=lib/InterfaceVerifier/src/ \
    --bin src/ZKNOX_dilithium.sol -o /out/.build --overwrite
  cp /out/.build/ZKNOX_dilithium.bin /out/ZKNOX_dilithium.bin
"
"$ROOT/scripts/dev.sh" /target/release/qevm-cli native-baseline \
  --bin results/native-baseline-packed/ZKNOX_dilithium.bin \
  --vectors results/native-baseline-packed/vectors.json \
  --expanded results/native-baseline-packed/expanded.json \
  --out results/native-baseline-packed \
  --helper-runtime results/native-baseline-packed/f1600_170.hex \
  --source "ZKNoxHQ/ETHDILITHIUM@$PACKED_COMMIT (branch exp/packed-verifier, experimental) src/ZKNOX_dilithium.sol + F1600 helper, solc $SOLC_VERSION --via-ir --optimize-runs 1000000 --evm-version cancun"
