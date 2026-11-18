# Executable native ML-DSA-44 baseline (supervisor point 5)

Verifier: ZKNoxHQ/ETHDILITHIUM@f85ca80c446c2d59fcd68b5efe565275599bb1f9 (branch exp/packed-verifier, experimental) src/ZKNOX_dilithium.sol + F1600 helper, solc 0.8.30 --via-ir --optimize-runs 1000000 --evm-version cancun

Executed on the same revm chain and hard fork as the Q-EVM contracts (`qevm_evm::LocalChain`, Cancun (revm 14.0.3)), with the same FIPS 204 ML-DSA-44 implementation (`pqcrypto-mldsa` 0.1.2) for keys and signatures.

- Signatures: 100
- Valid signatures accepted: 100/100
- Tampered signatures rejected: 100/100
- Verifier deployment: 5265127 gas, 24383 bytes of code

| quantity | mean | std | median | min | max |
|---|---:|---:|---:|---:|---:|
| `verify` transaction gas (measured) | 1248996 | 1667 | 1249080 | 1244485 | 1252253 |
| `setKey` once per account (measured) | 4837624 | 109 | 4837635 | 4837287 | 4837839 |
| opcode cost model, same inputs | 2801997 | 355 | 2802009 | 2801086 | 2802768 |

Model error vs. this executed verifier: +124.3% (mean). The model approximates an optimised Yul verifier and is *not* a substitute for this measurement. The ZKNox verifier stores an expanded public key (Â, tr, NTT(t1·2^d)) on-chain once per account (`setKey`); per-signature cost is the `verify` row.

