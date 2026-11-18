# Executable native ML-DSA-44 baseline (supervisor point 5)

Verifier: ZKNoxHQ/ETHDILITHIUM@f9f4fe1d84e68304b425e054c273c276fe44ba11 src/ZKNOX_dilithium.sol (NIST ML-DSA-44), solc 0.8.30 --optimize-runs 10000 --evm-version cancun

Executed on the same revm chain and hard fork as the Q-EVM contracts (`qevm_evm::LocalChain`, Cancun (revm 14.0.3)), with the same FIPS 204 ML-DSA-44 implementation (`pqcrypto-mldsa` 0.1.2) for keys and signatures.

- Signatures: 100
- Valid signatures accepted: 100/100
- Tampered signatures rejected: 100/100
- Verifier deployment: 3145500 gas, 14370 bytes of code

| quantity | mean | std | median | min | max |
|---|---:|---:|---:|---:|---:|
| `verify` transaction gas (measured) | 8168152 | 53172 | 8170567 | 8079771 | 8322498 |
| `setKey` once per account (measured) | 4837676 | 109 | 4837687 | 4837339 | 4837891 |
| opcode cost model, same inputs | 2801997 | 355 | 2802009 | 2801086 | 2802768 |

Model error vs. this executed verifier: -65.7% (mean). The model approximates an optimised Yul verifier and is *not* a substitute for this measurement. The ZKNox verifier stores an expanded public key (Â, tr, NTT(t1·2^d)) on-chain once per account (`setKey`); per-signature cost is the `verify` row.

