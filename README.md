# Q-EVM (Quantum-Resistant Account Abstraction Layer) — Phase 1



## Block Level Diagram 

```
+-------------------+
|      USER         |
| (Wallet / DApp)   |
+---------+---------+
          |
          | 1. Create Transaction
          | + ML-DSA Signature
          v
+--------------------------+
|   USER OPERATION (ERC-4337) |
| sender | nonce | calldata |
| signature (ML-DSA)        |
+------------+-------------+
             |
             | 2. Submit to Bundler
             v
+------------------------------+
|     OFF-CHAIN BUNDLER        |
|  (Rust Implementation)       |
|------------------------------|
| - Validate UserOperation     |
| - Verify ML-DSA Signature    |
| - Maintain Mempool           |
+------------+-----------------+
             |
             | 3. Forward Valid Ops
             v
+------------------------------+
|       zkVM PROVER            |
|   (SP1 / RISC Zero)          |
|------------------------------|
| - Execute verification logic |
| - Generate ZK Proof          |
|   (Proof of correct signature|
|    & state transition)       |
+------------+-----------------+
             |
             | 4. Submit Proof
             v
================ ON-CHAIN =================

+--------------------------------------+
|   SMART CONTRACT WALLET (Solidity)   |
|--------------------------------------|
| - Verify ZK Proof (cheap gas)        |
| - Validate transaction               |
| - Update state                      |
+----------------+---------------------+
                 |
                 | 5. Execute Tx
                 v
+------------------------------+
|        ETHEREUM NETWORK      |
|   (L1 / L2 - Sepolia etc.)   |
+------------------------------+

=========================================
```


Rust prototype that:

- Generates ML-DSA (CRYSTALS-Dilithium) keypairs
- Signs and verifies messages (ML-DSA + ECDSA)
- Simulates a basic ERC-4337-inspired `UserOperation` bundler (ML-DSA validation)
- Benchmarks performance vs ECDSA

## Project Layout

```text
./Cargo.toml
./qevm-core/
  Cargo.toml
  src/
    main.rs
    lib.rs
    crypto/
    bundler/
    benchmark/
```

### Build

```bash
cd /home/sanidhya/bitcoin/csd-project
cargo build
```

### Run (CLI)

Generate keypairs:

```bash
cargo run -p qevm-core -- generate-keys
```

Sign a message:

```bash
# algo: mldsa | ecdsa
cargo run -p qevm-core -- sign-message --algo mldsa "hello" --sk-hex <SECRET_KEY_HEX>
```

Verify a message signature:

```bash
cargo run -p qevm-core -- verify-message --algo mldsa "hello" --pk-hex <PUBLIC_KEY_HEX> --sig-hex <SIGNATURE_HEX>
```

Simulate bundler (creates + signs N UserOperations, validates, bundles):

```bash
cargo run -p qevm-core -- simulate-bundler --count 5
```

Run benchmarks (averages over N iterations) and prints a table:

```bash
cargo run -p qevm-core -- run-benchmarks --iters 50
```

### Example Outputs

Benchmarks output format:

```text
Algorithm | KeyGen(ms) | Sign(ms) | Verify(ms)
---|---:|---:|---:
ML-DSA(Dilithium2) | 0.000 | 0.000 | 0.000
ECDSA(secp256k1) | 0.000 | 0.000 | 0.000
```

Bundler prints acceptance and a sample `UserOperation` JSON (hex fields for readability).

