# Off-chain cost analysis (supervisor point 7)

## What is measured

| N | off-chain ML-DSA verify per op (ms) | binding-circuit Groth16 prove per batch (ms) | end-to-end per op, A3 (ms) | peak heap, A3 (MiB) |
|---:|---:|---:|---:|---:|
| 1 | 0.031 | 24.13 | 38.689 | 0.6 |
| 2 | 0.033 | 25.79 | 20.607 | 0.6 |
| 4 | 0.030 | 24.44 | 9.885 | 0.7 |
| 8 | 0.031 | 24.51 | 4.995 | 0.9 |
| 16 | 0.031 | 25.62 | 2.660 | 1.2 |
| 32 | 0.030 | 24.55 | 1.335 | 1.8 |
| 64 | 0.030 | 24.05 | 0.713 | 3.0 |
| 128 | 0.030 | 23.96 | 0.420 | 5.5 |
| 256 | 0.030 | 23.06 | 0.266 | 10.3 |

These are the only off-chain costs this prototype actually incurs. Proving ML-DSA *inside* a zkVM is not implemented, so its cost is evaluated below as a parameter, not measured.

## Projected cost of a sound proof

Assumptions (all explicit): prover at $1.006/h (AWS g5.xlarge on-demand (1x A10G), us-east-1 list price — check before citing); ETH = $3000; proving time scales linearly with the number of signatures (no parallelism credited). The per-sig times include 12.4 s, the earlier draft's projection for RISC Zero; it is **not** a measurement.

Gas saved per op = native model (2,802,020) − measured A3 gas/op at N. Off-chain $ per op = t_sig × price/3600.

### Gas price 1 gwei

| t_sig (s) | prover $/op | net saving $/op, N=1 | net saving $/op, N=2 | net saving $/op, N=4 | net saving $/op, N=8 | net saving $/op, N=16 | net saving $/op, N=32 | net saving $/op, N=64 | net saving $/op, N=128 | net saving $/op, N=256 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.00028 | 7.6519 | 8.0152 | 8.1968 | 8.2876 | 8.3330 | 8.3557 | 8.3671 | 8.3728 | 8.3756 |
| 5 | 0.00140 | 7.6508 | 8.0140 | 8.1957 | 8.2865 | 8.3319 | 8.3546 | 8.3660 | 8.3716 | 8.3745 |
| 12.4 | 0.00347 | 7.6487 | 8.0120 | 8.1936 | 8.2844 | 8.3298 | 8.3526 | 8.3639 | 8.3696 | 8.3724 |
| 30 | 0.00838 | 7.6438 | 8.0071 | 8.1887 | 8.2795 | 8.3249 | 8.3476 | 8.3590 | 8.3647 | 8.3675 |
| 60 | 0.01677 | 7.6354 | 7.9987 | 8.1803 | 8.2711 | 8.3165 | 8.3392 | 8.3506 | 8.3563 | 8.3591 |

### Gas price 10 gwei

| t_sig (s) | prover $/op | net saving $/op, N=1 | net saving $/op, N=2 | net saving $/op, N=4 | net saving $/op, N=8 | net saving $/op, N=16 | net saving $/op, N=32 | net saving $/op, N=64 | net saving $/op, N=128 | net saving $/op, N=256 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.00028 | 76.5213 | 80.1542 | 81.9705 | 82.8787 | 83.3328 | 83.5599 | 83.6734 | 83.7302 | 83.7585 |
| 5 | 0.00140 | 76.5201 | 80.1531 | 81.9694 | 82.8776 | 83.3317 | 83.5588 | 83.6723 | 83.7290 | 83.7574 |
| 12.4 | 0.00347 | 76.5181 | 80.1510 | 81.9673 | 82.8755 | 83.3297 | 83.5567 | 83.6702 | 83.7270 | 83.7553 |
| 30 | 0.00838 | 76.5132 | 80.1461 | 81.9624 | 82.8706 | 83.3247 | 83.5518 | 83.6653 | 83.7221 | 83.7504 |
| 60 | 0.01677 | 76.5048 | 80.1377 | 81.9540 | 82.8622 | 83.3164 | 83.5434 | 83.6569 | 83.7137 | 83.7420 |

### Gas price 50 gwei

| t_sig (s) | prover $/op | net saving $/op, N=1 | net saving $/op, N=2 | net saving $/op, N=4 | net saving $/op, N=8 | net saving $/op, N=16 | net saving $/op, N=32 | net saving $/op, N=64 | net saving $/op, N=128 | net saving $/op, N=256 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.00028 | 382.6074 | 400.7721 | 409.8537 | 414.3947 | 416.6653 | 417.8005 | 418.3681 | 418.6519 | 418.7938 |
| 5 | 0.00140 | 382.6063 | 400.7710 | 409.8526 | 414.3936 | 416.6642 | 417.7994 | 418.3669 | 418.6508 | 418.7927 |
| 12.4 | 0.00347 | 382.6042 | 400.7689 | 409.8505 | 414.3915 | 416.6621 | 417.7974 | 418.3649 | 418.6487 | 418.7906 |
| 30 | 0.00838 | 382.5993 | 400.7640 | 409.8456 | 414.3866 | 416.6572 | 417.7924 | 418.3600 | 418.6438 | 418.7857 |
| 60 | 0.01677 | 382.5909 | 400.7556 | 409.8372 | 414.3782 | 416.6488 | 417.7841 | 418.3516 | 418.6354 | 418.7773 |

A positive value means the off-chain proof costs less than the gas it saves. The break-even proving time per signature is t* = gas_saved × gas_price × ETH / (price/3600).

| gas price (gwei) | break-even t_sig at N=1 (s) | at largest N (s) |
|---:|---:|---:|
| 1 | 27383 | 29973 |
| 10 | 273835 | 299733 |
| 50 | 1369173 | 1498667 |

## Latency

With a sound zkVM proof, end-to-end latency per batch is at least N × t_sig on one prover (plus the Groth16 wrap), so batching lowers *gas* per op but not *latency*; only parallel provers lower wall-clock time. With the binding circuit used today, latency is dominated by off-chain ML-DSA verification and EVM execution (table above).
