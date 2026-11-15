"""Expand FIPS 204 ML-DSA-44 public keys into the storage format of the ZKNox
ETHDILITHIUM NIST verifier (A_hat in the NTT domain, tr, NTT(t1 * 2^d)).

Usage: python zknox_expand_pk.py <ETHDILITHIUM/pythonref dir> <vectors.json> <expanded.json>

Mirrors pythonref/prepare_pk_for_deployment.py (NIST branch: SHAKE-256 for tr,
SHAKE-128 for ExpandA), but takes existing public keys instead of seeds.
"""
import json
import sys

ref_dir, vectors_path, out_path = sys.argv[1:4]
sys.path.insert(0, ref_dir)

from dilithium_py.dilithium.default_parameters import Dilithium2 as D  # noqa: E402
from dilithium_py.shake.shake_wrapper import shake128, shake256  # noqa: E402
from eth_abi import encode  # noqa: E402


def prepare_public_key_for_deployment(a_hat_compact, tr_hex, t1_compact):
    # Same encoding as ZKNox pythonref/prepare_pk_for_deployment.py (MIT):
    # abi.encode(abi.encode(uint256[][][] A_hat), tr, abi.encode(uint256[][] t1)).
    tr = bytes.fromhex(tr_hex)
    assert len(tr) == 64
    a = encode(["uint256[][][]"], [[[[int(x) for x in col] for col in row] for row in a_hat_compact]])
    t = encode(["uint256[][]"], [[[int(x) for x in row] for row in t1_compact]])
    return encode(["bytes", "bytes", "bytes"], [a, tr, t])


out = []
for v in json.load(open(vectors_path)):
    pk = bytes.fromhex(v["pk"])
    rho, t1 = D._unpack_pk(pk)
    a_hat = D._expand_matrix_from_seed(rho, _xof=shake128)
    tr = D._h(pk, 64, _xof=shake256)
    t1 = t1.scale(1 << D.d).to_ntt()
    t1_compact = [row[0] for row in t1.compact_256(32)]
    out.append(prepare_public_key_for_deployment(a_hat.compact_256(32), tr.hex(), t1_compact).hex())

json.dump(out, open(out_path, "w"))
print(f"expanded {len(out)} keys")
