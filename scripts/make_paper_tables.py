"""Generate the revised paper's tables and plot data from the result files, so
every number in paper/revised traces to results/.

Usage: python scripts/make_paper_tables.py results/<date> [results/security.json] [results/native-baseline]
Writes paper/revised/tables/*.tex and paper/revised/data/*.csv.
"""
import csv
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
res = sys.argv[1]
sec = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "results", "security.json")
nat = sys.argv[3] if len(sys.argv) > 3 else os.path.join(ROOT, "results", "native-baseline")
out_t = os.path.join(ROOT, "paper", "revised", "tables")
out_d = os.path.join(ROOT, "paper", "revised", "data")
os.makedirs(out_t, exist_ok=True)
os.makedirs(out_d, exist_ok=True)

rows = list(csv.DictReader(open(os.path.join(res, "summary.csv"))))
by = {(r["config"], int(r["n"])): r for r in rows}
sizes = sorted({int(r["n"]) for r in rows})
f = lambda r, k: float(r[k])


def g(v):
    return f"{v:,.0f}".replace(",", "{,}")


def write(name, text):
    open(os.path.join(out_t, name), "w", encoding="utf-8", newline="\n").write(text)


# Per-config CSVs for pgfplots
for cfg in sorted({r["config"] for r in rows}):
    sub = [r for r in rows if r["config"] == cfg]
    with open(os.path.join(out_d, f"{cfg}.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["n", "gas_per_op", "gas_per_op_ci95", "e2e_ms", "e2e_ms_ci95", "e2e_per_op_ms", "prove_ms", "heap_mib"])
        for r in sorted(sub, key=lambda r: int(r["n"])):
            w.writerow([r["n"], r["gas_per_op_mean"], r["gas_per_op_ci95"], r["e2e_ms_mean"], r["e2e_ms_ci95"],
                        r["e2e_per_op_ms_mean"], r["prove_ms_mean"], r["peak_heap_mib_max"]])
shutil.copy(os.path.join(res, "summary.csv"), os.path.join(out_d, "summary.csv"))

# Native baselines (executed), if present: the optimised experimental verifier
# (primary, conservative for our claims) and the main-branch verifier.
def load_baseline(d):
    bl = os.path.join(d, "baseline.csv")
    if not os.path.exists(bl):
        return None
    b = list(csv.DictReader(open(bl)))
    if not b or not all(x["valid_accepted"] == "true" and x["tampered_rejected"] == "true" for x in b):
        return None
    vs = [int(x["verify_gas"]) for x in b]
    return {
        "n": len(b), "mean": sum(vs) / len(vs), "min": min(vs), "max": max(vs),
        "setkey": sum(int(x["set_key_gas"]) for x in b) / len(b),
        "model": sum(int(x["model_gas"]) for x in b) / len(b),
    }


packed = load_baseline(nat + "-packed")
main = load_baseline(nat)
native_exec = packed["mean"] if packed else (main["mean"] if main else None)
if packed or main:
    BS = "\\"
    NL = BS + BS + "\n"
    cell = lambda b, k: g(b[k]) if b else "--"
    mdl = (packed or main)["model"]
    err = lambda b: f"{(mdl - b['mean']) / b['mean'] * 100:+.1f}{BS}%" if b else "--"
    t = BS + "begin{tabular}{lrr}\n" + BS + "toprule\nQuantity & optimised$^a$ & main branch$^b$ " + NL + BS + "midrule\n"
    t += f"{BS}texttt{{verify}} tx gas, mean ($n={(packed or main)['n']}$) & {cell(packed, 'mean')} & {cell(main, 'mean')} " + NL
    t += f"{BS}quad min & {cell(packed, 'min')} & {cell(main, 'min')} " + NL
    t += f"{BS}quad max & {cell(packed, 'max')} & {cell(main, 'max')} " + NL
    t += f"One-off {BS}texttt{{setKey}} per account & {cell(packed, 'setkey')} & {cell(main, 'setkey')} " + NL
    t += f"Opcode cost model, same inputs & {BS}multicolumn{{2}}{{c}}{{{g(mdl)}}} " + NL
    t += f"Model error vs.{BS} executed & {err(packed)} & {err(main)} " + NL
    t += BS + "bottomrule\n" + BS + "end{tabular}\n"
    write("native_baseline.tex", t)
model_native = f(by[("A0-native-model", 1)], "gas_per_op_mean")

# Ablation table at representative N
pick = [n for n in (1, 8, 32, 256) if n in sizes]
labels = {
    "A0-native-model": "A0 native ML-DSA (model)",
    "A1-attestation": "A1 off-chain + ECDSA attest.",
    "A2-groth16-per-op": "A2 + Groth16, per op",
    "A3-groth16-batch": "A3 + Groth16 + batching",
}
trust = {
    "A0-native-model": "none",
    "A1-attestation": "bundler key",
    "A2-groth16-per-op": "bundler$^\\dagger$",
    "A3-groth16-batch": "bundler$^\\dagger$",
}
t = "\\begin{tabular}{l" + "r" * len(pick) + "l}\n\\toprule\n"
t += "Configuration & " + " & ".join(f"$N={n}$" for n in pick) + " & Trust \\\\\n\\midrule\n"
if packed:
    t += "A0$'$ native, executed (optimised) & " + " & ".join(g(packed["mean"]) for _ in pick) + " & none \\\\\n"
if main:
    t += "A0$''$ native, executed (main) & " + " & ".join(g(main["mean"]) for _ in pick) + " & none \\\\\n"
for cfg in labels:
    t += labels[cfg] + " & " + " & ".join(g(f(by[(cfg, n)], "gas_per_op_mean")) for n in pick) + f" & {trust[cfg]} \\\\\n"
t += "\\bottomrule\n\\end{tabular}\n"
write("ablation_gas.tex", t)

# Full sweep table for A3 and A1
t = "\\begin{tabular}{rrrrrrr}\n\\toprule\n$N$ & \\multicolumn{2}{c}{A3 gas/op} & A1 gas/op & A3 vs model & " \
    + ("A3 vs exec. & " if native_exec else "") + "e2e/op (ms) \\\\\n"
t = t.replace("rrrrrrr", "rrrrrr" + ("r" if native_exec else ""))
t += " & mean & 95\\% CI & & & " + ("& " if native_exec else "") + "\\\\\n\\midrule\n"
for n in sizes:
    a3 = by[("A3-groth16-batch", n)]
    a1 = by[("A1-attestation", n)]
    red = (1 - f(a3, "gas_per_op_mean") / model_native) * 100
    line = f"{n} & {g(f(a3, 'gas_per_op_mean'))} & $\\pm${g(f(a3, 'gas_per_op_ci95'))} & {g(f(a1, 'gas_per_op_mean'))} & {red:.1f}\\% & "
    if native_exec:
        line += f"{(1 - f(a3, 'gas_per_op_mean') / native_exec) * 100:.1f}\\% & "
    line += f"{f(a3, 'e2e_per_op_ms_mean'):.2f} \\\\\n"
    t += line
t += "\\bottomrule\n\\end{tabular}\n"
write("sweep_gas.tex", t)

# Time and memory table
t = "\\begin{tabular}{lrrrrrr}\n\\toprule\nConfig & $N$ & ML-DSA verify & Authorise & EVM exec & End-to-end & Peak heap \\\\\n" \
    " & & (ms, all $N$) & (ms) & (ms) & (ms, mean $\\pm$ sd) & (MiB) \\\\\n\\midrule\n"
for cfg in ("A1-attestation", "A2-groth16-per-op", "A3-groth16-batch"):
    for n in pick:
        r = by[(cfg, n)]
        t += f"{cfg.split('-')[0]} & {n} & {f(r, 'mldsa_verify_ms_mean'):.2f} & {f(r, 'prove_ms_mean'):.2f} & {f(r, 'verify_evm_ms_mean'):.2f} & " \
             f"{f(r, 'e2e_ms_mean'):.1f} $\\pm$ {f(r, 'e2e_ms_std'):.1f} & {f(r, 'peak_heap_mib_max'):.1f} \\\\\n"
    t += "\\midrule\n" if cfg != "A3-groth16-batch" else ""
t += "\\bottomrule\n\\end{tabular}\n"
write("time_memory.tex", t)

# Security table (grouped)
if os.path.exists(sec):
    cases = json.load(open(sec, encoding="utf-8"))
    groups = {}
    for c in cases:
        groups.setdefault(c["category"], []).append(c)
    t = "\\begin{tabular}{p{2.3cm}rp{3.6cm}l}\n\\toprule\nCategory & Cases & Decided by & As expected \\\\\n\\midrule\n"
    for cat, cs in groups.items():
        layers = sorted({c["layer"] for c in cs})
        ok = sum(c["pass"] for c in cs)
        exp = "accepted (gap C1)" if cat.startswith("soundness") else f"{ok}/{len(cs)}"
        t += f"{cat} & {len(cs)} & {', '.join(layers)} & {exp} \\\\\n"
    t += f"\\midrule\nTotal & {len(cases)} & & {sum(c['pass'] for c in cases)}/{len(cases)} \\\\\n\\bottomrule\n\\end{{tabular}}\n"
    write("security.tex", t)

# Macros for inline numbers
a3 = lambda n, k="gas_per_op_mean": f(by[("A3-groth16-batch", n)], k)
macros = {
    "NativeModel": g(model_native),
    "SingleOpGas": g(a3(1)),
    "BatchEightGas": g(a3(8)) if 8 in sizes else "--",
    "BatchMaxGas": g(a3(sizes[-1])),
    "BatchMaxN": str(sizes[-1]),
    "AttestMaxGas": g(f(by[("A1-attestation", sizes[-1])], "gas_per_op_mean")),
    "AttestOneGas": g(f(by[("A1-attestation", 1)], "gas_per_op_mean")),
    "PerOpGas": g(f(by[("A2-groth16-per-op", 1)], "gas_per_op_mean")),
    "GrothOverhead": g(f(by[("A2-groth16-per-op", 1)], "gas_per_op_mean") - f(by[("A1-attestation", 1)], "gas_per_op_mean")),
    "RedModelOne": f"{(1 - a3(1) / model_native) * 100:.1f}",
    "RedModelMax": f"{(1 - a3(sizes[-1]) / model_native) * 100:.1f}",
    "ProveMsOne": f"{a3(1, 'prove_ms_mean'):.1f}",
    "ProveMsMax": f"{a3(sizes[-1], 'prove_ms_mean'):.1f}",
    "MldsaVerifyMsPerOp": f"{a3(sizes[-1], 'mldsa_verify_ms_mean') / sizes[-1]:.3f}",
    "EtoEMsOne": f"{a3(1, 'e2e_ms_mean'):.1f}",
    "EtoEMsMax": f"{a3(sizes[-1], 'e2e_ms_mean'):.1f}",
    "EtoEPerOpMax": f"{a3(sizes[-1], 'e2e_per_op_ms_mean'):.2f}",
    "HeapMax": f"{a3(sizes[-1], 'peak_heap_mib_max'):.1f}",
    "Repeats": rows[0]["runs"],
}
if main:
    macros["NativeExecMain"] = g(main["mean"])
    macros["NativeExecMainRaw"] = f"{main['mean']:.0f}"
    macros["RedMainOne"] = f"{(1 - a3(1) / main['mean']) * 100:.1f}"
    macros["RedMainMax"] = f"{(1 - a3(sizes[-1]) / main['mean']) * 100:.2f}"
    macros["MainVsModel"] = f"{(model_native - main['mean']) / main['mean'] * 100:+.1f}"
if native_exec:
    macros["NativeExec"] = g(native_exec)
    macros["NativeExecRaw"] = f"{native_exec:.0f}"
    macros["RedExecOne"] = f"{(1 - a3(1) / native_exec) * 100:.1f}"
    macros["RedExecMax"] = f"{(1 - a3(sizes[-1]) / native_exec) * 100:.2f}"
    macros["SetKeyGas"] = g((packed or main)["setkey"])
    macros["ExecVsModel"] = f"{(model_native - native_exec) / native_exec * 100:+.1f}"
if os.path.exists(sec):
    macros["SecCases"] = str(len(cases))
    macros["SecPass"] = str(sum(c["pass"] for c in cases))
write("macros.tex", "".join(f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in macros.items()))
print("tables written:", sorted(os.listdir(out_t)))

# Off-chain cost (point 7) against the conservative executed baseline.
# All prices are explicit assumptions (see cost-assumptions.json); 12.4 s is projected.
assum = json.load(open(os.path.join(res, "cost-assumptions.json")))
price_s = assum["prover_usd_per_hour"] / 3600.0
eth = assum["eth_usd"]
base = native_exec or model_native
B = chr(92)
NL = B + B + "\n"
gweis = [0.1, 1.0, 10.0]
t = B + "begin{tabular}{r" + "r" * len(gweis) + "}\n" + B + "toprule\n"
t += "$t_{sig}$ (s), prover USD/op & " + " & ".join(f"{x:g} gwei" for x in gweis) + " " + NL + B + "midrule\n"
for ts in assum["prove_seconds_per_sig"]:
    cost = ts * price_s
    cells = []
    for gw in gweis:
        saved = (base - a3(sizes[-1])) * gw * 1e-9 * eth
        cells.append(f"{saved - cost:.3f}")
    t += f"{ts:g}, {cost:.4f} & " + " & ".join(cells) + " " + NL
t += B + "bottomrule\n" + B + "end{tabular}\n"
write("offchain_cost.tex", t)
be = lambda gw, n: (base - a3(n)) * gw * 1e-9 * eth / price_s
extra = {
    "ProverUsdPerOpProj": f"{12.4 * price_s:.4f}",
    "SavedUsdOneGwei": f"{(base - a3(sizes[-1])) * 1e-9 * eth:.2f}",
    "BreakEvenTenthGwei": g(be(0.1, sizes[-1])),
    "BreakEvenOneGwei": g(be(1.0, sizes[-1])),
    "EthUsd": g(eth),
    "ProverUsdHour": f"{assum['prover_usd_per_hour']:.3f}",
}
open(os.path.join(out_t, "macros.tex"), "a", encoding="utf-8", newline="\n").write(
    "".join(f"{B}newcommand{{{B}{k}}}{{{v}}}\n" for k, v in extra.items()))
print("offchain table written")
