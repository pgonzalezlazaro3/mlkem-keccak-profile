"""Reads results/portable.csv and results/optimised.csv and writes results/summary.md.

Standard library only. If matplotlib is installed, also writes results/keccak_share.png.
"""

import csv
from pathlib import Path

RESULTS = Path(__file__).parent / "results"
OPS = ["keygen", "encaps", "decaps"]
ALGS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]


def load(build):
    with open(RESULTS / f"{build}.csv", newline="") as f:
        return {(r["algorithm"], r["operation"]): r for r in csv.DictReader(f)}


def main():
    port, opt = load("portable"), load("optimised")
    lines = [
        "| Algorithm | Operation | Portable: us/op | Portable: Keccak share | "
        "Optimised: us/op | Optimised: Keccak share | Optimised: Amdahl bound | Timer overhead (opt.) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for a in ALGS:
        for op in OPS:
            p, o = port[(a, op)], opt[(a, op)]
            lines.append(
                f"| {a} | {op} | {float(p['us_per_op']):.1f} | {100 * float(p['keccak_share']):.0f}% | "
                f"{float(o['us_per_op']):.1f} | {100 * float(o['keccak_share']):.0f}% | "
                f"{float(o['amdahl_bound']):.2f}x | {100 * float(o['timer_overhead']):.0f}% |"
            )

    p768 = [port[("ML-KEM-768", op)] for op in OPS]
    o768 = [opt[("ML-KEM-768", op)] for op in OPS]
    t_p = sum(float(r["us_per_op"]) for r in p768)
    t_o = sum(float(r["us_per_op"]) for r in o768)
    k_p = sum(float(r["keccak_us_per_op"]) for r in p768)
    k_o = sum(float(r["keccak_us_per_op"]) for r in o768)
    w_p = sum(float(r["us_per_op_with_timers"]) for r in p768)
    w_o = sum(float(r["us_per_op_with_timers"]) for r in o768)

    head = [
        "## Headline, ML-KEM-768, one full key exchange (keygen + encaps + decaps)",
        "",
        f"- Portable build: {t_p:.1f} us, of which Keccak {100 * k_p / w_p:.0f}%.",
        f"- Optimised build: {t_o:.1f} us (speed-up {t_p / t_o:.2f}x), of which Keccak {100 * k_o / w_o:.0f}%.",
        f"- Upper bound on the gain from a Keccak accelerator in the optimised build: {1 / (1 - k_o / w_o):.2f}x.",
        "",
    ]
    out = "\n".join(head + lines) + "\n"
    (RESULTS / "summary.md").write_text(out)
    print("\n" + out)
    print(f"Saved {RESULTS / 'summary.md'}")

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed: no plot (the table is enough).")
        return
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    labels = [f"{a.split('-')[-1]}\n{op}" for a in ALGS for op in OPS]
    x = range(len(labels))
    sp = [100 * float(port[(a, op)]["keccak_share"]) for a in ALGS for op in OPS]
    so = [100 * float(opt[(a, op)]["keccak_share"]) for a in ALGS for op in OPS]
    ax.bar([i - 0.2 for i in x], sp, width=0.4, label="portable C ML-KEM")
    ax.bar([i + 0.2 for i in x], so, width=0.4, label="NEON / AVX2 ML-KEM")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=7)
    ax.set_ylabel("Share of time in Keccak (%)")
    ax.set_ylim(0, 100)
    ax.set_title("ML-KEM in liboqs: time spent in Keccak")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(RESULTS / "keccak_share.png", dpi=200)
    print(f"Saved {RESULTS / 'keccak_share.png'}")


if __name__ == "__main__":
    main()
