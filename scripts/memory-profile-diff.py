#!/usr/bin/env python3
"""Diff two memory_profile JSONL runs and render the result as a markdown matrix.

Usage: memory-profile-diff.py <base.jsonl> <head.jsonl>

Rows are joined on (workload, curve, seed). Peak byte metrics are
deterministic for a given runner, so any nonzero delta there is caused by the
change under test; allocation counts, peak_resident and the timings are noisy
and only indicative.

Exits nonzero if a gated metric (allocated, peak_live, peak_delta) grows by
more than REGRESSION_THRESHOLD on any row. 1% of the peak is roughly one
domain-sized d8 polynomial buffer (8·2^k·32 bytes), so the gate reads as
"this change retains at least a polynomial's worth of extra memory".
"""

import json
import sys

REGRESSION_THRESHOLD = 0.01

METRICS = [
    ("allocated_bytes", "allocated", "mb", True),
    ("allocs", "allocs*", "count", False),
    ("peak_live_bytes", "peak_live", "mb", True),
    ("peak_delta_bytes", "peak_delta", "mb", True),
    ("peak_resident_bytes", "peak_resident*", "mb", False),
    ("prove_ms", "prove*", "ms", False),
]


def load(path):
    runs = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            key = (r["workload"], r.get("curve", ""), r.get("seed", ""), r.get("srs_log2", ""))
            runs[key] = r
    return runs


def fmt_value(v, unit):
    if unit == "mb":
        return f"{v / 2**20:.1f} MB"
    if unit == "ms":
        return f"{v} ms"
    return str(v)


def fmt_cell(base, head, unit):
    delta = head - base
    if delta == 0:
        return f"{fmt_value(head, unit)} (=)"
    pct = 100.0 * delta / base if base else float("inf")
    sign = "+" if delta > 0 else "−"
    if unit == "mb":
        mag = f"{abs(delta) / 2**20:.1f} MB"
    elif unit == "ms":
        mag = f"{abs(delta)} ms"
    else:
        mag = str(abs(delta))
    return f"{fmt_value(head, unit)} ({sign}{mag}, {sign}{abs(pct):.1f}%)"


def row_label(key, run):
    workload, curve, seed, srs_log2 = key
    if workload == "synthetic":
        return f"synthetic 2^{srs_log2}"
    return f"{curve} {seed} 2^{run['domain_log2']}"


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    base_runs, head_runs = load(sys.argv[1]), load(sys.argv[2])

    common = [k for k in head_runs if k in base_runs]
    if not common:
        sys.exit("no common (workload, curve, seed) rows between the two runs")

    regressions = []
    print("| fixture | " + " | ".join(label for _, label, _, _ in METRICS) + " |")
    print("|" + "---|" * (len(METRICS) + 1))
    for key in sorted(common):
        base, head = base_runs[key], head_runs[key]
        cells = []
        for m, label, unit, gated in METRICS:
            cell = fmt_cell(base[m], head[m], unit)
            if gated and base[m] and (head[m] - base[m]) / base[m] > REGRESSION_THRESHOLD:
                cell = f"**{cell} ⚠**"
                regressions.append(f"{row_label(key, head)}: {label} {fmt_value(base[m], unit)} -> {fmt_value(head[m], unit)}")
            cells.append(cell)
        print(f"| {row_label(key, head)} | " + " | ".join(cells) + " |")

    print()
    print("Cells are `head (delta vs base, %)`. `peak_live` and `peak_delta` "
          "are deterministic per runner class and `allocated` is stable to "
          "well under 0.1%; metrics marked `*` (allocation count, resident "
          "set, wall time) are noisy and only indicative. Gated metrics fail "
          f"the job on a >{REGRESSION_THRESHOLD:.0%} increase.")

    only_base = [k for k in base_runs if k not in head_runs]
    only_head = [k for k in head_runs if k not in base_runs]
    for label, keys, runs in (("base", only_base, base_runs), ("head", only_head, head_runs)):
        if keys:
            names = ", ".join(row_label(k, runs[k]) for k in sorted(keys))
            print(f"\nOnly in {label}: {names}")

    if regressions:
        print(f"\n**Memory regression detected ({len(regressions)}):**")
        for r in regressions:
            print(f"- {r}")
        sys.exit(1)


if __name__ == "__main__":
    main()
