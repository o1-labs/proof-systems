#!/usr/bin/env python3
"""Diff two memory_profile JSONL runs and render the result as a markdown matrix.

Usage: memory-profile-diff.py <base.jsonl> <head.jsonl>

Rows are joined on (workload, curve, seed). Peak byte metrics are
deterministic for a given runner, so any nonzero delta there is caused by the
change under test; allocation counts, peak_resident and the timings are noisy
and only indicative.
"""

import json
import sys

METRICS = [
    ("allocated_bytes", "allocated", "mb"),
    ("allocs", "allocs*", "count"),
    ("peak_live_bytes", "peak_live", "mb"),
    ("peak_delta_bytes", "peak_delta", "mb"),
    ("peak_resident_bytes", "peak_resident*", "mb"),
    ("prove_ms", "prove*", "ms"),
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

    print("| fixture | " + " | ".join(label for _, label, _ in METRICS) + " |")
    print("|" + "---|" * (len(METRICS) + 1))
    for key in sorted(common):
        base, head = base_runs[key], head_runs[key]
        cells = [fmt_cell(base[m], head[m], unit) for m, _, unit in METRICS]
        print(f"| {row_label(key, head)} | " + " | ".join(cells) + " |")

    print()
    print("Cells are `head (delta vs base, %)`. `peak_live` and `peak_delta` "
          "are deterministic per runner class and `allocated` is stable to "
          "well under 0.1%; metrics marked `*` (allocation count, resident "
          "set, wall time) are noisy and only indicative.")

    only_base = [k for k in base_runs if k not in head_runs]
    only_head = [k for k in head_runs if k not in base_runs]
    for label, keys, runs in (("base", only_base, base_runs), ("head", only_head, head_runs)):
        if keys:
            names = ", ".join(row_label(k, runs[k]) for k in sorted(keys))
            print(f"\nOnly in {label}: {names}")


if __name__ == "__main__":
    main()
