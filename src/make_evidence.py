#!/usr/bin/env python3
"""Build evidence.json from a run's results.json + remediation logs.

Usage: python3 src/make_evidence.py --results outputs/run1/results.json
         --before-log outputs/run1/remediation-before.log
         --after-log outputs/run1/remediation-after.log
"""
import argparse
import json
import os
import re

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def count_findings():
    """Count findings by severity from findings.md headers (## F-0X — Sev:)."""
    counts = {"High": 0, "Medium": 0, "Low": 0}
    total = 0
    with open(os.path.join(PACK, "findings.md")) as f:
        for line in f:
            m = re.match(r"## F-\d+ — (High|Medium|Low)", line)
            if m:
                counts[m.group(1)] += 1
                total += 1
    return total, counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--before-log", required=True)
    ap.add_argument("--after-log", required=True)
    a = ap.parse_args()
    with open(a.results) as f:
        r = json.load(f)
    with open(a.before_log) as f:
        before = f.read()
    with open(a.after_log) as f:
        after = f.read()
    total, counts = count_findings()
    m = re.search(r"regression test: (\d+) passed, (\d+) failed", after)
    evidence = {
        "pack": "lattice-benchmark-remediation-pack",
        "implementations_benchmarked": {
            "liboqs": "0.16.0 (C)",
            "kyber-py": "1.2.0 (pure Python, ML-KEM)",
            "dilithium-py": "1.5.1 (pure Python, ML-DSA)",
            "rust": "not run — no cargo/rustc toolchain on this machine",
            "go": "not run — no Go toolchain on this machine",
        },
        "parameter_sets": {
            "ML-KEM": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
            "ML-DSA": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        },
        "throughput_ms_median": r["throughput"],
        "peak_rss_kb": r["memory_kb"],
        "sizes_verified": {k: v["match"] for k, v in r["sizes_verified"].items()},
        "adversarial_cases": {alg: len(c) for alg, c in r["adversarial"].items()},
        "cross_implementation_all_pass": all(
            all(v for v in cases.values())
            for cases in r["cross_implementation"].values()),
        "determinism": r["determinism"],
        "weakness": {
            "id": "F-01",
            "title": "dilithium-py deterministic ML-DSA signing silently drops the FIPS 204 randomized-signing hedge",
            "reproduced": "REPRODUCED" in before,
            "regression_test_passed": int(m.group(1)) if m else 0,
            "regression_test_failed": int(m.group(2)) if m else -1,
            "remediation": "remediation/hedged_sign.py — hedged_sign() wrapper, deterministic opt-in gate, repeat-signature tripwire; patch in remediation/remediation.patch",
        },
        "findings_total": total,
        "findings_by_severity": counts,
    }
    with open(os.path.join(PACK, "evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"evidence.json written: {total} findings {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
