# Lattice Benchmark Remediation Pack

Reproducible ML-KEM / ML-DSA benchmarking across pinned liboqs 0.16.0 (C),
kyber-py 1.2.0 and dilithium-py 1.5.1 (pure Python), with adversarial-input
behaviour, one reproduced core-protocol weakness and a tested remediation.

## What this pack is

- **Benchmarks**: ML-KEM-512/768/1024 and ML-DSA-44/65/87 keygen / encaps /
  decaps / sign / verify throughput (median per operation), peak RSS per
  operation, and adversarial-input behaviour (flipped, truncated, oversized
  and wrong-parameter-set inputs), for every implementation that runs on
  this machine.
- **The one weakness (F-01)**: dilithium-py's `ML_DSA.sign(...,
  deterministic=True)` silently produces byte-identical signatures for
  repeated signings of the same message, and those signatures verify under
  every implementation — a verifier cannot tell the FIPS 204 hedged-signing
  protection was dropped. Reproduced in
  `remediation/reproduce_weakness.py`; remediated by the hedged-signing
  wrapper `remediation/hedged_sign.py` (explicit opt-in gate for
  deterministic mode + a repeat-signature tripwire), with the patch in
  `remediation/remediation.patch` and a regression test in
  `remediation/test_remediation.py` that fails before the patch and passes
  after it.
- **Claim-to-evidence index**: `claims.md` maps every claim to the script
  and output file that proves it. **Findings**: `findings.md`, severity
  ranked. **Sources**: `citations.md`.

This pack does **not** reuse the earlier implicit-rejection assessment:
that work tested FIPS 203 ML-KEM.Decaps implicit rejection in ML-KEM-768
only. The weakness here is new (FIPS 204 ML-DSA deterministic signing in
dilithium-py), and the benchmarks cover all six parameter sets and three
implementations, including ML-DSA, which the earlier pack did not touch.

## How to run it

```sh
bash scripts/run_all.sh            # full rebuild + benchmark into outputs/run1/
bash scripts/clean_reproduce.sh    # fresh-copy re-run into outputs/run2-clean/ + comparison
bash scripts/verify_digests.sh     # SHA-256 check over all shippable files
```

Requirements: gcc, cmake, make, python3 (>= 3.10), OpenSSL dev headers
(`libssl-dev`) for `-lcrypto`, ~500 MB free disk for the liboqs build. No
network access is needed: all sources are bundled under `src/` (liboqs
tarball, both Python wheels, both FIPS PDFs) and their SHA-256 digests are
verified at the start of every run.

## Results (run1)

See `outputs/run1/results.json` for the full machine-readable results and
`docs/index.html` for the rendered findings page. Headline numbers
(medians, run1):

- **ML-KEM throughput (liboqs vs kyber-py, median ms)**: 512 —
  keygen 0.018/5.38, encaps 0.021/7.87, decaps 0.023/11.22; 768 —
  0.030/9.17, 0.032/12.29, 0.037/16.64; 1024 — 0.040/13.99, 0.043/17.90,
  0.051/23.28. Peak RSS: liboqs ~5.8–5.9 MB, kyber-py ~19.2–19.4 MB.
- **ML-DSA throughput (liboqs vs dilithium-py, median ms)**: 44 —
  keygen 0.058/16.57, sign 0.206/84.45, verify 0.065/20.66; 65 —
  0.100/27.25, 0.273/125.93, 0.095/32.00; 87 — 0.151/44.60, 0.312/203.98,
  0.146/48.86. Peak RSS: liboqs ~5.9–6.0 MB, dilithium-py ~20.0–21.1 MB.
- **Adversarial behaviour**: 15 KEM cases + 14 SIG cases per parameter
  set, all with the expected outcome in both implementations (flipped /
  zero ciphertexts decapsulate to a different 32-byte secret under
  implicit rejection; truncated, oversized and wrong-parameter-set inputs
  are refused; flipped signatures, wrong messages and wrong contexts fail
  verification; a 300-byte context is refused by both implementations).
- **Cross-implementation agreement**: liboqs <-> kyber-py KEM
  encaps/decaps and liboqs <-> dilithium-py signatures verify in both
  directions for all six parameter sets — including deterministic
  dilithium-py signatures, which liboqs accepts as valid.
- **Determinism**: liboqs ML-DSA signing is hedged (repeated signings
  differ); dilithium-py default signing is hedged (repeated signings
  differ); dilithium-py `deterministic=True` signing is byte-identical
  across repeated signings (F-01).

## Comparison rule (why run1 and run2-clean logs differ)

`scripts/clean_reproduce.sh` re-runs everything from a fresh copy and
compares only **deterministic** fields between runs (sizes, round-trip
outcomes, adversarial outcomes, cross-implementation outcomes,
determinism booleans, remediation verdicts) — see
`src/compare_runs.py`. The following are reported in both runs but are
**not** asserted equal, because they vary between runs by design:

- timing medians and peak-RSS values (system load, CPU frequency);
- digests of keys and signatures (test keys are generated fresh per run).

A clean reproduction reports `MATCH` when every compared field is equal.

## What did and did not run here

- **liboqs 0.16.0 (C)**: ran — ML-KEM + ML-DSA only, built from the
  bundled tarball (other algorithms disabled at configure time).
- **kyber-py 1.2.0 (pure Python)**: ran — ML-KEM-512/768/1024.
- **dilithium-py 1.5.1 (pure Python)**: ran — ML-DSA-44/65/87.
- **Rust**: NOT RUN — no `cargo`/`rustc` toolchain on this machine.
- **Go**: NOT RUN — no Go toolchain on this machine.
- **ML-KEM reference implementation (C)**: not built separately; the
  liboqs mlkem-native backend is the C implementation under test, and
  kyber-py is the independent second implementation.
- **ML-DSA reference implementation**: not built separately; the liboqs
  ml-dsa-native backend is the C implementation under test, and
  dilithium-py is the independent second implementation.

## Layout

```
README.md                  this file
claims.md                  claim-to-evidence index (C-01...)
findings.md                severity-ranked findings (F-01...)
citations.md               every primary source, with URL and what it establishes
evidence.json              machine-readable summary of the run
SHA256SUMS                 SHA-256 of every shippable file (see exclusion note below)
docs/index.html            rendered findings page (generated from outputs/run1/)
src/
  liboqs-0.16.0.tar.gz     liboqs 0.16.0 (bundled; SHA-256 verified per run)
  FIPS.203.pdf             FIPS 203 (bundled; SHA-256 verified per run)
  FIPS.204.pdf             FIPS 204 (bundled; SHA-256 verified per run)
  kyber_py-1.2.0-py3-none-any.whl
  dilithium_py-1.5.1-py3-none-any.whl
  pq_driver.c              C driver over liboqs (length checks before every call)
  benchmark.py             benchmark + adversarial + cross-implementation harness
  compare_runs.py          deterministic run comparison
  generate_docs.py         renders docs/index.html from results.json
  make_evidence.py         builds evidence.json from results.json + remediation logs
scripts/
  run_all.sh               full rebuild + run (see header for steps)
  clean_reproduce.sh       fresh-copy re-run + comparison
  verify_digests.sh        sha256sum -c SHA256SUMS
  regen_digests.sh         regenerates SHA256SUMS (called by run_all.sh)
remediation/
  reproduce_weakness.py    F-01 reproduction (exit 0 = reproduced)
  vulnerable_caller.py     the vulnerable pattern (BEFORE)
  vulnerable_caller.fixed.py  the fixed caller (AFTER)
  hedged_sign.py           the remediation: hedged-signing wrapper
  remediation.patch        diff vulnerable_caller.py -> fixed caller
  test_remediation.py      regression test (fails before, passes after)
fixtures/
  test-vectors.json        FIPS 203 Table 2 / FIPS 204 Table 2 sizes + test message
outputs/
  run1/                    unedited logs + results.json from run_all.sh
  run2-clean/              unedited logs + results.json from clean_reproduce.sh
  run-comparison.log       deterministic comparison of run1 vs run2-clean
  build-liboqs-cmake.log / build-liboqs-make.log
```

## Digest exclusion note

`SHA256SUMS` covers every shippable file **except** `docs/index.html`
(a generated rendering of the run outputs — a digest row for the page
itself would be self-referential) and `submission-text-final.txt` (a
submission draft, not pack content). Build artefacts that are rebuilt by
`run_all.sh` (`src/liboqs-0.16.0/`, `src/liboqs-build/`, the compiled
`src/pq_driver` binary, `venv/`) are also excluded; the sources they are
built from are covered. The build logs (`outputs/build-liboqs-*.log`)
have the absolute build path scrubbed to `.` by `run_all.sh`, so no local
workspace path leaks into the shipped pack.

## Honest limitations

- liboqs's ML-DSA signing was verified hedged **by experiment** (repeated
  signings differ) and **by source inspection** (ml-dsa-native calls
  `mld_randombytes` for `rnd`); the internal RNG itself was not audited.
- dilithium-py and kyber-py state in their own documentation that they
  are educational implementations, not constant-time and not written for
  performance. Their timing figures measure the Python code, not the
  algorithms, and must not be quoted as algorithm performance.
- The remediation wrapper enforces hedged signing at the call site; it
  cannot change the behaviour of any other caller of dilithium-py, and it
  does not add a cryptographic check — verification cannot distinguish
  deterministic from hedged signatures (that indistinguishability is
  itself part of F-01).
- Peak RSS is read from `/proc/self/status` VmHWM, not from
  `getrusage` `ru_maxrss`: in this environment a child spawned from
  Python reports the parent Python process's peak through `ru_maxrss`
  (verified with a trivial test program), while VmHWM is the process's
  own high-water mark and is parent-independent.
- The 300-byte-context and cross-parameter-set cases test the library
  APIs as exposed; no network, TLS, or protocol integration was tested.
- No fault injection was performed: the fault-attack risk cited for
  deterministic signing is the standard's own statement (FIPS 204
  §3.4), not an observed key recovery.
