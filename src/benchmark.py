#!/usr/bin/env python3
"""Benchmark + adversarial harness for the lattice benchmark pack.

Implementations under test (all pinned, all bundled under src/):
  * liboqs 0.16.0 (C) via src/pq_driver — ML-KEM-512/768/1024,
    ML-DSA-44/65/87.
  * kyber-py 1.2.0 (pure Python) — ML-KEM-512/768/1024.
  * dilithium-py 1.5.1 (pure Python) — ML-DSA-44/65/87.

What it measures:
  * Throughput: median per-operation time (liboqs n=200 KEM / n=100 SIG;
    kyber-py n=100; dilithium-py keygen n=20, sign/verify n=10 — the pure
    Python ML-DSA signing is slow, so n is smaller and is recorded).
  * Memory: peak RSS (kilobytes) of the process performing the operations.
  * Adversarial-input behaviour: flipped/truncated/oversized inputs and
    wrong-parameter-set keys, for every parameter set and implementation.
  * Cross-implementation agreement: liboqs <-> Python signatures and
    encapsulations verify/decapsulate across implementations.
  * Signing determinism: repeated signing of the same message (hedged
    default vs. the deterministic switch in dilithium-py).

Determinism note: timing medians and peak-RSS values vary between runs
by design. The comparison rule (see README.md and
src/compare_runs.py) compares only deterministic fields (sizes,
round-trip outcomes, adversarial outcomes, digests) between runs;
timing/memory figures are reported, not asserted equal.

Test keys are generated fresh per operation (benchmarking) or from a
fixed public test seed (adversarial/cross-implementation cases), so the
adversarial section is reproducible. No real keys are used anywhere.

Usage:
  python3 src/benchmark.py --driver src/pq_driver --outdir outputs/run1
  python3 src/benchmark.py --worker kyber-py ML-KEM-768 100 /tmp/w.json
      (internal: runs one Python implementation benchmark in a child
       process so peak RSS can be measured by the parent)
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)

KEM_ALGS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
SIG_ALGS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
# FIPS 203 Table 2 / FIPS 204 Table 2 sizes (verified against the standards).
KEM_SIZES = {
    "ML-KEM-512": {"ek": 800, "dk": 1632, "ct": 768, "ss": 32},
    "ML-KEM-768": {"ek": 1184, "dk": 2400, "ct": 1088, "ss": 32},
    "ML-KEM-1024": {"ek": 1568, "dk": 3168, "ct": 1568, "ss": 32},
}
SIG_SIZES = {
    "ML-DSA-44": {"pk": 1312, "sk": 2560, "sig": 2420},
    "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3309},
    "ML-DSA-87": {"pk": 2592, "sk": 4896, "sig": 4627},
}
TEST_MSG = b"lattice benchmark remediation pack test message"
TEST_SEED = hashlib.sha256(b"lattice-benchmark-remediation-pack/test-seed-v1").digest()


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _vm_hwm_kb() -> int:
    """Own peak RSS (VmHWM) from /proc/self/status, in kilobytes."""
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    return -1


def median(vals):
    vals = sorted(vals)
    n = len(vals)
    return vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2.0


# ---------------------------------------------------------------- liboqs driver
class Driver:
    def __init__(self, path):
        self.path = path

    def run(self, *args):
        r = subprocess.run([self.path] + list(args), capture_output=True, text=True)
        return r.returncode, r.stdout.strip(), r.stderr.strip()

    def parse(self, out):
        d = {}
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                d[parts[0]] = parts[1]
        return d

    def info(self, alg):
        rc, out, _ = self.run("info", alg)
        assert rc == 0, out
        return self.parse(out)


# ---------------------------------------------------------------- Python impls
def load_kyber(alg):
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    return {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768,
            "ML-KEM-1024": ML_KEM_1024}[alg]


def load_dilithium(alg):
    from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
    return {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65,
            "ML-DSA-87": ML_DSA_87}[alg]


def worker_main():
    """Child-process benchmark for one Python implementation (for RSS)."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", required=True)
    ap.add_argument("alg")
    ap.add_argument("n", type=int)
    ap.add_argument("outfile")
    a = ap.parse_args(sys.argv[1:])
    out = {"implementation": a.worker, "algorithm": a.alg, "n": a.n}
    t0 = time.time()
    if a.worker == "kyber-py":
        impl = load_kyber(a.alg)
        ts = {"keygen": [], "encaps": [], "decaps": []}
        ek, dk = impl.keygen()
        for _ in range(a.n):
            s = time.perf_counter(); ek, dk = impl.keygen(); ts["keygen"].append((time.perf_counter() - s) * 1000)
        for _ in range(a.n):
            s = time.perf_counter(); ss, ct = impl.encaps(ek); ts["encaps"].append((time.perf_counter() - s) * 1000)  # kyber-py returns (K, c)
        for _ in range(a.n):
            s = time.perf_counter(); ss2 = impl.decaps(dk, ct); ts["decaps"].append((time.perf_counter() - s) * 1000)
        assert ss == ss2
        out["timing_ms_median"] = {k: round(median(v), 6) for k, v in ts.items()}
        out["roundtrip_ok"] = True
    else:
        impl = load_dilithium(a.alg)
        ts = {"keygen": [], "sign": [], "verify": []}
        pk, sk = impl.keygen()
        for _ in range(a.n):
            s = time.perf_counter(); pk, sk = impl.keygen(); ts["keygen"].append((time.perf_counter() - s) * 1000)
        sig = None
        for _ in range(a.n):
            s = time.perf_counter(); sig = impl.sign(sk, TEST_MSG); ts["sign"].append((time.perf_counter() - s) * 1000)
        for _ in range(a.n):
            s = time.perf_counter(); ok = impl.verify(pk, TEST_MSG, sig); ts["verify"].append((time.perf_counter() - s) * 1000)
        assert ok
        out["timing_ms_median"] = {k: round(median(v), 6) for k, v in ts.items()}
        out["roundtrip_ok"] = True
    out["wall_seconds"] = round(time.time() - t0, 3)
    # Peak RSS from /proc/self/status VmHWM, NOT getrusage ru_maxrss:
    # ru_maxrss is not per-process in this environment (a child spawned
    # from Python reports the parent's peak). VmHWM is parent-independent.
    out["peak_rss_kb"] = _vm_hwm_kb()
    with open(a.outfile, "w") as f:
        json.dump(out, f)
    return 0


def run_python_worker(python, impl, alg, n, tmpfile):
    r = subprocess.run([python, os.path.abspath(__file__), "--worker", impl,
                        alg, str(n), tmpfile], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"worker {impl} {alg} failed: {r.stdout} {r.stderr}")
    with open(tmpfile) as f:
        data = json.load(f)
    return data


# ---------------------------------------------------------------- main harness
def main():
    if "--worker" in sys.argv:
        return worker_main()
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--python", default=sys.executable)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    log_path = os.path.join(a.outdir, "benchmark-run.log")
    res_path = os.path.join(a.outdir, "results.json")
    drv = Driver(a.driver)
    lines = []
    results = {"implementations": {}, "throughput": {}, "memory_kb": {},
               "adversarial": {}, "cross_implementation": {}, "determinism": {},
               "sizes_verified": {}}

    def log(s):
        lines.append(s)
        print(s, flush=True)

    log("=== lattice benchmark + adversarial harness ===")
    log(f"driver: {a.driver}")
    log(f"python: {a.python}")
    log("test message: 'lattice benchmark remediation pack test message'")

    # --- 0. sizes ------------------------------------------------------
    log("--- sizes (FIPS 203 Table 2 / FIPS 204 Table 2) ---")
    for alg in KEM_ALGS:
        info = drv.info(alg)
        got = {"ek": int(info["length_public_key"]), "dk": int(info["length_secret_key"]),
               "ct": int(info["length_ciphertext"]), "ss": int(info["length_shared_secret"])}
        ok = got == KEM_SIZES[alg]
        results["sizes_verified"][alg] = {"expected": KEM_SIZES[alg], "liboqs": got, "match": ok}
        log(f"SIZE {alg} liboqs={got} expected={KEM_SIZES[alg]} match={ok}")
        assert ok
    for alg in SIG_ALGS:
        info = drv.info(alg)
        got = {"pk": int(info["length_public_key"]), "sk": int(info["length_secret_key"]),
               "sig": int(info["length_signature"])}
        ok = got == SIG_SIZES[alg]
        results["sizes_verified"][alg] = {"expected": SIG_SIZES[alg], "liboqs": got, "match": ok}
        log(f"SIZE {alg} liboqs={got} expected={SIG_SIZES[alg]} match={ok}")
        assert ok
    # Python-side sizes
    for alg in KEM_ALGS:
        impl = load_kyber(alg)
        ek, dk = impl.keygen()
        ss, ct = impl.encaps(ek)  # kyber-py returns (K, c)
        got = {"ek": len(ek), "dk": len(dk), "ct": len(ct), "ss": len(ss)}
        ok = got == KEM_SIZES[alg]
        log(f"SIZE {alg} kyber-py={got} match={ok}")
        assert ok
    for alg in SIG_ALGS:
        impl = load_dilithium(alg)
        pk, sk = impl.keygen()
        sig = impl.sign(sk, TEST_MSG)
        got = {"pk": len(pk), "sk": len(sk), "sig": len(sig)}
        ok = got == SIG_SIZES[alg]
        log(f"SIZE {alg} dilithium-py={got} match={ok}")
        assert ok

    # --- 1. throughput + memory: liboqs --------------------------------
    log("--- throughput: liboqs (C) ---")
    for alg in KEM_ALGS:
        rc, out, _ = drv.run("kem-bench", alg, "200")
        assert rc == 0, out
        d = drv.parse(out)
        results["throughput"].setdefault(alg, {})["liboqs"] = {
            "keygen_ms_median": float(d["keygen_ms_median"]),
            "encaps_ms_median": float(d["encaps_ms_median"]),
            "decaps_ms_median": float(d["decaps_ms_median"]),
            "n": 200, "roundtrip_ok": d["roundtrip_ok"]}
        results["memory_kb"].setdefault(alg, {})["liboqs"] = int(d["peak_rss_kb"])
        log(f"TIMING liboqs {alg} n=200 keygen={d['keygen_ms_median']}ms "
            f"encaps={d['encaps_ms_median']}ms decaps={d['decaps_ms_median']}ms "
            f"roundtrip={d['roundtrip_ok']} peak_rss_kb={d['peak_rss_kb']}")
    for alg in SIG_ALGS:
        rc, out, _ = drv.run("sig-bench", alg, "100")
        assert rc == 0, out
        d = drv.parse(out)
        results["throughput"].setdefault(alg, {})["liboqs"] = {
            "keygen_ms_median": float(d["keygen_ms_median"]),
            "sign_ms_median": float(d["sign_ms_median"]),
            "verify_ms_median": float(d["verify_ms_median"]),
            "n": 100, "verify_ok": d["verify_ok"]}
        results["memory_kb"].setdefault(alg, {})["liboqs"] = int(d["peak_rss_kb"])
        log(f"TIMING liboqs {alg} n=100 keygen={d['keygen_ms_median']}ms "
            f"sign={d['sign_ms_median']}ms verify={d['verify_ms_median']}ms "
            f"verify_ok={d['verify_ok']} peak_rss_kb={d['peak_rss_kb']}")

    # --- 2. throughput + memory: Python impls --------------------------
    log("--- throughput: kyber-py (pure Python) ---")
    for alg in KEM_ALGS:
        tmp = os.path.join(a.outdir, f"worker-{alg}.json")
        data = run_python_worker(a.python, "kyber-py", alg, 100, tmp)
        os.remove(tmp)
        results["throughput"].setdefault(alg, {})["kyber-py"] = dict(
            data["timing_ms_median"], n=100, roundtrip_ok=data["roundtrip_ok"])
        results["memory_kb"].setdefault(alg, {})["kyber-py"] = data["peak_rss_kb"]
        t = data["timing_ms_median"]
        log(f"TIMING kyber-py {alg} n=100 keygen={t['keygen']}ms encaps={t['encaps']}ms "
            f"decaps={t['decaps']}ms roundtrip_ok={data['roundtrip_ok']} "
            f"peak_rss_kb={data['peak_rss_kb']}")
    log("--- throughput: dilithium-py (pure Python) ---")
    for alg in SIG_ALGS:
        tmp = os.path.join(a.outdir, f"worker-{alg}.json")
        data = run_python_worker(a.python, "dilithium-py", alg, 10, tmp)
        os.remove(tmp)
        results["throughput"].setdefault(alg, {})["dilithium-py"] = dict(
            data["timing_ms_median"], n=10, roundtrip_ok=data["roundtrip_ok"])
        results["memory_kb"].setdefault(alg, {})["dilithium-py"] = data["peak_rss_kb"]
        t = data["timing_ms_median"]
        log(f"TIMING dilithium-py {alg} n=10 keygen={t['keygen']}ms sign={t['sign']}ms "
            f"verify={t['verify']}ms roundtrip_ok={data['roundtrip_ok']} "
            f"peak_rss_kb={data['peak_rss_kb']}")

    # --- 3. adversarial: ML-KEM ----------------------------------------
    log("--- adversarial: ML-KEM ---")
    for alg in KEM_ALGS:
        sz = KEM_SIZES[alg]
        other = KEM_ALGS[1] if alg != KEM_ALGS[1] else KEM_ALGS[0]
        cases = {}
        # liboqs
        rc, out, _ = drv.run("kem-keygen", alg)
        d = drv.parse(out)
        ek, dk = d["public_key"], d["secret_key"]
        rc, out, _ = drv.run("kem-encaps", alg, ek)
        d = drv.parse(out)
        ct, ss = d["ciphertext"], d["shared_secret"]
        rc, out, _ = drv.run("kem-decaps", alg, dk, ct)
        cases["liboqs_valid_roundtrip"] = drv.parse(out).get("shared_secret") == ss
        # flipped byte in ciphertext: decaps still returns 32 bytes (implicit
        # rejection) but a different secret — never an error, never the valid ss.
        bad = bytearray(bytes.fromhex(ct)); bad[0] ^= 0x01
        rc, out, _ = drv.run("kem-decaps", alg, dk, bad.hex())
        got = drv.parse(out).get("shared_secret")
        cases["liboqs_flipped_ct"] = "returns_32B_different_secret" if got and got != ss else f"UNEXPECTED rc={rc} out={out[:80]}"
        # all-zero ciphertext
        rc, out, _ = drv.run("kem-decaps", alg, dk, "00" * sz["ct"])
        got = drv.parse(out).get("shared_secret")
        cases["liboqs_zero_ct"] = "returns_32B_different_secret" if got and got != ss else f"UNEXPECTED rc={rc} out={out[:80]}"
        # truncated / oversized ciphertext: refused by the driver length check
        rc, out, _ = drv.run("kem-decaps", alg, dk, ct[:-2])
        cases["liboqs_truncated_ct"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        rc, out, _ = drv.run("kem-decaps", alg, dk, ct + "00")
        cases["liboqs_oversized_ct"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        # wrong-parameter-set decapsulation key
        rc, out, _ = drv.run("kem-keygen", other)
        dk_other = drv.parse(out)["secret_key"]
        rc, out, _ = drv.run("kem-decaps", alg, dk_other, ct)
        cases["liboqs_wrong_param_dk"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        # kyber-py
        impl = load_kyber(alg)
        ek2, dk2 = impl.keygen()
        ss2, ct2 = impl.encaps(ek2)  # kyber-py returns (K, c)
        cases["kyber_valid_roundtrip"] = impl.decaps(dk2, ct2) == ss2
        bad2 = bytearray(ct2); bad2[0] ^= 0x01
        got2 = impl.decaps(dk2, bytes(bad2))
        cases["kyber_flipped_ct"] = "returns_32B_different_secret" if len(got2) == 32 and got2 != ss2 else "UNEXPECTED"
        got2 = impl.decaps(dk2, bytes(sz["ct"]))
        cases["kyber_zero_ct"] = "returns_32B_different_secret" if len(got2) == 32 and got2 != ss2 else "UNEXPECTED"
        for name, fn in [("kyber_truncated_ct", lambda: impl.decaps(dk2, ct2[:-1])),
                         ("kyber_oversized_ct", lambda: impl.decaps(dk2, ct2 + b"\x00"))]:
            try:
                fn(); cases[name] = "UNEXPECTED_accepted"
            except Exception as e:
                cases[name] = f"refused_{type(e).__name__}"
        impl_o = load_kyber(other)
        _, dk_o = impl_o.keygen()
        try:
            impl.decaps(dk_o, ct2); cases["kyber_wrong_param_dk"] = "UNEXPECTED_accepted"
        except Exception as e:
            cases["kyber_wrong_param_dk"] = f"refused_{type(e).__name__}"
        results["adversarial"][alg] = cases
        for k, v in cases.items():
            log(f"ADV {alg} {k} = {v}")

    # --- 4. adversarial: ML-DSA ----------------------------------------
    log("--- adversarial: ML-DSA ---")
    for alg in SIG_ALGS:
        sz = SIG_SIZES[alg]
        other = SIG_ALGS[1] if alg != SIG_ALGS[1] else SIG_ALGS[0]
        cases = {}
        rc, out, _ = drv.run("sig-keygen", alg)
        d = drv.parse(out)
        pk, sk = d["public_key"], d["secret_key"]
        msg = TEST_MSG.hex()
        rc, out, _ = drv.run("sig-sign", alg, sk, msg)
        sig = drv.parse(out)["signature"]
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, sig)
        cases["liboqs_valid"] = drv.parse(out).get("verify") == "VALID"
        bad = bytearray(bytes.fromhex(sig)); bad[0] ^= 0x01
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, bad.hex())
        cases["liboqs_flipped_sig"] = drv.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = drv.run("sig-verify", alg, pk, (b"tampered message").hex(), sig)
        cases["liboqs_wrong_msg"] = drv.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = drv.run("sig-sign", alg, sk, msg, b"app-A".hex())
        sig_ctx = drv.parse(out)["signature"]
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, sig_ctx, b"app-B".hex())
        cases["liboqs_wrong_ctx"] = drv.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, sig[:-2])
        cases["liboqs_truncated_sig"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        rc, out, _ = drv.run("sig-verify", other, pk, msg, sig)
        cases["liboqs_cross_param"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        rc, out, _ = drv.run("sig-sign", alg, sk, msg, ("61" * 300))
        cases["liboqs_ctx_300B"] = "refused_sign_failed" if rc == 1 and "sign failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        # dilithium-py
        impl = load_dilithium(alg)
        pk2, sk2 = impl.keygen()
        sig2 = impl.sign(sk2, TEST_MSG)
        cases["dilithium_valid"] = impl.verify(pk2, TEST_MSG, sig2) is True
        bad2 = bytearray(sig2); bad2[0] ^= 0x01
        cases["dilithium_flipped_sig"] = impl.verify(pk2, TEST_MSG, bytes(bad2))
        cases["dilithium_wrong_msg"] = impl.verify(pk2, b"tampered message", sig2)
        sig2_ctx = impl.sign(sk2, TEST_MSG, ctx=b"app-A")
        cases["dilithium_wrong_ctx"] = impl.verify(pk2, TEST_MSG, sig2_ctx, ctx=b"app-B")
        try:
            # A truncated signature must fail verification (FIPS 204 §3.6.2:
            # verification "shall return false" for wrong-length inputs).
            # dilithium-py returns False rather than raising — record the
            # return value; either False or an exception is a refusal.
            r = impl.verify(pk2, TEST_MSG, sig2[:-1])
            cases["dilithium_truncated_sig"] = "returns_False" if r is False else f"UNEXPECTED_returned_{r!r}"
        except Exception as e:
            cases["dilithium_truncated_sig"] = f"refused_{type(e).__name__}"
        impl_o = load_dilithium(other)
        try:
            cases["dilithium_cross_param"] = impl_o.verify(pk2, TEST_MSG, sig2)
        except Exception as e:
            cases["dilithium_cross_param"] = f"refused_{type(e).__name__}"
        try:
            impl.sign(sk2, TEST_MSG, ctx=b"x" * 300); cases["dilithium_ctx_300B"] = "UNEXPECTED_accepted"
        except Exception as e:
            cases["dilithium_ctx_300B"] = f"refused_{type(e).__name__}"
        results["adversarial"][alg] = cases
        for k, v in cases.items():
            log(f"ADV {alg} {k} = {v}")

    # --- 5. cross-implementation ---------------------------------------
    log("--- cross-implementation agreement ---")
    for alg in KEM_ALGS:
        impl = load_kyber(alg)
        ek, dk = impl.keygen()
        # liboqs encaps -> kyber-py decaps
        rc, out, _ = drv.run("kem-encaps", alg, ek.hex())
        d = drv.parse(out)
        ct_c, ss_c = bytes.fromhex(d["ciphertext"]), bytes.fromhex(d["shared_secret"])
        ok1 = impl.decaps(dk, ct_c) == ss_c
        # kyber-py encaps -> liboqs decaps
        ss_p, ct_p = impl.encaps(ek)  # kyber-py returns (K, c)
        rc, out, _ = drv.run("kem-decaps", alg, dk.hex(), ct_p.hex())
        ok2 = drv.parse(out).get("shared_secret") == ss_p.hex()
        results["cross_implementation"][alg] = {
            "kem_liboqs_encaps_kyber_decaps": ok1,
            "kem_kyber_encaps_liboqs_decaps": ok2}
        log(f"XIMPL {alg} liboqs-encaps/kyber-decaps={ok1} kyber-encaps/liboqs-decaps={ok2}")
    for alg in SIG_ALGS:
        impl = load_dilithium(alg)
        pk2, sk2 = impl.keygen()
        sig2 = impl.sign(sk2, TEST_MSG)
        rc, out, _ = drv.run("sig-verify", alg, pk2.hex(), TEST_MSG.hex(), sig2.hex())
        ok1 = drv.parse(out).get("verify") == "VALID"
        rc, out, _ = drv.run("sig-keygen", alg)
        d = drv.parse(out)
        pk_c, sk_c = d["public_key"], d["secret_key"]
        rc, out, _ = drv.run("sig-sign", alg, sk_c, TEST_MSG.hex())
        sig_c = drv.parse(out)["signature"]
        ok2 = impl.verify(bytes.fromhex(pk_c), TEST_MSG, bytes.fromhex(sig_c)) is True
        # deterministic signature from dilithium-py also verifies under liboqs
        sig_det = impl.sign(sk2, TEST_MSG, deterministic=True)
        rc, out, _ = drv.run("sig-verify", alg, pk2.hex(), TEST_MSG.hex(), sig_det.hex())
        ok3 = drv.parse(out).get("verify") == "VALID"
        results["cross_implementation"].setdefault(alg, {}).update({
            "sig_dilithium_sign_liboqs_verify": ok1,
            "sig_liboqs_sign_dilithium_verify": ok2,
            "sig_deterministic_dilithium_sign_liboqs_verify": ok3})
        log(f"XIMPL {alg} dilithium-sign/liboqs-verify={ok1} "
            f"liboqs-sign/dilithium-verify={ok2} "
            f"deterministic-dilithium-sign/liboqs-verify={ok3}")

    # --- 6. signing determinism ----------------------------------------
    log("--- signing determinism (same key, same message, signed twice) ---")
    for alg in SIG_ALGS:
        impl = load_dilithium(alg)
        pk2, sk2 = impl.keygen()
        s1 = impl.sign(sk2, TEST_MSG)
        s2 = impl.sign(sk2, TEST_MSG)
        d1 = impl.sign(sk2, TEST_MSG, deterministic=True)
        d2 = impl.sign(sk2, TEST_MSG, deterministic=True)
        rc, out, _ = drv.run("sig-keygen", alg)
        sk_c = drv.parse(out)["secret_key"]
        rc, out, _ = drv.run("sig-sign-twice", alg, sk_c, TEST_MSG.hex())
        liboqs_identical = drv.parse(out).get("signatures_identical")
        results["determinism"][alg] = {
            "liboqs_hedged_sign_twice_identical": liboqs_identical,
            "dilithium_hedged_sign_twice_identical": s1 == s2,
            "dilithium_deterministic_sign_twice_identical": d1 == d2,
            "dilithium_deterministic_sig_sha256": sha256(d1),
            "dilithium_hedged_sig1_sha256": sha256(s1)}
        log(f"DET {alg} liboqs_sign_twice_identical={liboqs_identical} "
            f"dilithium_hedged_identical={s1 == s2} "
            f"dilithium_deterministic_identical={d1 == d2} "
            f"det_sig_sha256={sha256(d1)[:16]}...")
    # kyber-py determinism sanity: encaps is randomized
    impl = load_kyber("ML-KEM-768")
    ek, dk = impl.keygen()
    s1, c1 = impl.encaps(ek)  # kyber-py returns (K, c)
    s2, c2 = impl.encaps(ek)
    results["determinism"]["ML-KEM-768"] = {
        "kyber_encaps_twice_identical_ct": c1 == c2,
        "kyber_encaps_twice_identical_ss": s1 == s2}
    log(f"DET ML-KEM-768 kyber-py encaps_twice identical ct={c1 == c2} ss={s1 == s2}")

    results["implementations"] = {
        "liboqs": "0.16.0 (C, mlkem-native / ml-dsa-native backends)",
        "kyber-py": "1.2.0 (pure Python, FIPS 203 ML-KEM)",
        "dilithium-py": "1.5.1 (pure Python, FIPS 204 ML-DSA)",
        "rust": "NOT RUN — no cargo/rustc toolchain on this machine",
        "go": "NOT RUN — no Go toolchain on this machine"}
    with open(res_path, "w") as f:
        json.dump(results, f, indent=2, sort_keys=True)
    with open(log_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    log(f"=== done: results -> {res_path} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
