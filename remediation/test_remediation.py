#!/usr/bin/env python3
"""Regression test for the F-01 remediation.

Structure (mirrors the before/after discipline of the pack):
  BEFORE (the weakness, expected to FAIL the "signatures must differ"
  assertion): direct dilithium-py deterministic signing of the same
  message twice yields byte-identical signatures. This section proves
  the test can detect the weakness — it is not a vacuous pass.
  AFTER (the remediation, all must pass):
    1. hedged_sign twice -> signatures differ.
    2. Both hedged signatures verify under dilithium-py AND liboqs.
    3. deterministic_sign without allow_deterministic=True raises.
    4. deterministic_sign with the opt-in works but logs a warning.
    5. The remediation patch applies cleanly to a fresh copy of
       vulnerable_caller.py and the patched caller produces differing
       signatures.
    6. A repeated signature for the same key+message is refused by the
       wrapper's tripwire (simulated by re-feeding a recorded signature
       through the record function).

Trigger:
  python3 remediation/test_remediation.py [--driver src/pq_driver]

Exit code 0 only if the BEFORE section reproduces the weakness AND all
AFTER checks pass.
"""
import argparse
import hashlib
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MESSAGE = b"lattice benchmark remediation pack test message"
PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}" + (f" — {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"FAIL {name}" + (f" — {detail}" if detail else ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", default="src/pq_driver")
    a = ap.parse_args()

    from dilithium_py.ml_dsa import ML_DSA_44
    from hedged_sign import (DeterministicSigningRefused, RepeatedSignatureError,
                             deterministic_sign, hedged_sign, reset_record, _record)

    pk, sk = ML_DSA_44.keygen()
    print("=== BEFORE (weakness): direct deterministic signing ===")
    d1 = ML_DSA_44.sign(sk, MESSAGE, deterministic=True)
    d2 = ML_DSA_44.sign(sk, MESSAGE, deterministic=True)
    check("before_deterministic_signatures_identical", d1 == d2,
          "the weakness reproduces: identical signatures, both valid")
    check("before_deterministic_signatures_verify",
          ML_DSA_44.verify(pk, MESSAGE, d1) and ML_DSA_44.verify(pk, MESSAGE, d2))
    before_reproduced = d1 == d2

    print("=== AFTER (remediation): hedged_sign wrapper ===")
    reset_record()
    h1 = hedged_sign(ML_DSA_44, sk, MESSAGE)
    h2 = hedged_sign(ML_DSA_44, sk, MESSAGE)
    check("after_hedged_signatures_differ", h1 != h2)
    check("after_hedged_signatures_verify_dilithium",
          ML_DSA_44.verify(pk, MESSAGE, h1) and ML_DSA_44.verify(pk, MESSAGE, h2))

    # Both hedged signatures also verify under liboqs (cross-implementation).
    ok_liboqs = True
    for sig in (h1, h2):
        r = subprocess.run([a.driver, "sig-verify", "ML-DSA-44", pk.hex(),
                            MESSAGE.hex(), sig.hex()],
                           capture_output=True, text=True)
        if "VALID" not in r.stdout:
            ok_liboqs = False
    check("after_hedged_signatures_verify_liboqs", ok_liboqs)

    # Deterministic mode without the opt-in must raise.
    try:
        deterministic_sign(ML_DSA_44, sk, MESSAGE)
        check("after_deterministic_without_optin_refused", False, "no exception raised")
    except DeterministicSigningRefused:
        check("after_deterministic_without_optin_refused", True)
    except Exception as e:  # noqa: BLE001 — any other exception is a failure
        check("after_deterministic_without_optin_refused", False, f"wrong exception: {e!r}")

    # With the opt-in it works, and the warning is emitted.
    r = subprocess.run([sys.executable, "-c",
                        "import sys; sys.path.insert(0, 'remediation');"
                        "from dilithium_py.ml_dsa import ML_DSA_44;"
                        "from hedged_sign import deterministic_sign;"
                        "pk, sk = ML_DSA_44.keygen();"
                        "s = deterministic_sign(ML_DSA_44, sk, b'm', allow_deterministic=True, reason='test vector');"
                        "print('signed', ML_DSA_44.verify(pk, b'm', s))"],
                       capture_output=True, text=True)
    check("after_deterministic_with_optin_works_and_warns",
          r.returncode == 0 and "signed True" in r.stdout
          and "WARNING: deterministic ML-DSA signing used" in r.stderr,
          r.stderr.strip().splitlines()[-1] if r.stderr.strip() else r.stdout.strip())

    # The patch applies cleanly and the patched caller differs per signing.
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "vulnerable_caller.py")
        dst = os.path.join(td, "vulnerable_caller.py")
        import shutil
        shutil.copy(src, dst)
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "hedged_sign.py"), os.path.join(td, "hedged_sign.py"))
        patch = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "remediation.patch")
        r = subprocess.run(["patch", "--dry-run", "-p1", "-i", patch],
                           cwd=td, capture_output=True, text=True)
        check("after_patch_applies_cleanly", r.returncode == 0, r.stdout.strip() or r.stderr.strip())
        r = subprocess.run(["patch", "-p1", "-i", patch],
                           cwd=td, capture_output=True, text=True)
        check("after_patch_applied", r.returncode == 0)
        r = subprocess.run([sys.executable, dst], cwd=td,
                           capture_output=True, text=True)
        check("after_patched_caller_signatures_differ",
              r.returncode == 0 and "signatures identical: False" in r.stdout,
              r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr.strip()[-200:])

    # Tripwire: re-recording an already-issued signature must raise.
    reset_record()
    _record(sk, MESSAGE, h1)
    try:
        _record(sk, MESSAGE, h1)
        check("after_repeat_signature_tripwire", False, "no exception raised")
    except RepeatedSignatureError:
        check("after_repeat_signature_tripwire", True)
    except Exception as e:  # noqa: BLE001
        check("after_repeat_signature_tripwire", False, f"wrong exception: {e!r}")

    print(f"=== regression test: {PASS} passed, {FAIL} failed ===")
    return 0 if (before_reproduced and FAIL == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
